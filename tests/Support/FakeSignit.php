<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\Signit\Tests\Support;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use HamadaEmamTech\Esign\Signit\SignitApi;
use HamadaEmamTech\Esign\Signit\SignitCredentials;
use HamadaEmamTech\Esign\Signit\SignitOptions;
use HamadaEmamTech\Esign\Signit\SignitProvider;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * An in-memory Signit, shaped like its v1 API: OAuth client credentials, /documents upload,
 * /signature-requests, signatory reminders and links, void, and sealed files served from a
 * separate download host.
 */
final class FakeSignit implements ClientInterface
{
    public const CLIENT_SECRET = 'client&secret#1';
    public const WEBHOOK_KEY = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    public const SEALED = "%PDF-1.7 sealed /ByteRange [0 1 2 3]\n";
    /** A one-page A4 PDF (595 x 842 points). */
    public const PDF = "%PDF-1.7\n1 0 obj << /Type /Page /MediaBox [0 0 595 842] >> endobj\n%%EOF\n";

    /** @var list<array{method: string, url: string, auth: string, body: string}> */
    public array $calls = [];

    /** @var array<string, mixed> the last create body */
    public array $lastCreate = [];

    public int $tokenCalls = 0;

    public int $unauthorizedNext = 0;

    /** Leave email out of signatories in responses, as Signit may. */
    public bool $omitEmails = false;

    public ?string $forcedStatus = null;

    /** @var array<int|string, array{status: string, signatories: list<array<string, mixed>>}> numeric IDs become int keys */
    private array $requests = [];

    private int $sequence = 0;

    public function provider(?SignitOptions $options = null, ?\Closure $clock = null): SignitProvider
    {
        $factory = new HttpFactory();

        return new SignitProvider(
            new SignitApi($this, $factory, $factory, new SignitCredentials('api-key', self::CLIENT_SECRET), 'https://api-sandbox.signit.test/v1', null, $clock),
            $options ?? new SignitOptions(webhookSecret: self::WEBHOOK_KEY),
        );
    }

    public function sign(string $id, int $index): void
    {
        $this->requests[$id]['signatories'][$index]['status'] = 'SIGNED';
    }

    public function signAll(string $id, string $requestStatus = 'COMPLETED'): void
    {
        foreach (array_keys($this->requests[$id]['signatories']) as $i) {
            $this->requests[$id]['signatories'][$i]['status'] = 'SIGNED';
        }
        $this->requests[$id]['status'] = $requestStatus;
    }

    /**
     * Build a webhook body exactly as Signit sends it: base64(IV + AES-256-CBC(json)).
     *
     * @param array<string, mixed> $payload
     */
    public static function encryptedWebhook(array $payload, string $hexKey = self::WEBHOOK_KEY, bool $asForm = false): string
    {
        $iv = random_bytes(16);
        $data = base64_encode($iv . openssl_encrypt((string) json_encode($payload), 'aes-256-cbc', (string) hex2bin($hexKey), OPENSSL_RAW_DATA, $iv));

        return $asForm ? http_build_query(['data' => $data, 'is_encrypted' => 'true']) : (string) json_encode(['data' => $data, 'is_encrypted' => true]);
    }

    /** @return list<string> "METHOD path" of every API call */
    public function paths(): array
    {
        return array_map(fn (array $c) => $c['method'] . ' ' . parse_url($c['url'], PHP_URL_PATH) . (($q = parse_url($c['url'], PHP_URL_QUERY)) ? "?{$q}" : ''), $this->calls);
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $uri = (string) $request->getUri();
        $path = $request->getUri()->getPath();
        $body = (string) $request->getBody();

        if ($request->getUri()->getHost() === 'files.signit.test') {
            $this->calls[] = ['method' => 'GET', 'url' => $uri, 'auth' => $request->getHeaderLine('Authorization'), 'body' => ''];

            return new Response(200, ['Content-Type' => 'application/pdf'], self::SEALED);
        }
        if ($path === '/v1/oauth/token') {
            return $this->token($body);
        }

        $this->calls[] = ['method' => $request->getMethod(), 'url' => $uri, 'auth' => $request->getHeaderLine('Authorization'), 'body' => $body];
        if ($this->unauthorizedNext > 0) {
            --$this->unauthorizedNext;

            return new Response(401, [], '{"message":"Unauthenticated."}');
        }
        if ($request->getHeaderLine('Authorization') !== 'Bearer token-' . $this->tokenCalls) {
            return new Response(401, [], '{"message":"Unauthenticated."}');
        }

        $m = [];

        return match (true) {
            $path === '/v1/documents' => $this->upload($request, $body),
            $path === '/v1/signature-requests' || $path === '/v1/signature-requests/embedded' => $this->create($body),
            (bool) preg_match('#^/v1/signature-requests/(\d+)$#', $path, $m) => $this->get($m[1]),
            (bool) preg_match('#^/v1/signature-requests/(\d+)/files$#', $path, $m) => self::json(['url' => "https://files.signit.test/sealed/{$m[1]}.pdf"]),
            (bool) preg_match('#^/v1/signature-requests/(\d+)/void$#', $path, $m) => $this->void($m[1]),
            (bool) preg_match('#^/v1/signature-requests/(\d+)/signatories/(\w+)/reminders$#', $path) => self::json(['message' => 'Reminder sent']),
            (bool) preg_match('#^/v1/signature-requests/(\d+)/signatories/(\w+)/signing-link$#', $path, $m) => self::json(['signing_link' => "https://app.signit.test/sign/{$m[1]}/{$m[2]}"]),
            default => new Response(404, [], '{"message":"Not found"}'),
        };
    }

    private function token(string $body): ResponseInterface
    {
        parse_str($body, $form);
        $valid = ($form['grant_type'] ?? null) === 'client_credentials' && ($form['client_id'] ?? null) === 'api-key'
            && ($form['client_secret'] ?? null) === self::CLIENT_SECRET && ($form['scope'] ?? null) === 'signature-requests:write signature-requests:read';
        if (! $valid) {
            return new Response(401, [], '{"error":"invalid_client","error_description":"Client authentication failed"}');
        }
        ++$this->tokenCalls;

        return self::json(['token_type' => 'Bearer', 'expires_in' => 3600, 'access_token' => 'token-' . $this->tokenCalls]);
    }

    private function upload(RequestInterface $request, string $body): ResponseInterface
    {
        if (! str_contains($request->getHeaderLine('Content-Type'), 'multipart/form-data') || ! str_contains($body, 'name="document"')) {
            return new Response(422, [], '{"message":"The document field is required."}');
        }

        return self::json(['document_name' => 'doc_' . (++$this->sequence) . '.pdf']);
    }

    private function create(string $body): ResponseInterface
    {
        $decoded = json_decode($body, true);
        $this->lastCreate = is_array($decoded) ? $decoded : [];
        $request = $this->lastCreate['signature_request'] ?? [];
        if (! is_string($this->lastCreate['document_name'] ?? null) || ! is_array($request['signatories'] ?? null)) {
            return new Response(422, [], '{"message":"The given data was invalid.","errors":{"document_name":["required"]}}');
        }
        $id = (string) (1000 + $this->sequence);
        $signatories = [];
        foreach ($request['signatories'] as $i => $s) {
            $signatory = ['id' => "s{$i}", 'full_name' => $s['full_name'], 'order' => $s['order'], 'status' => 'PENDING', 'signing_link' => "https://app.signit.test/sign/{$id}/s{$i}"];
            if (! $this->omitEmails) {
                $signatory['notification_method'] = $s['notification_method'];
            }
            $signatories[] = $signatory;
        }
        $this->requests[$id] = ['status' => 'IN-PROGRESS', 'signatories' => array_values($signatories)];

        return self::json(['id' => (int) $id, 'status' => 'IN-PROGRESS', 'signatories' => $signatories]);
    }

    private function get(string $id): ResponseInterface
    {
        if (! isset($this->requests[$id])) {
            return new Response(404, [], '{"message":"Signature request not found"}');
        }

        return self::json(['id' => (int) $id, 'status' => $this->forcedStatus ?? $this->requests[$id]['status'], 'signatories' => $this->requests[$id]['signatories']]);
    }

    private function void(string $id): ResponseInterface
    {
        $this->requests[$id]['status'] = 'VOIDED';

        return self::json(['message' => 'Voided']);
    }

    /** @param array<string, mixed> $data */
    private static function json(array $data): ResponseInterface
    {
        return new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($data));
    }
}
