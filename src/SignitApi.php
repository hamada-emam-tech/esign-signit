<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\Signit;

use HamadaEmamTech\Esign\Exceptions\ProviderError;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Talks to Signit's REST API (https://api.signit.sa/v1, sandbox https://api-sandbox.signit.sa/v1):
 * an OAuth client-credentials token, then JSON or multipart calls. Plain JSON responses; HTTP status
 * codes mean what they say.
 *
 * @internal used by SignitProvider
 */
final class SignitApi
{
    private const SCOPES = 'signature-requests:write signature-requests:read';

    private ?string $token = null;

    private int $tokenExpiresAt = 0;

    /** @var \Closure(): int */
    private readonly \Closure $clock;

    public function __construct(
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
        private readonly SignitCredentials $credentials,
        private readonly string $baseUrl,
        private readonly ?CacheInterface $cache = null,
        ?\Closure $clock = null,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    /**
     * @param array<mixed>|null $body
     *
     * @return array<string, mixed>
     */
    public function json(string $method, string $path, ?array $body = null): array
    {
        $response = $this->call($method, $path, $body === null ? null : (string) json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR), 'application/json');

        return $this->decode($response, "{$method} {$path}");
    }

    /**
     * Upload one file as multipart.
     *
     * @return array<string, mixed>
     */
    public function upload(string $path, string $field, string $filename, string $contents, string $type): array
    {
        $boundary = '----esign' . bin2hex(random_bytes(12));
        $body = "--{$boundary}\r\nContent-Disposition: form-data; name=\"{$field}\"; filename=\"" . addcslashes($filename, "\"\\") . "\"\r\n"
            . "Content-Type: {$type}\r\n\r\n{$contents}\r\n--{$boundary}--\r\n";

        return $this->decode($this->call('POST', $path, $body, "multipart/form-data; boundary={$boundary}"), "POST {$path}");
    }

    /** The raw response of an authenticated GET: JSON or a file. */
    public function raw(string $path): ResponseInterface
    {
        return $this->call('GET', $path);
    }

    /** Fetch a file from the download URL Signit hands out. Sent without our token: it must not leak to another host. */
    public function fetchUrl(string $url): string
    {
        if (! str_starts_with($url, 'https://')) {
            throw new ProviderError('signit', 'Signit returned a download URL that is not https.');
        }
        $response = $this->send($this->requests->createRequest('GET', $url), 'download');
        if ($response->getStatusCode() >= 400) {
            throw new ProviderError('signit', 'Could not download the signed file.', $response->getStatusCode());
        }

        return (string) $response->getBody();
    }

    private function call(string $method, string $path, ?string $body = null, ?string $contentType = null, bool $isRetry = false): ResponseInterface
    {
        $request = $this->requests->createRequest($method, $this->baseUrl . $path)
            ->withHeader('Authorization', 'Bearer ' . $this->token())
            ->withHeader('Accept', 'application/json');
        if ($body !== null) {
            $request = $request->withHeader('Content-Type', (string) $contentType)->withBody($this->streams->createStream($body));
        }

        $response = $this->send($request, "{$method} {$path}");
        if ($response->getStatusCode() === 401 && ! $isRetry) {
            $this->forgetToken();

            return $this->call($method, $path, $body, $contentType, true);
        }
        if ($response->getStatusCode() >= 400) {
            throw $this->error($response, "{$method} {$path}");
        }

        return $response;
    }

    /** @return array<string, mixed> */
    private function decode(ResponseInterface $response, string $what): array
    {
        $body = (string) $response->getBody();
        if ($body === '') {
            return [];
        }
        $json = json_decode($body, true);

        return is_array($json) ? $json : throw new ProviderError('signit', "{$what} returned a non-JSON response.", $response->getStatusCode());
    }

    private function error(ResponseInterface $response, string $what): ProviderError
    {
        // Signit's error body isn't documented publicly. Read the usual fields when present.
        $json = json_decode((string) $response->getBody(), true);
        $code = null;
        $message = 'Request failed';
        if (is_array($json)) {
            $code = is_string($json['code'] ?? null) ? $json['code'] : (is_string($json['error'] ?? null) ? $json['error'] : null);
            foreach (['message', 'error_description', 'detail'] as $key) {
                if (is_string($json[$key] ?? null) && $json[$key] !== '') {
                    $message = $json[$key];
                    break;
                }
            }
            if (is_array($json['errors'] ?? null)) {
                $message .= ': ' . substr((string) json_encode($json['errors'], JSON_UNESCAPED_UNICODE), 0, 300);
            }
        }

        return new ProviderError('signit', "{$what}: {$message}", $response->getStatusCode(), $code);
    }

    private function token(): string
    {
        $now = ($this->clock)();
        if ($this->token !== null && $now < $this->tokenExpiresAt) {
            return $this->token;
        }
        $cached = $this->cache?->get($this->cacheKey());
        if (is_array($cached) && is_string($cached['token'] ?? null) && (int) ($cached['expires_at'] ?? 0) > $now) {
            [$this->token, $this->tokenExpiresAt] = [$cached['token'], (int) $cached['expires_at']];

            return $this->token;
        }

        $request = $this->requests->createRequest('POST', $this->baseUrl . '/oauth/token')
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streams->createStream(http_build_query([
                'grant_type' => 'client_credentials',
                'client_id' => $this->credentials->clientId,
                'client_secret' => $this->credentials->clientSecret,
                'scope' => self::SCOPES,
            ])));

        $response = $this->send($request, 'token');
        if ($response->getStatusCode() >= 500) {
            throw new ProviderError('signit', 'Signit authentication service is unavailable. Try again later.', $response->getStatusCode());
        }
        $json = json_decode((string) $response->getBody(), true);
        $token = is_array($json) ? ($json['access_token'] ?? null) : null;
        if ($response->getStatusCode() >= 400 || ! is_string($token) || $token === '') {
            $code = is_array($json) && is_string($json['error'] ?? null) ? $json['error'] : null;
            throw new ProviderError('signit', 'Authentication failed. Check client_id and client_secret.', $response->getStatusCode(), $code);
        }

        $lifetime = max(60, (int) ($json['expires_in'] ?? 3600) - 300);
        $this->token = $token;
        $this->tokenExpiresAt = $now + $lifetime;
        $this->cache?->set($this->cacheKey(), ['token' => $token, 'expires_at' => $this->tokenExpiresAt], $lifetime);

        return $token;
    }

    private function forgetToken(): void
    {
        $this->token = null;
        $this->tokenExpiresAt = 0;
        $this->cache?->delete($this->cacheKey());
    }

    private function cacheKey(): string
    {
        return 'esign_signit_token_' . sha1($this->baseUrl . '|' . $this->credentials->clientId);
    }

    private function send(RequestInterface $request, string $what): ResponseInterface
    {
        try {
            return $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new ProviderError('signit', "{$what}: could not reach Signit ({$e->getMessage()})", null, null, $e);
        }
    }
}
