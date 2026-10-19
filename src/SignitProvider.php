<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\Signit;

use HamadaEmamTech\Esign\Capabilities\Capabilities;
use HamadaEmamTech\Esign\Capabilities\Feature;
use HamadaEmamTech\Esign\Contracts\Features\RecognizesWebhooks;
use HamadaEmamTech\Esign\Contracts\Features\ReportsSigners;
use HamadaEmamTech\Esign\Contracts\Features\SendsReminders;
use HamadaEmamTech\Esign\Contracts\HasCapabilities;
use HamadaEmamTech\Esign\Contracts\SignatureProvider;
use HamadaEmamTech\Esign\Envelope\Envelope;
use HamadaEmamTech\Esign\Envelope\EnvelopeDetails;
use HamadaEmamTech\Esign\Envelope\EnvelopeRef;
use HamadaEmamTech\Esign\Envelope\EnvelopeStatus;
use HamadaEmamTech\Esign\Envelope\IdentityMethod;
use HamadaEmamTech\Esign\Envelope\SentEnvelope;
use HamadaEmamTech\Esign\Envelope\SignatureField;
use HamadaEmamTech\Esign\Envelope\Signer;
use HamadaEmamTech\Esign\Envelope\SignerState;
use HamadaEmamTech\Esign\Envelope\SignerStatus;
use HamadaEmamTech\Esign\Envelope\WebhookEvent;
use HamadaEmamTech\Esign\Exceptions\EsignException;
use HamadaEmamTech\Esign\Exceptions\InvalidWebhook;
use HamadaEmamTech\Esign\Exceptions\ProviderError;
use HamadaEmamTech\Esign\Support\PdfPageSize;

/**
 * Signit (signit.sa), the DGA-licensed Saudi e-signature platform, with Nafath identity.
 *
 * The flow: upload the PDF (/documents, returns a document_name) → create the signature request
 * (/signature-requests) → signers sign → an encrypted webhook arrives → status() → download() the
 * "sealed" file through the URL Signit returns.
 *
 * Behaviour this driver handles:
 * - Positions are measured from the BOTTOM-left of the page, with y at the box's bottom edge.
 *   SignatureField is top-left, so y is converted with the page height (read from the PDF, or the
 *   page_height option).
 * - Webhooks are not signed but encrypted: {"data": base64(IV + AES-256-CBC(json)), "is_encrypted": true},
 *   with a hex key. A call that decrypts to JSON came from someone holding the key.
 * - Webhook event names contain "SIGNED" for single signers too, so an event never decides the
 *   status. status() asks Signit and requires every signer to be SIGNED.
 * - The files endpoint returns a download URL, not the file.
 */
final class SignitProvider implements SignatureProvider, HasCapabilities, ReportsSigners, SendsReminders, RecognizesWebhooks
{
    public function __construct(
        private readonly SignitApi $api,
        private readonly SignitOptions $options = new SignitOptions(),
    ) {
    }

    public function name(): string
    {
        return 'signit';
    }

    public function capabilities(): Capabilities
    {
        return new Capabilities(
            identityMethods: [IdentityMethod::Email, IdentityMethod::Nafath],
            features: [Feature::SigningOrder, Feature::FieldPlacement, Feature::SigningUrls, Feature::Reminders, Feature::SignerDetails],
            maxDocuments: 1,
        );
    }

    public function send(Envelope $envelope): SentEnvelope
    {
        if (count($envelope->documents) !== 1) {
            throw new EsignException('Signit takes one document per signature request. Merge the PDFs first.');
        }
        $document = $envelope->documents[0];
        if ($document->mimeType !== 'application/pdf') {
            throw new EsignException("Signit signs PDFs only; \"{$document->name}\" is {$document->mimeType}.");
        }
        $pageHeight = $this->pageHeight($envelope);
        $signatories = array_map(fn (Signer $s) => $this->signatory($s, $pageHeight), $envelope->signers);

        $uploaded = $this->api->upload('/documents', 'document', $document->name, $document->contents, 'application/pdf');
        $documentName = $uploaded['document_name'] ?? null;
        if (! is_string($documentName) || $documentName === '') {
            throw new ProviderError('signit', 'The document was uploaded without a document_name.');
        }

        $created = $this->api->json('POST', $this->options->embedded ? '/signature-requests/embedded' : '/signature-requests', [
            'document_name' => $documentName,
            'signature_request' => [
                'title' => $envelope->subject,
                'digital_signature_provider' => $this->options->digitalSignatureProvider,
                'signatories' => $signatories,
            ],
        ]);
        $id = $created['id'] ?? null;
        if (! is_string($id) && ! is_int($id)) {
            throw new ProviderError('signit', 'The signature request was created without an id.');
        }

        return new SentEnvelope('signit', (string) $id, EnvelopeStatus::Sent, $this->signingUrls($envelope, $created));
    }

    public function status(string $envelopeId): EnvelopeStatus
    {
        return $this->map($this->request($envelopeId));
    }

    public function details(string $envelopeId): EnvelopeDetails
    {
        $data = $this->request($envelopeId);
        $signers = array_map(fn (array $s) => new SignerState(
            self::email($s) ?? '',
            (string) ($s['full_name'] ?? ''),
            self::signerStatus($s),
            is_string($s['signing_link'] ?? null) ? $s['signing_link'] : null,
            isset($s['order']) ? (int) $s['order'] : null,
        ), self::signatories($data));

        return new EnvelopeDetails(new EnvelopeRef('signit', $envelopeId), $this->map($data), $signers);
    }

    public function download(string $envelopeId): string
    {
        $status = $this->status($envelopeId);
        if ($status !== EnvelopeStatus::Signed) {
            throw new EsignException("Signit request {$envelopeId} is {$status->value}, not signed. There is no sealed PDF yet.");
        }

        $response = $this->api->raw('/signature-requests/' . rawurlencode($envelopeId) . '/files?file_type=sealed');
        $body = (string) $response->getBody();
        if (str_starts_with($body, '%PDF')) {
            return $body;
        }
        $json = json_decode($body, true);
        $url = is_array($json) ? ($json['url'] ?? $json['download_url'] ?? $json['file_url'] ?? null) : null;
        if (! is_string($url)) {
            throw new ProviderError('signit', "Signit returned no sealed file for {$envelopeId}.");
        }
        $pdf = $this->api->fetchUrl($url);
        if (! str_starts_with($pdf, '%PDF')) {
            throw new ProviderError('signit', "The sealed file for {$envelopeId} is not a PDF.");
        }

        return $pdf;
    }

    public function cancel(string $envelopeId): void
    {
        $this->api->json('PUT', '/signature-requests/' . rawurlencode($envelopeId) . '/void');
    }

    /** Re-sends the invitation to one signer (Signit reminds the signatory on file; it can't change the recipient). */
    public function remind(string $envelopeId, string $signerEmail): void
    {
        $signatory = $this->signatoryByEmail($envelopeId, $signerEmail);
        $this->api->json('POST', '/signature-requests/' . rawurlencode($envelopeId) . '/signatories/' . rawurlencode((string) $signatory['id']) . '/reminders');
    }

    // ---- Signit-only ------------------------------------------------------------------------

    /** A fresh signing link for one signer, e.g. for an embedded request. */
    public function signingLink(string $envelopeId, string $signerEmail): string
    {
        $signatory = $this->signatoryByEmail($envelopeId, $signerEmail);
        $json = $this->api->json('GET', '/signature-requests/' . rawurlencode($envelopeId) . '/signatories/' . rawurlencode((string) $signatory['id']) . '/signing-link');
        $link = $json['signing_link'] ?? $json['url'] ?? null;

        return is_string($link) && $link !== '' ? $link : throw new ProviderError('signit', 'Signit returned no signing link.');
    }

    /** Finish the request as its owner, once the signers you need have signed. */
    public function completeByOwner(string $envelopeId): void
    {
        $this->api->json('PUT', '/signature-requests/' . rawurlencode($envelopeId) . '/complete');
    }

    /** @return array<string, mixed> Signit's audit trail, as it returns it */
    public function auditTrail(string $envelopeId): array
    {
        return $this->api->json('GET', '/signature-requests/' . rawurlencode($envelopeId) . '/audit-trails');
    }

    // ---- webhooks -----------------------------------------------------------------------------

    public function recognizesWebhook(array $headers, string $rawBody): bool
    {
        $body = self::body($rawBody);

        return (is_string($body['data'] ?? null) && array_key_exists('is_encrypted', $body))
            || isset($body['data']['signature_request_id'], $body['data']['event_type']);
    }

    public function parseWebhook(array $headers, string $rawBody): WebhookEvent
    {
        $body = self::body($rawBody);
        $encrypted = filter_var($body['is_encrypted'] ?? true, FILTER_VALIDATE_BOOLEAN);

        if (is_string($body['data'] ?? null) && $encrypted) {
            $payload = $this->decrypt($body['data']);
        } elseif ($this->options->acceptUnencryptedWebhooks) {
            $payload = $body;
        } else {
            throw new InvalidWebhook('Signit webhook is not encrypted, so it cannot be trusted. Refusing it (set accept_unencrypted_webhooks to allow).');
        }

        $data = is_array($payload['data'] ?? null) ? $payload['data'] : $payload;
        $id = $data['signature_request_id'] ?? $data['signatureRequestId'] ?? null;
        if ((! is_string($id) && ! is_int($id)) || (string) $id === '') {
            throw new InvalidWebhook('Signit webhook has no signature_request_id.');
        }
        $event = $payload['event_type'] ?? $payload['event'] ?? $data['event_type'] ?? $data['event'] ?? null;

        return new WebhookEvent('signit', (string) $id, null, ['event_type' => is_string($event) ? $event : null]);
    }

    // ---- internals ----------------------------------------------------------------------------

    /** @return array<string, mixed> */
    private function decrypt(string $data): array
    {
        $secret = (string) $this->options->webhookSecret;
        if ($secret === '' || strlen($secret) !== 64 || ! ctype_xdigit($secret)) {
            throw new InvalidWebhook('Signit webhook_secret is missing or not a 64-character hex key, so the webhook cannot be decrypted. Refusing it.');
        }
        $raw = base64_decode($data, true);
        if ($raw === false || strlen($raw) <= 16) {
            throw new InvalidWebhook('Signit webhook data is not valid encrypted content.');
        }
        $plain = openssl_decrypt(substr($raw, 16), 'aes-256-cbc', (string) hex2bin($secret), OPENSSL_RAW_DATA, substr($raw, 0, 16));
        while (openssl_error_string() !== false) {
        }
        $json = $plain === false ? null : json_decode($plain, true);
        if (! is_array($json)) {
            throw new InvalidWebhook('Signit webhook did not decrypt with the configured key.');
        }

        return $json;
    }

    /** @return array<string, mixed> JSON or form-encoded webhook body */
    private static function body(string $rawBody): array
    {
        $json = json_decode($rawBody, true);
        if (is_array($json)) {
            return $json;
        }
        parse_str($rawBody, $form);
        $body = [];
        foreach ($form as $key => $value) {
            $body[(string) $key] = $value;
        }

        return $body;
    }

    /** @return array<string, mixed> */
    private function signatory(Signer $signer, ?float $pageHeight): array
    {
        $verification = match ($signer->identity) {
            IdentityMethod::Nafath => ['nafath_app' => (string) $signer->nationalId],
            IdentityMethod::Email => ['email' => $signer->email],
            default => throw new EsignException("Signit does not support the \"{$signer->identity->value}\" identity method here. Use email or nafath."),
        };

        return [
            'full_name' => $signer->name,
            'order' => $signer->order,
            'verification_method' => $verification,
            'notification_method' => ['email' => $signer->email],
            'fields' => array_map(fn (SignatureField $f) => $this->field($f, (float) $pageHeight), $signer->fields),
        ];
    }

    /** @return array<string, mixed> */
    private function field(SignatureField $field, float $pageHeight): array
    {
        if ($field->documentIndex !== 0) {
            throw new EsignException('Signit requests hold one document; fields must be on document 0.');
        }

        return [
            'position' => [
                'page' => $field->page,
                'x' => (int) round($field->x),
                // Bottom-left origin: the distance from the page bottom to the box's bottom edge.
                'y' => (int) round($pageHeight - $field->y - $field->height),
                'width' => (int) round($field->width),
                'height' => (int) round($field->height),
            ],
            'properties' => ['required' => true],
            'placeholder' => 'Signature',
            'kind' => 'signature',
        ];
    }

    private function pageHeight(Envelope $envelope): ?float
    {
        $hasFields = array_filter($envelope->signers, fn (Signer $s) => $s->fields !== []) !== [];
        if (! $hasFields) {
            return null;
        }
        $height = $this->options->pageHeight ?? PdfPageSize::uniformHeight($envelope->documents[0]->contents);

        return $height ?? throw new EsignException('Cannot read the page height of this PDF (mixed sizes, rotation or compressed objects). Set the page_height option so signature fields land in the right place.');
    }

    /**
     * Signing links come back per signatory, in the order they were sent.
     *
     * @param array<string, mixed> $created
     *
     * @return array<string, string>
     */
    private function signingUrls(Envelope $envelope, array $created): array
    {
        $urls = [];
        foreach (self::signatories($created) as $i => $s) {
            $link = $s['signing_link'] ?? null;
            $email = self::email($s) ?? ($envelope->signers[$i]->email ?? null);
            if (is_string($link) && $link !== '' && is_string($email)) {
                $urls[$email] = $link;
            }
        }

        return $urls;
    }

    /** @return array<string, mixed> */
    private function request(string $envelopeId): array
    {
        $data = $this->api->json('GET', '/signature-requests/' . rawurlencode($envelopeId));

        return is_array($data['data'] ?? null) && ! isset($data['status']) ? $data['data'] : $data;
    }

    /** @param array<string, mixed> $data */
    private function map(array $data): EnvelopeStatus
    {
        $raw = strtoupper(trim((string) ($data['status'] ?? '')));
        $signatories = self::signatories($data);
        $signed = count(array_filter($signatories, fn (array $s) => self::signerStatus($s) === SignerStatus::Signed));
        $everyone = $signatories !== [] && $signed === count($signatories);

        return match ($raw) {
            // "SIGNED" can describe a single signer, so finished statuses also need every signer SIGNED.
            'COMPLETED', 'FINISHED', 'SIGNED' => $everyone ? EnvelopeStatus::Signed : ($signed > 0 ? EnvelopeStatus::PartiallySigned : EnvelopeStatus::Sent),
            'DRAFT', 'PENDING', 'SENT', 'IN-PROGRESS', 'IN_PROGRESS', 'INPROGRESS' => $signed > 0 ? EnvelopeStatus::PartiallySigned : EnvelopeStatus::Sent,
            'VOIDED' => EnvelopeStatus::Cancelled,
            'DECLINED', 'REJECTED' => EnvelopeStatus::Declined,
            'EXPIRED' => EnvelopeStatus::Expired,
            default => throw new ProviderError('signit', "Signit returned a status this driver does not know: \"{$raw}\". Please report it."),
        };
    }

    /** @param array<string, mixed> $signatory */
    private static function signerStatus(array $signatory): SignerStatus
    {
        return match (strtoupper((string) ($signatory['status'] ?? ''))) {
            'SIGNED', 'COMPLETED' => SignerStatus::Signed,
            'REJECTED', 'DECLINED' => SignerStatus::Declined,
            default => SignerStatus::Pending,    // PENDING, TRANSFERRED, anything else
        };
    }

    /**
     * @param array<string, mixed> $data
     *
     * @return list<array<string, mixed>>
     */
    private static function signatories(array $data): array
    {
        $list = $data['signatories'] ?? [];

        return is_array($list) ? array_values(array_filter($list, 'is_array')) : [];
    }

    /** @param array<string, mixed> $signatory */
    private static function email(array $signatory): ?string
    {
        foreach ([$signatory['email'] ?? null, $signatory['contact']['email'] ?? null, $signatory['notification_method']['email'] ?? null, $signatory['verification_method']['email'] ?? null] as $email) {
            if (is_string($email) && $email !== '') {
                return $email;
            }
        }

        return null;
    }

    /** @return array<string, mixed> */
    private function signatoryByEmail(string $envelopeId, string $email): array
    {
        foreach (self::signatories($this->request($envelopeId)) as $s) {
            if (strcasecmp((string) self::email($s), $email) === 0 && isset($s['id'])) {
                return $s;
            }
        }

        throw new EsignException("No signer with the email {$email} in Signit request {$envelopeId}.");
    }
}
