<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\Signit;

final readonly class SignitOptions
{
    public function __construct(
        /** Hex key (64 characters = 32 bytes) that decrypts webhooks. Webhooks are refused without it. */
        #[\SensitiveParameter] public ?string $webhookSecret = null,
        /** Accept webhooks that arrive unencrypted. Off: an unencrypted call proves nothing. */
        public bool $acceptUnencryptedWebhooks = false,
        /** Which certificate authority signs: NOTARIUS (used in production integrations), EMDHA, HYBRID... */
        public string $digitalSignatureProvider = 'NOTARIUS',
        /** Page height in points, for PDFs whose page size can't be read. Signit measures y from the bottom. */
        public ?float $pageHeight = null,
        /** Create embedded requests (signing inside your app) instead of emailed ones. */
        public bool $embedded = false,
    ) {
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return ['webhookSecret' => $this->webhookSecret === null ? null : '***', 'digitalSignatureProvider' => $this->digitalSignatureProvider, 'embedded' => $this->embedded];
    }
}
