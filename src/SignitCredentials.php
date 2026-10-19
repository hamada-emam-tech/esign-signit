<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\Signit;

/** The OAuth client Signit issues (the "API key" and secret). Kept out of var_dump() and error trackers. */
final readonly class SignitCredentials
{
    public function __construct(
        public string $clientId,
        #[\SensitiveParameter] public string $clientSecret,
    ) {
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['clientId' => $this->clientId, 'clientSecret' => '***'];
    }
}
