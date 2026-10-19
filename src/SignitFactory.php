<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\Signit;

use HamadaEmamTech\Esign\Contracts\ProviderFactory;
use HamadaEmamTech\Esign\Contracts\SignatureProvider;
use HamadaEmamTech\Esign\Exceptions\EsignException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Builds the Signit provider from its config block:
 *
 *     'signit' => [
 *         'environment'    => 'sandbox',              // or 'production'
 *         'client_id'      => '...', 'client_secret' => '...',
 *         'webhook_secret' => '...',                  // 64-character hex key
 *         // optional: digital_signature_provider (NOTARIUS), page_height, embedded,
 *         //           accept_unencrypted_webhooks, base_url, http_client, request_factory,
 *         //           stream_factory, cache (PSR-16)
 *     ]
 */
final class SignitFactory implements ProviderFactory
{
    public const BASE_URLS = [
        'sandbox' => 'https://api-sandbox.signit.sa/v1',
        'production' => 'https://api.signit.sa/v1',
    ];

    public function create(array $config): SignatureProvider
    {
        $missing = array_values(array_filter(['client_id', 'client_secret'], fn (string $key) => ! is_string($config[$key] ?? null) || $config[$key] === ''));
        if ($missing !== []) {
            throw new EsignException('Signit config is missing: ' . implode(', ', $missing) . '.');
        }
        $environment = (string) ($config['environment'] ?? 'sandbox');
        $baseUrl = $config['base_url'] ?? self::BASE_URLS[$environment]
            ?? throw new EsignException("Signit environment must be \"sandbox\" or \"production\", got \"{$environment}\".");
        if (! str_starts_with((string) $baseUrl, 'https://')) {
            throw new EsignException('Signit base_url must be https.');
        }
        $secret = $config['webhook_secret'] ?? null;
        if ($secret !== null && $secret !== '' && (! is_string($secret) || strlen($secret) !== 64 || ! ctype_xdigit($secret))) {
            throw new EsignException('Signit webhook_secret must be the 64-character hex key from Signit.');
        }

        [$client, $requests, $streams] = self::http($config);
        $cache = $config['cache'] ?? null;

        return new SignitProvider(
            new SignitApi($client, $requests, $streams, new SignitCredentials((string) $config['client_id'], (string) $config['client_secret']), rtrim((string) $baseUrl, '/'), $cache instanceof CacheInterface ? $cache : null),
            new SignitOptions(
                webhookSecret: is_string($secret) && $secret !== '' ? $secret : null,
                acceptUnencryptedWebhooks: (bool) ($config['accept_unencrypted_webhooks'] ?? false),
                digitalSignatureProvider: (string) ($config['digital_signature_provider'] ?? 'NOTARIUS'),
                pageHeight: isset($config['page_height']) ? (float) $config['page_height'] : null,
                embedded: (bool) ($config['embedded'] ?? false),
            ),
        );
    }

    /**
     * The HTTP client you pass, or one that is installed: php-http/discovery, Guzzle 7, Symfony HttpClient.
     *
     * @param array<string, mixed> $config
     *
     * @return array{ClientInterface, RequestFactoryInterface, StreamFactoryInterface}
     */
    private static function http(array $config): array
    {
        $client = $config['http_client'] ?? null;
        $requests = $config['request_factory'] ?? null;
        $streams = $config['stream_factory'] ?? $requests;
        if ($client instanceof ClientInterface && $requests instanceof RequestFactoryInterface && $streams instanceof StreamFactoryInterface) {
            return [$client, $requests, $streams];
        }

        $discovery = 'Http\\Discovery\\Psr18ClientDiscovery';
        $factories = 'Http\\Discovery\\Psr17FactoryDiscovery';
        if (class_exists($discovery) && class_exists($factories)) {
            /** @var ClientInterface $found */
            $found = $discovery::find();
            /** @var RequestFactoryInterface $requestFactory */
            $requestFactory = $factories::findRequestFactory();
            /** @var StreamFactoryInterface $streamFactory */
            $streamFactory = $factories::findStreamFactory();

            return [$client instanceof ClientInterface ? $client : $found, $requests instanceof RequestFactoryInterface ? $requests : $requestFactory, $streams instanceof StreamFactoryInterface ? $streams : $streamFactory];
        }
        if (class_exists(\GuzzleHttp\Client::class) && class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            $factory = new \GuzzleHttp\Psr7\HttpFactory();

            return [$client instanceof ClientInterface ? $client : new \GuzzleHttp\Client(['timeout' => 60]), $factory, $factory];
        }
        $symfonyClass = 'Symfony\\Component\\HttpClient\\Psr18Client';
        if (class_exists($symfonyClass)) {
            /** @var ClientInterface&RequestFactoryInterface&StreamFactoryInterface $symfony */
            $symfony = new $symfonyClass();

            return [$client instanceof ClientInterface ? $client : $symfony, $symfony, $symfony];
        }

        throw new EsignException('Signit needs a PSR-18 HTTP client. Run: composer require guzzlehttp/guzzle (or pass http_client, request_factory and stream_factory).');
    }
}
