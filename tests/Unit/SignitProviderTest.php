<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\Signit\Tests\Unit;

use HamadaEmamTech\Esign\Envelope\Document;
use HamadaEmamTech\Esign\Envelope\Envelope;
use HamadaEmamTech\Esign\Envelope\EnvelopeStatus;
use HamadaEmamTech\Esign\Envelope\IdentityMethod;
use HamadaEmamTech\Esign\Envelope\SignatureField;
use HamadaEmamTech\Esign\Envelope\Signer;
use HamadaEmamTech\Esign\Envelope\SignerStatus;
use HamadaEmamTech\Esign\Exceptions\EsignException;
use HamadaEmamTech\Esign\Exceptions\InvalidWebhook;
use HamadaEmamTech\Esign\Exceptions\ProviderError;
use HamadaEmamTech\Esign\Signit\SignitFactory;
use HamadaEmamTech\Esign\Signit\SignitOptions;
use HamadaEmamTech\Esign\Signit\Tests\Support\FakeSignit;
use HamadaEmamTech\Esign\Testing\AssertsProviderConformance;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SignitProviderTest extends TestCase
{
    use AssertsProviderConformance;

    private FakeSignit $signit;

    protected function setUp(): void
    {
        $this->signit = new FakeSignit();
    }

    private static function envelope(?string $pdf = null): Envelope
    {
        return new Envelope(
            [new Document('contract.pdf', $pdf ?? FakeSignit::PDF)],
            [
                Signer::nafath('1012345678', 'Ahmed Ali', 'ahmed@example.sa', 1, [new SignatureField(1, 60, 700, 150, 50)]),
                Signer::email('Sara', 'sara@example.sa', 2, [new SignatureField(1, 300, 700, 150, 50)]),
            ],
            subject: 'Supply agreement',
        );
    }

    #[Test]
    public function it_conforms_to_the_shared_provider_contract(): void
    {
        $this->assertProviderConformance(new SignitFactory(), ['client_id' => 'a', 'client_secret' => 'b'], 'signit', __DIR__ . '/../../composer.json');
    }

    // ---- send -------------------------------------------------------------------------------

    #[Test]
    public function send_uploads_then_creates_the_request_in_signits_shape(): void
    {
        $sent = $this->signit->provider()->send(self::envelope());

        self::assertSame('1001', $sent->envelopeId);
        self::assertSame(['POST /v1/documents', 'POST /v1/signature-requests'], $this->signit->paths());

        $create = $this->signit->lastCreate;
        self::assertSame('doc_1.pdf', $create['document_name']);
        self::assertSame('Supply agreement', $create['signature_request']['title']);
        self::assertSame('NOTARIUS', $create['signature_request']['digital_signature_provider']);
        [$ahmed, $sara] = $create['signature_request']['signatories'];
        self::assertSame(['nafath_app' => '1012345678'], $ahmed['verification_method']);
        self::assertSame(['email' => 'ahmed@example.sa'], $ahmed['notification_method']);
        self::assertSame(1, $ahmed['order']);
        self::assertSame(['email' => 'sara@example.sa'], $sara['verification_method']);
        self::assertSame(2, $sara['order']);
    }

    #[Test]
    public function field_positions_are_flipped_to_signits_bottom_left_origin(): void
    {
        $this->signit->provider()->send(self::envelope());
        $field = $this->signit->lastCreate['signature_request']['signatories'][0]['fields'][0];

        // A4 is 842 pt tall. Top-left y=700 with a 50 pt box: its bottom edge is 750 from the top, 92 from the bottom.
        self::assertSame(['page' => 1, 'x' => 60, 'y' => 92, 'width' => 150, 'height' => 50], $field['position']);
        self::assertSame(['required' => true], $field['properties']);
        self::assertSame('signature', $field['kind']);
    }

    #[Test]
    public function signing_links_come_back_keyed_by_email_even_when_signit_omits_the_email(): void
    {
        self::assertSame(['ahmed@example.sa', 'sara@example.sa'], array_keys($this->signit->provider()->send(self::envelope())->signingUrls));

        $this->signit->omitEmails = true;
        self::assertSame(
            ['ahmed@example.sa' => 'https://app.signit.test/sign/1002/s0', 'sara@example.sa' => 'https://app.signit.test/sign/1002/s1'],
            $this->signit->provider()->send(self::envelope())->signingUrls,
        );
    }

    #[Test]
    public function an_unreadable_page_height_is_refused_before_any_call_unless_configured(): void
    {
        $rotated = "%PDF-1.7\n1 0 obj << /Type /Page /Rotate 90 /MediaBox [0 0 595 842] >> endobj\n";
        try {
            $this->signit->provider()->send(self::envelope($rotated));
            self::fail('Expected EsignException');
        } catch (EsignException $e) {
            self::assertStringContainsString('page_height', $e->getMessage());
        }
        self::assertSame([], $this->signit->calls);

        $this->signit->provider(new SignitOptions(webhookSecret: FakeSignit::WEBHOOK_KEY, pageHeight: 792))->send(self::envelope($rotated));
        self::assertSame(42, $this->signit->lastCreate['signature_request']['signatories'][0]['fields'][0]['position']['y']);   // 792 - 700 - 50
    }

    #[Test]
    public function what_signit_cannot_do_is_refused_before_any_call(): void
    {
        $two = new Envelope([new Document('a.pdf', FakeSignit::PDF), new Document('b.pdf', FakeSignit::PDF)], [Signer::email('A', 'a@example.sa')]);
        $sms = new Envelope([new Document('a.pdf', FakeSignit::PDF)], [new Signer('Omar', 'omar@example.sa', IdentityMethod::SmsOtp, mobile: '+966500000000')]);

        foreach ([[$two, 'one document'], [$sms, 'sms_otp']] as [$envelope, $message]) {
            try {
                $this->signit->provider()->send($envelope);
                self::fail("Expected: {$message}");
            } catch (EsignException $e) {
                self::assertStringContainsString($message, $e->getMessage());
            }
        }
        self::assertSame([], $this->signit->calls);
    }

    // ---- status, details, download, cancel, remind ---------------------------------------------

    #[Test]
    public function status_requires_every_signer_before_it_says_signed(): void
    {
        $provider = $this->signit->provider();
        $id = $provider->send(self::envelope())->envelopeId;

        self::assertSame(EnvelopeStatus::Sent, $provider->status($id));
        $this->signit->sign($id, 0);
        self::assertSame(EnvelopeStatus::PartiallySigned, $provider->status($id));

        // A request-level "SIGNED" while someone is still pending is not finished.
        $this->signit->forcedStatus = 'SIGNED';
        self::assertSame(EnvelopeStatus::PartiallySigned, $provider->status($id));

        $this->signit->forcedStatus = null;
        $this->signit->signAll($id);
        self::assertSame(EnvelopeStatus::Signed, $provider->status($id));
    }

    #[Test]
    public function other_statuses_map_and_unknown_ones_fail_loudly(): void
    {
        $provider = $this->signit->provider();
        $id = $provider->send(self::envelope())->envelopeId;

        foreach (['VOIDED' => EnvelopeStatus::Cancelled, 'REJECTED' => EnvelopeStatus::Declined, 'DECLINED' => EnvelopeStatus::Declined, 'EXPIRED' => EnvelopeStatus::Expired, 'PENDING' => EnvelopeStatus::Sent] as $raw => $expected) {
            $this->signit->forcedStatus = $raw;
            self::assertSame($expected, $provider->status($id), $raw);
        }

        $this->signit->forcedStatus = 'ARCHIVED';
        $this->expectException(ProviderError::class);
        $this->expectExceptionMessage('"ARCHIVED"');
        $provider->status($id);
    }

    #[Test]
    public function details_lists_each_signer(): void
    {
        $provider = $this->signit->provider();
        $id = $provider->send(self::envelope())->envelopeId;
        $this->signit->sign($id, 1);

        $details = $provider->details($id);

        self::assertSame("signit:{$id}", (string) $details->ref);
        self::assertSame([SignerStatus::Pending, SignerStatus::Signed], array_map(fn ($s) => $s->status, $details->signers));
        self::assertSame('ahmed@example.sa', $details->pending()[0]->email);
    }

    #[Test]
    public function download_follows_the_sealed_file_url_without_leaking_the_token(): void
    {
        $provider = $this->signit->provider();
        $id = $provider->send(self::envelope())->envelopeId;

        try {
            $provider->download($id);
            self::fail('Download must refuse an unsigned request');
        } catch (EsignException $e) {
            self::assertStringContainsString('not signed', $e->getMessage());
        }

        $this->signit->signAll($id);
        self::assertSame(FakeSignit::SEALED, $provider->download($id));

        $last = $this->signit->calls[array_key_last($this->signit->calls)];
        self::assertStringStartsWith('https://files.signit.test/', $last['url']);
        self::assertSame('', $last['auth'], 'the bearer token must not go to the download host');
        self::assertContains("GET /v1/signature-requests/{$id}/files?file_type=sealed", $this->signit->paths());
    }

    #[Test]
    public function cancel_voids_the_request(): void
    {
        $provider = $this->signit->provider();
        $id = $provider->send(self::envelope())->envelopeId;
        $provider->cancel($id);

        self::assertContains("PUT /v1/signature-requests/{$id}/void", $this->signit->paths());
        self::assertSame(EnvelopeStatus::Cancelled, $provider->status($id));
    }

    #[Test]
    public function remind_targets_the_signatory_by_email(): void
    {
        $provider = $this->signit->provider();
        $id = $provider->send(self::envelope())->envelopeId;
        $provider->remind($id, 'SARA@example.sa');

        self::assertContains("POST /v1/signature-requests/{$id}/signatories/s1/reminders", $this->signit->paths());

        $this->expectException(EsignException::class);
        $provider->remind($id, 'nobody@example.sa');
    }

    // ---- webhooks -----------------------------------------------------------------------------

    #[Test]
    public function an_encrypted_webhook_decrypts_to_the_request_id(): void
    {
        $provider = $this->signit->provider();
        $body = FakeSignit::encryptedWebhook(['event_type' => 'SIGNATORY_SIGNED', 'data' => ['signature_request_id' => 1001, 'signatories' => []]]);

        self::assertTrue($provider->recognizesWebhook([], $body));
        $event = $provider->parseWebhook([], $body);
        self::assertSame('1001', $event->envelopeId);
        self::assertSame('SIGNATORY_SIGNED', $event->payload['event_type']);

        // Form-encoded and flat payloads too.
        $form = FakeSignit::encryptedWebhook(['event' => 'REQUEST_COMPLETED', 'signatureRequestId' => '1001'], asForm: true);
        self::assertSame('1001', $provider->parseWebhook([], $form)->envelopeId);
    }

    #[Test]
    public function a_webhook_encrypted_with_another_key_is_refused(): void
    {
        $this->expectException(InvalidWebhook::class);
        $this->signit->provider()->parseWebhook([], FakeSignit::encryptedWebhook(['data' => ['signature_request_id' => 1]], str_repeat('ab', 32)));
    }

    #[Test]
    public function without_a_key_or_encryption_webhooks_are_refused_by_default(): void
    {
        $plain = (string) json_encode(['is_encrypted' => false, 'event_type' => 'REQUEST_COMPLETED', 'data' => ['signature_request_id' => 1001, 'event_type' => 'x']]);

        foreach ([[$this->signit->provider(new SignitOptions()), FakeSignit::encryptedWebhook(['data' => ['signature_request_id' => 1]])], [$this->signit->provider(), $plain]] as [$provider, $body]) {
            try {
                $provider->parseWebhook([], $body);
                self::fail('Expected InvalidWebhook');
            } catch (InvalidWebhook) {
            }
        }

        $open = $this->signit->provider(new SignitOptions(acceptUnencryptedWebhooks: true));
        self::assertSame('1001', $open->parseWebhook([], $plain)->envelopeId);
    }

    #[Test]
    public function noise_is_not_mistaken_for_a_signit_webhook(): void
    {
        $provider = $this->signit->provider();

        foreach (['', '{"RequestId":"x","Status":1}', '{"data":{"documentId":"d"}}', 'status=finished&signer_process_id=sp_1'] as $body) {
            self::assertFalse($provider->recognizesWebhook([], $body), $body);
        }
    }

    // ---- auth and factory ---------------------------------------------------------------------

    #[Test]
    public function the_token_is_reused_and_refreshed_once_on_401(): void
    {
        $provider = $this->signit->provider();
        $id = $provider->send(self::envelope())->envelopeId;
        $provider->status($id);
        self::assertSame(1, $this->signit->tokenCalls);

        $this->signit->unauthorizedNext = 1;
        $provider->status($id);
        self::assertSame(2, $this->signit->tokenCalls);
    }

    #[Test]
    public function a_failed_login_never_leaks_the_secret(): void
    {
        $factory = new \GuzzleHttp\Psr7\HttpFactory();
        $provider = new \HamadaEmamTech\Esign\Signit\SignitProvider(new \HamadaEmamTech\Esign\Signit\SignitApi($this->signit, $factory, $factory, new \HamadaEmamTech\Esign\Signit\SignitCredentials('api-key', 'wrong-secret-value'), 'https://api-sandbox.signit.test/v1'));

        try {
            $provider->status('1');
            self::fail('Expected ProviderError');
        } catch (ProviderError $e) {
            self::assertSame('invalid_client', $e->providerCode);
            self::assertStringNotContainsString('wrong-secret-value', $e->getMessage());
        }
    }

    #[Test]
    public function the_factory_validates_its_config(): void
    {
        foreach ([[[], 'client_id, client_secret'], [['client_id' => 'a', 'client_secret' => 'b', 'environment' => 'qa'], '"sandbox" or "production"'], [['client_id' => 'a', 'client_secret' => 'b', 'webhook_secret' => 'not-hex'], '64-character hex']] as [$config, $message]) {
            try {
                (new SignitFactory())->create($config);
                self::fail("Expected: {$message}");
            } catch (EsignException $e) {
                self::assertStringContainsString($message, $e->getMessage());
            }
        }
    }

    #[Test]
    public function secrets_stay_out_of_debug_output(): void
    {
        $dump = print_r(new \HamadaEmamTech\Esign\Signit\SignitCredentials('id', 'very-secret'), true) . print_r(new SignitOptions(webhookSecret: FakeSignit::WEBHOOK_KEY), true);

        self::assertStringNotContainsString('very-secret', $dump);
        self::assertStringNotContainsString(FakeSignit::WEBHOOK_KEY, $dump);
    }
}
