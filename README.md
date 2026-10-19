# hamada-emam-tech/esign-signit

[Signit](https://signit.sa) driver for [hamada-emam-tech/esign](https://github.com/hamada-emam-tech/esign-php): Saudi DGA-licensed e-signature, with Nafath identity.

> **Status:** built from Signit's API collection and from the request and response handling of a production Signit integration. This package has not yet been run against a Signit account. The points to confirm are listed below.

```bash
vendor/bin/esign add signit          # or: composer require hamada-emam-tech/esign-signit
```

## Configure

```php
$esign = new Esign([
    'default'   => 'signit',
    'providers' => [
        'signit' => [
            'environment'    => 'production',         // or 'sandbox' (the default)
            'client_id'      => getenv('SIGNIT_CLIENT_ID'),
            'client_secret'  => getenv('SIGNIT_CLIENT_SECRET'),
            'webhook_secret' => getenv('SIGNIT_WEBHOOK_SECRET'),   // the 64-character hex key from Signit
        ],
    ],
]);
```

| Option | Default | Notes |
|---|---|---|
| `environment` | `sandbox` | `sandbox` → `https://api-sandbox.signit.sa/v1`, `production` → `https://api.signit.sa/v1` |
| `base_url` | from `environment` | Must be https. |
| `client_id`, `client_secret` | required | The API key and secret of your Signit app (OAuth client credentials). |
| `webhook_secret` | none | Hex key that decrypts webhooks. Without it, every webhook is refused. |
| `accept_unencrypted_webhooks` | `false` | Accept webhooks that arrive unencrypted. Only safe because the status always comes from the API. |
| `digital_signature_provider` | `NOTARIUS` | Which certificate authority signs, e.g. `NOTARIUS`, `EMDHA`, `HYBRID`. |
| `page_height` | read from the PDF | Points. Needed only when the PDF's page size can't be read (mixed sizes, rotation, compressed objects). |
| `embedded` | `false` | Create embedded requests, for signing inside your own app. |
| `http_client`, `request_factory`, `stream_factory`, `cache` | | As for every driver. |

## Use it

```php
use HamadaEmamTech\Esign\Envelope\{Envelope, Document, Signer, SignatureField};

$sent = $esign->send(new Envelope(
    documents: [Document::fromPath('contract.pdf')],
    signers: [
        Signer::nafath('1012345678', 'Ahmed Ali', 'ahmed@example.sa', order: 1, fields: [new SignatureField(page: 1, x: 60, y: 700)]),
        Signer::email('Sara', 'sara@example.sa', order: 2, fields: [new SignatureField(page: 1, x: 300, y: 700)]),
    ],
    subject: 'Supply agreement',
));
$contract->esign_ref = (string) $sent->ref();       // "signit:1001"
$sent->signingUrls;                                 // email => signing link

// Webhooks, status, download and reminders: the same calls as every provider (see docs/webhooks.md)
$esign->status($ref);
$esign->details($ref)->pending();
$esign->remind($ref, 'sara@example.sa');
$pdf = $esign->download($ref);                      // the sealed PDF, once everyone signed
$esign->cancel($ref);                               // voids the request
```

Signit-only extras: `$esign->provider('signit')->signingLink($id, $email)`, `->completeByOwner($id)` and `->auditTrail($id)`.

## Capabilities

| | Signit |
|---|---|
| Identity methods | `email`, `nafath` |
| Documents per envelope | 1 |
| Signing order, field placement, signing links | yes |
| `remind()`, `details()` | yes |
| `extendDeadline()`, webhook management | no |

## Status mapping

| Signit request status | `EnvelopeStatus` |
|---|---|
| `DRAFT`, `PENDING`, `SENT`, `IN-PROGRESS`, nobody signed | `Sent` |
| the same, some signers `SIGNED` | `PartiallySigned` |
| `COMPLETED`, `FINISHED`, `SIGNED`, **and every signer `SIGNED`** | `Signed` |
| `COMPLETED`/`FINISHED`/`SIGNED` while someone is still pending | `PartiallySigned` |
| `VOIDED` | `Cancelled` |
| `DECLINED`, `REJECTED` | `Declined` |
| `EXPIRED` | `Expired` |
| anything else | throws `ProviderError` |

Signer statuses: `SIGNED` → Signed; `REJECTED` → Declined; `PENDING`, `TRANSFERRED` → Pending.

## What this driver handles for you

1. **Bottom-left coordinates.** Signit measures `y` from the page bottom to the box's bottom edge. `SignatureField` is top-left, so the driver converts using the page height read from the PDF, and refuses before uploading anything when it can't tell the height.
2. **Encrypted webhooks.** Signit sends `{"data": base64(IV + AES-256-CBC(json)), "is_encrypted": true}`. The driver decrypts with your hex key and refuses anything that doesn't decrypt, or that isn't encrypted (unless you allow it).
3. **"SIGNED" doesn't always mean finished.** Event names such as `SIGNATORY_SIGNED` contain "SIGNED" when only one person signed. The driver never reads a status from a webhook, and `Signed` requires every signer to be `SIGNED`.
4. **The sealed file comes as a URL.** `download()` follows it without sending your token to the download host, and checks it is a PDF.
5. **Reminders go to a signatory ID.** `remind()` looks the signer up by email first.

## Points to confirm on a live account

1. Whether the create response always includes each signer's email. If it doesn't, signing links are matched to signers in the order they were sent.
2. Signit's error body format (not published). The driver reads `message`, `error`, `error_description` and `errors` when present.
3. Whether Signit's API collection key `verification_method` and the production integration's use of it agree for every identity type. Both use `{nafath_app: "<national ID>"}` and `{email: "…"}`.

## Sources

- Signit API collection: https://www.postman.com/collections/26439087-a31a0923-d572-4a9d-87e1-3322c7482bfc
- Signit help centre, API pages: https://help.signit.sa/en/migrated/integrations-and-api
