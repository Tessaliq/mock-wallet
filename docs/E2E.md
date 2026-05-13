# End-to-end test scenario

This document describes how to exercise the mock wallet against the live
Tessaliq staging API at `https://api-staging.tessaliq.com`. Use it after every
substantive change to MW2 / MW3.

The flow has two halves: receive a credential (OID4VCI), then present it to a
verifier session (OID4VP). Both halves are independent and can be run in
either order.

## Prerequisites

- The mock wallet is loaded in a modern browser at
  `https://wallet-demo.tessaliq.com/` (or `pnpm dev` locally).
- The staging API key embedded in the public demo:
  `tsl_live_KOeL1k1ID_puLRqvsRDT2yTtqWQp8MUSSe87Ce4Ihv4`.
  It is intentionally public — the same key is shipped in the
  `demo.tessaliq.com` frontend.
- `curl` and `jq` installed locally.

## Half 1 — receive an mdoc credential (OID4VCI)

The staging API exposes a conformance helper that mints a credential offer
without going through the full verifier flow. It returns a `tx_code` (PIN)
the wallet must submit on the token exchange.

```bash
curl -sS -X POST https://api-staging.tessaliq.com/v1/test-helpers/oidf-credential-offer | jq
```

Expected:

```json
{
  "session_id": "…",
  "pre_authorized_code": "…",
  "tx_code": "1234",
  "credential_offer": { … },
  "credential_offer_uri": "openid-credential-offer://?credential_offer=…"
}
```

Steps in the wallet UI:

1. Click **Add credential**.
2. Paste the `credential_offer_uri` from the response above.
3. Click **Continue** — the wallet parses the offer and detects the
   `tx_code` requirement.
4. Enter the PIN (`1234`) and click **Receive credential**.

What this exercises end-to-end:

- `parseCredentialOffer` (inline JSON or `credential_offer_uri`)
- `/v1/credential/token` round-trip with `private_key_jwt` client
  authentication signed by the device key + `tx_code` + pre-authorized code
- `/v1/credential/issue` with the `proof.jwt` signed by the device key
- mdoc CBOR decode + IndexedDB persistence

On success, the credential appears in the **Credentials** list with namespace
`eu.europa.ec.av.1` and claims `age_over_18`, etc.

## Half 2 — present the credential (OID4VP)

Create a fresh verifier session, fetch the deep link, paste it into the
wallet.

```bash
SESSION=$(curl -sS -X POST https://api-staging.tessaliq.com/v1/sessions \
  -H "Authorization: Bearer tsl_live_KOeL1k1ID_puLRqvsRDT2yTtqWQp8MUSSe87Ce4Ihv4" \
  -H "Content-Type: application/json" \
  -d '{"useCase":"age_verification_18_plus","jurisdiction":"FR"}' | jq -r .id)

curl -sS "https://api-staging.tessaliq.com/v1/openid4vp/link/$SESSION" | jq -r .deep_link
```

Steps in the wallet UI:

1. Scroll to **Present credential**.
2. Paste the `deep_link` (`openid4vp://authorize?…`).
3. Click **Continue** — the wallet fetches the JAR via `request_uri`,
   parses the DCQL, and matches the stored credential.
4. Inspect the **Consent screen** :
   - Verifier `client_id` (`x509_hash:…`).
   - `response_uri` the wallet will POST to.
   - Claims being shared (e.g. `age_over_18`).
5. Click **Share**.

On success, the **Confirmation screen** shows verifier `HTTP 200` and
optionally a `redirect_uri`. The verifier-side receipt can be fetched with:

```bash
curl -sS "https://api-staging.tessaliq.com/v1/sessions/$SESSION/receipt" \
  -H "Authorization: Bearer tsl_live_KOeL1k1ID_puLRqvsRDT2yTtqWQp8MUSSe87Ce4Ihv4" | jq
```

The returned `receipt_token` is a signed JWT (ES256) attesting that the
session reached the `verified` state.

What this exercises end-to-end:

- `parseAuthorizationRequest` (JAR `request_uri` path)
- DCQL matching against stored credentials
- `SessionTranscript.forOid4Vp` (binds clientId / responseUri / nonce)
- mdoc DeviceResponse build with selective disclosure (only the claims the
  verifier asked for survive in `IssuerSigned`)
- `DeviceSignedBuilder.sign` with the self-signed device cert in `x5chain`
- `direct_post` round-trip with the verifier's `response_uri`

## Half 3 — reuse + revocation (Variante C)

Once a credential is stored, the same mdoc can be presented to N consecutive
verifier sessions. Variante C is validated when:

1. The wallet still holds the credential after a page reload.
2. A second `POST /v1/sessions` + `GET /openid4vp/link/...` round-trip
   succeeds with the same wallet, without re-running Half 1.

Revocation testing is **deferred**: it requires an admin API surface on the
Tessaliq side (`/v1/credential/status/:id/revoke`) that is not enabled on
staging today. Track via Tessaliq issue
[#224](https://github.com/oliviermeunier/tessaliq/issues/224) P6.

## Known gaps

- **JAR signature validation** : V1 accepts unsigned and signed JAR
  requests without validating the x509 chain. The UI surfaces a warning
  when the request is unsigned.
- **DC API + HPKE encrypted response** : not implemented in V1
  (`direct_post` only).
- **MAC0 device auth** : not implemented (signature mode only).
- **CBOR round-trip of `IssuerSignedItem`** : selective disclosure relies
  on `@owf/mdoc` preserving the original byte representation when
  re-encoding filtered items. If a verifier rejects with a digest mismatch,
  the fallback is to ship the full credential and let the verifier ignore
  the extra claims.
