# Debugging guide

How to validate the wallet, what failure modes to expect, and where to look
when something is off.

## Smoke tests

Two scripts, both written to run against the live staging API.

### `scripts/smoke-e2e.mjs` — single round-trip

The fastest sanity check. Mirrors the browser code path with `jose` +
`@owf/mdoc` + WebCrypto (via Node 22's `globalThis.crypto.subtle`):

```bash
node scripts/smoke-e2e.mjs
```

Walks through OID4VCI receive → OID4VP present (one credential, one
verifier session) and prints structured status:

```
half1 receive OK — credential base64url len: 1458
half2 JAR parsed — { clientId, responseUri, responseMode, state, nonce, hasDcql }
half2 MSO: { docType, namespace, deviceKeyAlg, msoKeyX, walletKeyX, keysMatch }
half2 filter — keep: [ 'age_over_18' ] kept items: 1 / 1
half2 LOCAL verify (verifier recompute) — p256.verify: true
half2 walletTbs == verifierTbs? true
half2 posting to https://api-staging.tessaliq.com/v1/openid4vp/response?details=1
half2 verifier: 200 {"session_id":"…","status":"credential_verified",…}
half2 receipt: 200 {"receipt_token":"eyJ…"}
```

If `half2 verifier` is not `200`, see [DeviceAuth mismatches](#deviceauth-mismatches)
below.

`NO_FILTER=1 node scripts/smoke-e2e.mjs` ships the unfiltered `IssuerSigned`
— useful to isolate whether a failure is from selective disclosure
(digest mismatch) or from the device signature.

### `scripts/smoke-mw4-acceptance.mjs` — reusability + revocation

Validates the MW4 acceptance criteria: same credential across two
distinct verifier sessions, plus the admin-side revocation path.

```bash
node scripts/smoke-mw4-acceptance.mjs
```

Expected output (with the V1.1 revocation gap documented):

```
=== MW4 acceptance: reusability ===
1. Receive one credential from the Tessaliq issuer...
   credential len: 1458
2. Present to session A (first verifier)...
[A] session=… verify=200 receipt=200
3. Present the SAME credential to session B (second verifier)...
[B] session=… verify=200 receipt=200
   ✓ REUSABILITY: same credential accepted across 2 distinct sessions with 2 valid receipts

=== MW4 acceptance: revocation ===
4. Revoke index 0 of the default status list via /v1/credential/status...
   revoke: 200 {"list_id":"list-1","index":0,"revoked":true}
5. Present the same credential AGAIN (session C)...
[C] session=… verify=200 receipt=200
   △ EXPECTED V1 GAP: presentation accepted after revocation
```

The V1.1 gap closes when [tessaliq#224](https://github.com/oliviermeunier/tessaliq/issues/224)
P5.1 wires the status list pointer into the MSO and the verifier-side
check is added.

## Common failure modes

### `Device signature must be valid: undefined` (verifier 400)

The verifier rebuilt the `SessionTranscript` with different inputs than
the wallet signed against. The `undefined` reason comes from
`@owf/mdoc`'s `Verifier` reporting `status: FAILED` without a `reason`
on the signature-mismatch path — the message you see is literally
`${check}: ${reason}` with `reason` resolved to the string `"undefined"`.

Diagnose:

1. From the smoke output, confirm `walletTbs == verifierTbs? true` —
   that proves the wallet builds the same transcript a verifier
   would given the JAR's `client_id` / `response_uri` / `nonce`.
2. Compare the server logs (`flyctl logs --app tessaliq-api-staging`)
   for an `mdoc_st_inputs` line (if present in the deployed build).
   The four fields you want to compare are `clientId`, `responseUri`,
   `nonce`, and `cachedJarClientId`.
3. Check whether a session encryption key was unexpectedly stored.
   For `eu_av_blueprint` the response mode is forced to `direct_post`,
   which means no encryption and no jwkThumbprint in the transcript.
   If the verifier stored an encryption key anyway (regression of
   tessaliq#234), the wallet's transcript is missing the thumbprint
   while the verifier's transcript has it → 32-byte
   `OpenID4VPHandover` hash diverges → signature fails.

The historical instance of this bug:
[oliviermeunier/tessaliq#234](https://github.com/oliviermeunier/tessaliq/issues/234)
— closed 2026-05-13 via the response_mode-lockdown-before-encryption
fix.

### `vp_token and state are required` (verifier 400)

The wallet posted a payload Fastify could not extract `vp_token` /
`state` from. Causes seen so far:

- Wrong `Content-Type` (must be `application/x-www-form-urlencoded`).
- `vp_token` not URL-encoded properly. `URLSearchParams` produces the
  right encoding; `JSON.stringify` directly into the body does not.
- The wallet sent the wrong dcql id as the JSON key. The verifier
  parses `vp_token` as JSON object and reads the first entry — but if
  parsing fails it falls back to treating `vp_token` as a single
  string. The smoke prints the dcqlId for verification.

### `Failed to decode encrypted response` (verifier 400)

The wallet sent `response=<JWE>` when the verifier expected unencrypted
`vp_token` (or vice versa). Cross-check `request.responseMode` from the
JAR against what the wallet posted. For `eu_av_blueprint` it is always
`direct_post` (no encryption).

### Issuer returns 400 on `/v1/credential/issue`

Check the headers of the `proof.jwt`. Required:

- `typ: openid4vci-proof+jwt`
- `alg: ES256` (V1) or `ES384` (also accepted server-side)
- `jwk: <device public JWK>`
- payload `aud = <credential_issuer>`
- payload `nonce = <c_nonce from token response>`
- payload `iat = <now>`

The server logs include a `phase: issue_request_debug` line listing the
keys it received in the request body — if the proof's structure is off
that's where the surprise will be.

### Issuer returns 401 on `/v1/credential/token`

The `client_assertion` JWT didn't pass `private_key_jwt` validation.
Required:

- `alg: ES256`
- `typ: JWT`
- `jwk: <device public JWK>` (so the issuer can verify without prior
  client registration)
- payload `iss = sub = thumbprint(public JWK)`
- payload `aud = [<credential_issuer>, <token endpoint>]`
- payload `iat`, `exp = +5m`, `jti = uuid`

The server logs include a `phase: client_assertion_debug` line.

### Browser shows the wallet but credentials disappear

This is expected if you cleared site data, or if the browser is in
private / incognito mode. IndexedDB is per-origin + per-profile +
per-storage-partition.

To inspect: DevTools → Application → IndexedDB →
`tessaliq-mock-wallet` → `keys` and `credentials` stores.

To wipe deliberately: DevTools console:

```js
const req = indexedDB.deleteDatabase('tessaliq-mock-wallet')
req.onsuccess = () => console.log('wiped')
```

## Reading mdoc CBOR

Sometimes a credential or a `DeviceResponse` is failing for non-obvious
reasons and you want to look at the raw structure.

```js
// In a Node REPL with the project deps installed
import { IssuerSigned, DeviceResponse } from '@owf/mdoc'

// From a stored credential
const issuerSigned = IssuerSigned.fromEncodedForOid4Vci(credentialB64)
console.log(issuerSigned.issuerAuth.mobileSecurityObject.docType)
console.log(issuerSigned.getPrettyClaims('eu.europa.ec.av.1'))
console.log(issuerSigned.issuerAuth.mobileSecurityObject.validityInfo)

// From a vp_token
const dr = DeviceResponse.fromEncodedForOid4Vp(vpTokenB64)
const doc = dr.documents[0]
console.log(doc.docType)
console.log(doc.deviceSigned.deviceAuth.deviceSignature?.protectedHeaders.headers)
```

The `cbor2` CLI (or `cbor-diag`) is useful for converting raw CBOR to
a human-readable diagnostic form when you suspect structural drift:

```bash
echo "<base64url>" | base64 -d | cbor2diag.rb
```

## Reading verifier server logs

For everything that goes to `api-staging.tessaliq.com`:

```bash
flyctl logs --app tessaliq-api-staging --no-tail | grep <reqId>
flyctl logs --app tessaliq-api-staging --no-tail | grep <sessionId>
flyctl logs --app tessaliq-api-staging --no-tail | grep oid4vp
```

Relevant log keys to grep for:

| Key | What it tells you |
|-----|-------------------|
| `oid4vp: 'response_received'` | What Fastify saw in the body (`vp_token`, `state`, content-type) |
| `oid4vp: 'wallet_error_response'` | The wallet posted an OAuth error response (`error`, `error_description`) instead of a `vp_token` |
| `oid4vp: 'mdoc_st_inputs'` | (when the debug log is deployed) The four `SessionTranscript` inputs the verifier used at verify time |
| `mdoc: 'verify_dev'` or `'verify'` | The mdoc verification result — `failedChecks` lists the assessment names that didn't pass |
| `phase: 'client_assertion_debug'` | OID4VCI token endpoint — the JWT header the wallet sent |
| `phase: 'issue_request_debug'` | OID4VCI credential endpoint — the request body keys |

## Performance gotchas

- **Service worker caching**. The PWA service worker may return a stale
  bundle after a deploy. Force-reload (`Ctrl+Shift+R`) or unregister the
  worker (DevTools → Application → Service Workers → Unregister) when
  testing a fresh build.
- **DB recovery after Fly restart**. The staging Postgres has been
  observed to hang for several minutes after back-to-back deploys
  (memory + IO pressure). If smoke calls time out and `flyctl checks
  list --app tessaliq-db-staging-v2` shows critical state, restart the
  DB machine — it recovers in ~30 s.
- **Service worker + `vite-plugin-pwa` in dev**. The worker only runs
  in production builds. `pnpm dev` does not generate it. To exercise
  the offline shell, do `pnpm build && pnpm preview`.

## Known gaps (V1)

These are limitations the wallet acknowledges and that may surface as
runtime errors. None of them are bugs in this repository.

- **Revocation not enforced** on AV mdoc credentials (V1.1) — see
  CRYPTO.md "No revocation enforcement".
- **JAR signature not validated** — see CRYPTO.md "No JAR signature
  validation".
- **MAC0 device-auth not supported** — `@owf/mdoc` MAC mode is for
  NFC/BLE proximity, not relevant for online OID4VP. The wallet
  context adapter throws if a verifier requests it.
- **DC API / HPKE not supported** — V2 work. Verifiers that mandate
  `dc_api.jwt` cannot use this wallet.
- **SD-JWT-VC credentials not supported** — V2 work. mdoc only in V1.

## When you're stuck

If the smoke is green but the browser flow is not, walk through the
network tab and compare the request bodies and headers — the smoke
is the reference for what should go over the wire. Any difference
between the browser and the smoke is a bug in one of `src/lib/oid4vci.ts`,
`src/lib/oid4vp.ts`, or the UI wiring in `src/App.tsx`.

If both smoke and browser fail, the bug is most likely on the Tessaliq
backend — open an issue at
[oliviermeunier/tessaliq](https://github.com/oliviermeunier/tessaliq/issues)
with the smoke output and the relevant server logs.
