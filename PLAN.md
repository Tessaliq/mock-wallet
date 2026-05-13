# Implementation plan — Mock Wallet V1

> Living document. Updated as decisions are made and phases complete.
>
> Date: 2026-05-12
> Status: V1 in scoping (MW0 phase)
> Parent issue (Tessaliq side): https://github.com/oliviermeunier/tessaliq/issues/224 (Variante C)

## Objective

Unblock the end-to-end test of Tessaliq Variante C (reusable AV credential) without depending on the French national wallet sandbox or the EU AV reference Android app (which currently crashes on enrolment, v2026.04-2).

Deliver a browser-based PWA that demonstrates:

```
Tessaliq Issuer (existing) → Mock Wallet (this repo) → Tessaliq Verifier (existing) → receipt JWT
```

Same credential reused across N verifier sessions, with device binding via WebCrypto and revocation tested via the IETF status list draft-14.

## Decisions log

| Decision | Choice | Reason |
|---|---|---|
| Frontend stack | Vite + React + TypeScript | Fast bootstrap, mature crypto/CBOR/QR ecosystem |
| UI | TailwindCSS + shadcn/ui | Consistency with Tessaliq dashboard |
| Crypto | WebCrypto API native (P-256 ECDSA / ES256) | Standard, browser-native, non-extractable keys |
| JWT building | `jose` (or `panva/jose`) | Already used on the Tessaliq backend |
| mdoc CBOR | **TBD in MW0** — check `@owf/mdoc` browser compat; fallback `cbor-web` + manual mdoc subset | Risk to validate first |
| QR scanning | `@yudiel/react-qr-scanner` or equivalent | Mainstream, camera + image upload |
| Storage | IndexedDB native (no library wrapper initially) | Standard browser API, no extra dep |
| Hosting | New Vercel project → `wallet-demo.tessaliq.com` | Clean separation from `demo.tessaliq.com` |
| License | MIT | Same as `tessaliq-open` |
| Branding | "Tessaliq Mock Wallet" with permanent "DEMO ONLY" banner | Avoid commercial-demo ambiguity |
| Credential format V1 | mdoc only (`eu.europa.ec.av.1`) | Matches Variante C scope |
| Presentation mode V1 | `direct_post` only | DC API + HPKE deferred to V2 |
| Auth flow V1 | Pre-authorized code only | Matches what Tessaliq Issuer exposes |
| Camera QR scan in V1 | Yes | Realistic E2E flow validation |

## Phase breakdown

### MW0 — Technical scoping + bootstrap (0.5 day) ✅ DONE 2026-05-12

- [x] Verify whether `@owf/mdoc` (v0.6.x, currently used on the Tessaliq API side) is browser-compatible
  - **Result: OK.** ESM-only distribution, zero node-only imports, runtime deps (`cbor-x`, `zod`, `zod-validation-error`) all browser-compat. Used directly.
- [x] Initialise the project with Vite + React + TypeScript template
- [x] Add Tailwind, jose deps. (shadcn/ui + `@yudiel/react-qr-scanner` deferred to MW2/MW3 when actually needed.)
- [x] Configure PWA manifest + minimal service worker via `vite-plugin-pwa`
- [x] Set up the new Vercel project, point `wallet-demo.tessaliq.com` to it (DNS via Infomaniak CNAME → cname.vercel-dns.com)
- [x] Build local works (vite 593 ms, 195 kB JS gzip 61 kB, PWA SW generated), deploy hello-world to `https://wallet-demo.tessaliq.com` confirmed live

**Output:** project bootstrapped, deploys, loaded from `wallet-demo.tessaliq.com`. Risk on `@owf/mdoc` resolved.

### MW1 — Device key + storage (0.5 day) ✅ DONE 2026-05-12

- [x] `src/lib/device-key.ts` — `getOrCreateDeviceKey()` returns a P-256 ECDSA CryptoKey pair, non-extractable, persisted across sessions
- [x] `src/lib/storage.ts` — IndexedDB schema (`keys` + `credentials` stores), `StoredCredential` type, helpers `listCredentials`, `putCredential`, `deleteCredential`
- [x] Test page: shows the device key public JWK + RFC 7638 thumbprint, lists stored credentials

**Output:** device key persists across page reloads, IndexedDB schema ready. Commit `5096ca5`.

### MW2 — OID4VCI reception flow (1.5 days)

- [ ] `src/lib/oid4vci-client.ts`:
  - parse `openid-credential-offer://?credential_offer=...` URL
  - fetch `${issuer}/.well-known/openid-credential-issuer` metadata
  - call token endpoint with pre-authorized code → receive `access_token` + `c_nonce`
  - build `proof.jwt`: `header.typ='openid4vci-proof+jwt'`, `header.alg='ES256'`, `header.jwk=<device public key>`, payload contains `aud=issuer`, `iat`, `nonce=c_nonce`
  - sign the `proof.jwt` using the device private key via WebCrypto
  - call credential endpoint with `access_token` + `proof.jwt` → receive the mdoc credential
  - parse mdoc CBOR (issuer-signed namespace, MSO, validity period)
  - store the credential in IndexedDB
- [ ] UI:
  - home page with "Add credential" button → opens QR scanner OR URL input
  - "Credential received" page showing claims (`age_over_18`, `age_over_21`, issuer, expiry)

**Output:** can run `Tessaliq Issuer /v1/credential/offer → mock wallet`. Credential stored locally.

### MW3 — OID4VP presentation flow (1.5 days) ✅ DONE 2026-05-13

- [x] `src/lib/oid4vp.ts`:
  - parse `openid4vp://?...` link (or HTTPS link with the request); inline `request=` JWT + `request_uri` JAR + raw query params
  - V1 accepts unsigned and signed verifier requests without x509 chain validation (`signed` flag surfaced to UI warning); V2 must validate
  - extract requested claims from DCQL (`claims[].path` last segment)
  - build the OID4VP session transcript via `SessionTranscript.forOid4Vp`
  - construct an mdoc DeviceResponse:
    - filter `IssuerSignedItems` to the requested claim list (selective disclosure)
    - `DeviceSignedBuilder.sign()` with ES256 over the SessionTranscript
    - wrap into `Document` + `DeviceResponse.createSimple`
  - POST `vp_token={"<dcqlId>":"<base64url(CBOR DeviceResponse)>"}` to the verifier's `response_uri` via `direct_post`, surface verifier 200/redirect_uri
- [x] `src/lib/device-cert.ts`: self-signed X.509 cert for the device key (ECDSA P-256, SHA-256, 10-year validity), generated via `@peculiar/x509` and persisted alongside the key. Used as the `derCertificate` `x5chain` payload for `DeviceSignedBuilder`.
- [x] UI:
  - "Present credential" panel with paste-URL form
  - Consent screen: verifier identity (`client_id`), `response_uri`, signed/unsigned warning, claims being shared per DCQL slot, Share / Cancel
  - Confirmation page: verifier status, optional `redirect_uri`, raw response toggle

**Output:** `mock wallet → Tessaliq Verifier` end-to-end. Selective disclosure validated through the existing MSO digests. Build passes (`pnpm build` 4 s, 808 kB JS gzip 213 kB).

### MW4 — End-to-end test + revocation (0.5 day) — DONE 2026-05-13

**OID4VCI half: VALIDATED 2026-05-13** via a node smoke-test that mirrors
the wallet code (jose ES256, same headers, same params) against the live
`api-staging.tessaliq.com`:

- `POST /v1/test-helpers/oidf-credential-offer` → offer with `tx_code=1234`
- `POST /v1/credential/token` with `client_assertion_type` +
  `client_assertion` (`private_key_jwt` per OIDF HAIP) + `tx_code` →
  `access_token` + `c_nonce` OK
- `POST /v1/credential/issue` with `proof.jwt` (`openid4vci-proof+jwt`) →
  mdoc credential (1458 bytes base64url, `notification_id` returned) OK

**OID4VP half: VALIDATED 2026-05-13** after Tessaliq fix
[oliviermeunier/tessaliq#234](https://github.com/oliviermeunier/tessaliq/issues/234).

Root cause was a sequencing bug in `handleAuthorizationRequest`: the
default `responseMode` is `direct_post.jwt`, which caused the route to
store an HPKE session encryption key in Redis BEFORE
`buildAuthorizationRequest` applied the `eu_av_blueprint` profile
lockdown that rewrites `response_mode` to `direct_post` in the JAR. The
wallet (told `direct_post`, no encryption) signed `SessionTranscript`
without a `jwkThumbprint`; the verifier retrieved the stored key,
computed a thumbprint, and rebuilt `SessionTranscript` WITH it. The
32-byte `OpenID4VPHandover` hash diverged → `Verifier.verifyDeviceResponse`
reported `Device signature must be valid: FAILED` (no `reason` field on
the signature-mismatch path, hence the literal `undefined` in the
server response). Fix in tessaliq commit `2b8c3aa7` hoists the profile
lockdown above the encryption block.

**Reusability + revocation: VALIDATED 2026-05-13** via
[`scripts/smoke-mw4-acceptance.mjs`](./scripts/smoke-mw4-acceptance.mjs)
against staging:

- Receive 1 credential → present to session A → `200 credential_verified`
  + receipt JWT.
- Present the SAME credential to session B → `200 credential_verified`
  + a second valid receipt JWT (REUSABILITY proven across distinct
  sessions).
- `POST /v1/credential/status { action: 'revoke', index: 0 }` → `200`
  (admin endpoint works).
- Present same credential to session C → `200 credential_verified`
  (gap: see V1.1 follow-up below).

**V1.1 gap (documented, not blocking V1 acceptance):**
`buildAvCredential` does not yet embed a `status_list` pointer in the
MSO, so the verifier has no claim to check against and revocation is
not enforced on AV credentials. The admin endpoint succeeds (the
bitstring is updated and `/.well-known/status-list/list-1` reflects
the revocation), but the wallet's stored credential remains
verifier-accepted until V1.1 wires the status pointer into the MSO.
Tracked in [oliviermeunier/tessaliq#224](https://github.com/oliviermeunier/tessaliq/issues/224)
P5.1.

- [x] Reproducible E2E test scenario:
  1. Trigger a verifier session on Tessaliq → wallet presents the user's PID France Identité (simulated) → Tessaliq issues a derived AV credential offer
  2. Wallet receives the offer (MW2), stores the AV credential
  3. Trigger a second verifier session on Tessaliq from a different "merchant" context → wallet presents the stored AV credential
  4. Verifier returns a receipt JWT → verifier confirms the same credential was reused
- [~] Revocation test (admin endpoint OK; verifier enforcement gated on tessaliq#224 P5.1):
  1. Admin endpoint on Tessaliq revokes the credential (existing P5 endpoint) — ✓
  2. Wallet attempts to present → verifier checks the status list → rejects with "revoked" — gap (V1.1)
  3. Wallet UI shows the revocation reason — N/A until step 2 lands

**Output:** Variante C P6 (mock-wallet) validated end-to-end via headless smoke. Browser UI smoke pending MW5.

### MW5 — Documentation + polish + deploy (0.5 day)

- [ ] Complete `README.md` with screenshots and full quick-start
- [ ] Document the E2E test scenario in `docs/E2E.md`
- [ ] Add a CONTRIBUTING.md
- [ ] Set up GitHub Actions: lint + typecheck + build
- [ ] Final deploy to `wallet-demo.tessaliq.com`
- [ ] Update memories on the Tessaliq side (mark Variante C P6 as validated via mock wallet)
- [ ] Update Tessaliq `feature-matrix.md` and `src/CLAUDE.md`
- [ ] Update `project_variante_c_issuer_av` memory

**Output:** repo ready for public visibility, P6 marked done on Tessaliq side.

## Effort total

| Phase | Effort |
|---|---|
| MW0 | 0.5 d |
| MW1 | 0.5 d |
| MW2 | 1.5 d |
| MW3 | 1.5 d |
| MW4 | 0.5 d |
| MW5 | 0.5 d + 0.5 d for public repo setup (LICENSE, CONTRIBUTING, CI) |
| **Total** | **~5.5 days** |

With a 20 % buffer for `@owf/mdoc` browser surprises and OID4VP edge cases: **~6.5 days wall-time**.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| `@owf/mdoc` is node-only and porting to browser is non-trivial | High | MW0 verifies first thing. Fallback: re-implement the mdoc presentation subset using `cbor-web` (the IssuerSigned + DeviceSigned structures are not that large) |
| WebCrypto P-256 inconsistencies across browsers | Low | Target modern Chrome/Safari/Firefox only, document supported versions |
| OID4VP session transcript computation tricky in browser | Medium | Reuse the same SHA-256 + CBOR logic the Tessaliq backend uses, port to JS |
| Mock wallet confused with a production consumer product | Medium | Permanent "DEMO ONLY — NOT A PRODUCTION WALLET" banner. URL `wallet-demo.tessaliq.com` makes the intent explicit. README is unambiguous |
| Effort underestimated, especially on mdoc browser side | Medium | MW0 caps the risk. If > 1 d overrun, fallback to SD-JWT-VC for V1 (much simpler in JS) and defer mdoc to V2 |
| Maintenance burden if community engages | Low | "No SLA, best-effort, contributions welcome" policy in README |
| Security of device key in browser | Low (V1 mock) | Non-extractable WebCrypto key is the strongest browser primitive available. Acceptable for a test tool. Not for production |

## Open items for the community

If this repo is useful to others in the EUDI ecosystem, contributions welcome on:
- SD-JWT-VC support (V2)
- DC API integration with HPKE encrypted response (V2)
- Multi-credential management UI
- Trust list management for issuer cert validation
- Translation (currently English only)

## Source of truth

This document. Updated as phases complete.

Related: the parent Tessaliq issue tracks the strategic and product context: https://github.com/oliviermeunier/tessaliq/issues/224
