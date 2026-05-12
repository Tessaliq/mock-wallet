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

### MW0 — Technical scoping + bootstrap (0.5 day)

- [ ] Verify whether `@owf/mdoc` (v0.6.x, currently used on the Tessaliq API side) is browser-compatible
  - If yes: use directly
  - If no: choose between (a) fork + port a browser bundle, (b) re-implement the mdoc subset needed for credential presentation using `cbor-web` or `@cborg/json`
- [ ] Initialise the project with Vite + React + TypeScript template
- [ ] Add Tailwind, shadcn/ui, jose, `@yudiel/react-qr-scanner` deps
- [ ] Configure PWA manifest + minimal service worker
- [ ] Set up the new Vercel project, point `wallet-demo.tessaliq.com` to it (DNS via Infomaniak)
- [ ] Build local works, deploy hello-world to staging URL

**Output:** project bootstrapped, deploys, can be loaded from `wallet-demo.tessaliq.com`. Risk on `@owf/mdoc` resolved.

### MW1 — Device key + storage (0.5 day)

- [ ] `src/lib/device-key.ts` — `generateOrLoadDeviceKey()` returns a P-256 ECDSA CryptoKey pair, non-extractable, persisted across sessions (IndexedDB stores the CryptoKey handle directly via `structuredClone`)
- [ ] `src/lib/storage.ts` — IndexedDB schema for credentials:
  ```ts
  type StoredCredential = {
    id: string
    format: 'mdoc'
    namespace: string             // e.g. 'eu.europa.ec.av.1'
    rawBytes: Uint8Array          // the full IssuerSigned mdoc
    claims: Record<string, unknown>
    issuerCertSubject: string
    issuedAt: Date
    expiresAt: Date | null
    statusListUri: string | null
    statusListIndex: number | null
  }
  ```
- [ ] Test page: show the device key public JWK, list stored credentials (empty at first)

**Output:** device key persists across page reloads, IndexedDB schema ready.

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

### MW3 — OID4VP presentation flow (1.5 days)

- [ ] `src/lib/oid4vp-client.ts`:
  - parse `openid4vp://?...` link (or HTTPS link with the request)
  - fetch `request_uri` if signed JAR is used
  - validate the verifier signature against the x509 cert chain — for V1 mock, accept self-signed verifiers (with warning); for V2, validate against trusted roots
  - extract requested claims from the DCQL or Presentation Definition
  - build the OID4VP session transcript
  - construct an mdoc DeviceResponse:
    - select the requested claims (e.g. `age_over_18` only, not the full credential)
    - build DeviceAuth signed by the device key (HMAC-SHA-256 over the session transcript)
  - POST the `vp_token` to the verifier's `response_uri` via `direct_post`
- [ ] UI:
  - "Present credential" page when a QR is scanned with `openid4vp://...`
  - Consent screen: show verifier identity (from request), show claims being shared, big "Share" and "Cancel" buttons
  - Confirmation page after successful presentation

**Output:** can run `mock wallet → Tessaliq Verifier`. Verifier receives the mdoc DeviceResponse, validates it, generates a receipt JWT.

### MW4 — End-to-end test + revocation (0.5 day)

- [ ] Reproducible E2E test scenario:
  1. Trigger a verifier session on Tessaliq → wallet presents the user's PID France Identité (simulated) → Tessaliq issues a derived AV credential offer
  2. Wallet receives the offer (MW2), stores the AV credential
  3. Trigger a second verifier session on Tessaliq from a different "merchant" context → wallet presents the stored AV credential
  4. Verifier returns a receipt JWT → verifier confirms the same credential was reused
- [ ] Revocation test:
  1. Admin endpoint on Tessaliq revokes the credential (existing P5 endpoint)
  2. Wallet attempts to present → verifier checks the status list → rejects with "revoked"
  3. Wallet UI shows the revocation reason
- [ ] Optional: scripted test runner that automates this end-to-end (Playwright?)

**Output:** Variante C P6 fully validated. Documented scenario reproducible by anyone.

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
