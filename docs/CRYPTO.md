# Crypto & security model

What's protected, what isn't, and where the wallet would differ from a
production EUDI wallet.

## Device key

The wallet has exactly one device key pair: P-256 ECDSA (ES256), generated
on first use, persisted in IndexedDB, and re-loaded on every page load.

### Why P-256 / ES256

- Default curve for the `proof.jwt` of OID4VCI 1.0 Final.
- Default `alg` for mdoc `DeviceAuth` on the EU AV blueprint.
- First-class WebCrypto support across Chrome, Safari, Firefox.
- Same primitive the Tessaliq issuer uses for its DSC (Document Signer Certificate).

### Non-extractable private key

The private key is generated `extractable: true` (WebCrypto returns the same
flag on both halves of a pair), then **immediately re-imported as
non-extractable**:

```ts
// device-key.ts
const pair = await crypto.subtle.generateKey(ALGO, true, ['sign', 'verify'])
const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey)
const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, ALGO, false, ['sign'])
```

The result:

- Application code can call `crypto.subtle.sign(...)` against the key.
- Application code **cannot** call `crypto.subtle.exportKey(...)` on it
  (throws `InvalidAccessError`).
- The IndexedDB clone preserves `extractable: false` across reloads.

This is the strongest primitive a pure-JS browser app has. It is not
hardware-backed.

### Why the public key is extractable

The public key is exported as JWK in three places:

1. **OID4VCI `client_assertion` header** — `jwk` field, so the issuer can
   verify the assertion signature without prior client registration.
2. **OID4VCI `proof.jwt` header** — `jwk` field, so the issuer can take the
   public key and stamp it into the new credential's `MSO.deviceKeyInfo.deviceKey`.
3. **Self-signed device X.509 certificate** — written into the mdoc
   `x5chain` unprotected header during presentation. The verifier ignores
   the chain (trust is via `MSO.deviceKeyInfo.deviceKey`), but `@owf/mdoc`
   requires the field to be present.

The RFC 7638 thumbprint of the public JWK is exposed in the UI as the
device identifier — a stable 22-char base64url string that uniquely names
this wallet instance without exposing the JWK itself.

## What gets signed, and how

### OID4VCI flow

Two JWTs are signed by the device key during credential reception:

| JWT | Library | Adapter |
|-----|---------|---------|
| `client_assertion` (token endpoint) | `jose` SignJWT | `device-key.ts` private key → `jose` |
| `proof.jwt` (credential endpoint) | `jose` SignJWT | same |

`jose` calls into WebCrypto under the hood. Signatures are raw `r||s`
(IEEE P-1363), 64 bytes — same encoding ECDSA-over-WebCrypto produces
natively. No DER encoding is involved here.

### OID4VP flow

The device signs one COSE_Sign1 over the `DeviceAuthentication` CBOR
structure. The signing happens via `@owf/mdoc`'s `DeviceSignedBuilder.sign()`
which delegates to the wallet's `MdocContext.cose.sign1.sign()` callback.

Our adapter (`src/lib/mdoc-context.ts`) implements that callback like this:

```ts
sign: async ({ toBeSigned, algorithm }) => {
  const hash = algorithmToHash(String(algorithm ?? 'ES256'))
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash },
    devicePrivateKey,                   // captured in closure
    toArrayBuffer(toBeSigned),
  )
  return new Uint8Array(sig)
}
```

Two things to notice:

1. The `key` argument from `@owf/mdoc` is **deliberately ignored**.
   The adapter closes over the device private key and uses that. This is
   how we keep the private key non-extractable: we never have to hand it
   to anyone, we just expose a function that signs.

2. `crypto.subtle.sign` for ECDSA also returns raw `r||s` form, which is
   what COSE_Sign1 expects per RFC 8152 §8.1. No re-encoding needed.

## What is *not* protected

Be honest about what this V1 mock cannot do.

### No hardware backing

A non-extractable WebCrypto key is software, not hardware. A malicious
browser extension with permissions, or a compromised browser process, can
call `crypto.subtle.sign()` on behalf of the user without consent.

A production wallet binds the key to an OS keystore (Android Keystore /
StrongBox, iOS Secure Enclave, TPM / SE / SIM on hardware tokens). Those
provide:

- Anti-extraction even in the presence of OS root compromise.
- User-presence checks (biometric / PIN gate before each signature).
- Attestation: the issuer can verify at issuance time that the key really
  is hardware-backed.

None of this exists here. The wallet is a development / interop tool.

### No JAR signature validation

When the wallet fetches the verifier's Authorization Request JAR via
`request_uri`, we decode the JWT with `jose.decodeJwt` and **do not
verify the signature**. A real wallet MUST:

- Parse the JAR JWS header.
- Resolve the verifier identity (x5c chain, federation, trust list).
- Verify the signature against the resolved key.
- Reject the request if the cert chain does not terminate at a trusted
  root.

We skip this because the staging verifier identity isn't meaningfully
distinguishable from "anyone with a TLS cert" in a mock setting. The code
surfaces a `signed` boolean on `OpenId4VpRequest` so the UI could warn
about unsigned requests if needed.

### No PIN / passcode / biometric gate

The wallet has no lock screen. Anyone with access to the browser session
can authorise a presentation. A production wallet:

- Gates each presentation behind a user-presence check.
- Locks after inactivity, requires re-auth to unlock.
- Wipes the credential store after N failed attempts.

### No revocation enforcement (V1.1 gap)

The wallet stores the `statusListUri` and `statusListIndex` fields when
the credential carries them, but currently the Tessaliq issuer for
**Reusable AV** credentials (mdoc) does **not** stamp a status list
pointer into the MSO. The verifier therefore has no claim to look up
and accepts revoked credentials.

Tracked as P5.1 in [oliviermeunier/tessaliq#224](https://github.com/oliviermeunier/tessaliq/issues/224).
The admin endpoint `POST /v1/credential/status` updates the bitstring
and the signed status list JWT — the missing piece is wiring the pointer
into the MSO extension and the verifier-side check.

### No PII protection at rest

IndexedDB is plaintext at rest from a forensic-tools perspective. The
mdoc credential bytes are stored as `Uint8Array` in the credentials
store. Anyone with disk access (or, in dev tools, anyone who opens
Application → IndexedDB) can read them.

This is acceptable for the Reusable AV scope — the credential carries
boolean age claims, no birth date, no name, no document number. It would
**not** be acceptable for a credential containing personally identifying
attributes.

### No anti-cloning

If the user backs up their browser profile (or syncs across devices via
the browser vendor), the wallet's IndexedDB — including the
"non-extractable" CryptoKey — travels along. Browser vendors may or may
not honour the `extractable` flag across profile sync — Chrome currently
does (the key is unusable on a different machine), Safari behaviour is
undocumented.

## Threat model summary

| Adversary | Mitigated? |
|-----------|------------|
| Network MITM | TLS — fine |
| Replay attack on a single verifier session | OID4VP nonce binding + SessionTranscript — fine |
| Replay across verifier sessions (reusing a vp_token) | nonce changes per session — fine |
| Verifier impersonation | **not mitigated** — wallet does not validate JAR signature |
| Browser extension stealing the device key | **not mitigated** — WebCrypto is in-process |
| Stolen device, browser unlocked | **not mitigated** — no lock screen |
| Stolen device, browser locked | Browser's profile encryption (vendor-specific) |
| Credential issued long ago but recently revoked | **not mitigated** — V1.1 gap |

The Variante C / Reusable AV strategic story (`docs/02-architecture/issuance-flow.md`
in Tessaliq) treats this mock wallet as a development tool, not a vehicle
for production claims. Anyone deploying a wallet against real users in
production must address each of these gaps.

## Dependencies you should be aware of

| Package | Cryptographic role | Trust |
|---------|--------------------|-------|
| Browser WebCrypto (`crypto.subtle`) | All ECDSA signing, all hashing | Browser vendor (Chromium, WebKit, Gecko) — standard, audited |
| `jose@6` | JWT serialisation, calling WebCrypto under the hood | Mature library, used widely incl. by Tessaliq's backend |
| `@owf/mdoc@0.6.0` | CBOR encode/decode, `SessionTranscript`, `DeviceSignedBuilder`, signature delegation through `MdocContext` | Same version as Tessaliq backend — eliminates version drift, but adds a dependency on a relatively young ecosystem package |
| `@peculiar/x509` | Self-signed device certificate generation | De-facto X.509 toolkit in EUDI ecosystem |
| `@noble/curves`, `@noble/hashes` | Used **indirectly** by `@owf/mdoc` (it does not depend on WebCrypto for everything) | Audit history is short but the code is highly reviewed and used by Lightning, Bitcoin, etc. |

The mock wallet does no cryptography of its own. Every signature and hash
goes through one of the libraries above.
