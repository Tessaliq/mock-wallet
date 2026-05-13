# Architecture

The mock wallet is a small browser-only PWA. There is no backend of its own —
everything happens in the browser, against the Tessaliq issuer/verifier endpoints.

## Components

```
┌──────────────────────────────────────────────────────────────────┐
│  Browser (the entire wallet)                                     │
│                                                                  │
│  ┌──────────────────────────┐    ┌─────────────────────────────┐ │
│  │  src/App.tsx             │    │  Tessaliq backend           │ │
│  │  React UI                │◀──▶│  api-staging.tessaliq.com   │ │
│  │  - Add credential        │    │  - Issuer  /v1/credential/* │ │
│  │  - List credentials      │    │  - Verifier /v1/openid4vp/* │ │
│  │  - Present credential    │    └─────────────────────────────┘ │
│  │  - Consent screen        │                                    │
│  └─────────┬────────────────┘                                    │
│            │                                                     │
│  ┌─────────▼────────────────┐                                    │
│  │  src/lib                 │                                    │
│  │  - oid4vci.ts            │  receive flow                      │
│  │  - oid4vp.ts             │  present flow                      │
│  │  - device-key.ts         │  WebCrypto P-256 device key        │
│  │  - device-cert.ts        │  self-signed X.509 for device key  │
│  │  - mdoc-context.ts       │  @owf/mdoc WebCrypto adapter       │
│  │  - proof-jwt.ts          │  OID4VCI JWT signing               │
│  │  - storage.ts            │  IndexedDB schema                  │
│  └─────────┬────────────────┘                                    │
│            │                                                     │
│  ┌─────────▼────────────────┐                                    │
│  │  Browser primitives      │                                    │
│  │  - WebCrypto (signing)   │                                    │
│  │  - IndexedDB (storage)   │                                    │
│  │  - fetch                 │                                    │
│  └──────────────────────────┘                                    │
└──────────────────────────────────────────────────────────────────┘
```

Nothing is server-side here. The wallet is a static PWA hosted on Vercel at
`wallet-demo.tessaliq.com`. All HTTP is between the browser and the Tessaliq
API.

## Module responsibilities

| File | What it does | Talks to |
|------|--------------|----------|
| [`src/lib/device-key.ts`](../src/lib/device-key.ts) | Generates the P-256 device key on first use, stores it in IndexedDB with `extractable: false`. Exposes `getOrCreateDeviceKey()`, public JWK, RFC 7638 thumbprint. | `storage.ts`, WebCrypto |
| [`src/lib/device-cert.ts`](../src/lib/device-cert.ts) | Generates a self-signed X.509 over the device public key. The verifier ignores the chain (mock wallet) but `@owf/mdoc` requires *some* cert to put in the `x5chain` unprotected header. | `device-key.ts`, `@peculiar/x509` |
| [`src/lib/storage.ts`](../src/lib/storage.ts) | IndexedDB schema. Two stores: `keys` (single device key slot) and `credentials` (mdoc credentials by uuid). | `idb` |
| [`src/lib/mdoc-context.ts`](../src/lib/mdoc-context.ts) | Implements `@owf/mdoc`'s `MdocContext` interface backed by WebCrypto. Closes over the device private key so signing can happen without exposing it. See [CRYPTO.md](./CRYPTO.md). | WebCrypto, `@owf/mdoc` types |
| [`src/lib/proof-jwt.ts`](../src/lib/proof-jwt.ts) | Builds `openid4vci-proof+jwt` (for `/v1/credential/issue`) and `jwt-bearer` client assertions (for `/v1/credential/token`). | `jose`, `device-key.ts` |
| [`src/lib/oid4vci.ts`](../src/lib/oid4vci.ts) | OID4VCI 1.0 Final pre-authorized code flow. Parses the offer, fetches issuer metadata, exchanges the pre-auth code, requests the credential. Persists to IndexedDB. | Tessaliq issuer, `proof-jwt.ts`, `storage.ts` |
| [`src/lib/oid4vp.ts`](../src/lib/oid4vp.ts) | OID4VP 1.0 Final `direct_post` flow. Parses the JAR, matches against stored credentials, builds the filtered mdoc `DeviceResponse`, POSTs to `response_uri`. | Tessaliq verifier, `mdoc-context.ts`, `@owf/mdoc` |

## External dependencies

| Package | Role | Why this one |
|---------|------|--------------|
| `@owf/mdoc@0.6.0` | mdoc CBOR encoding/decoding, `SessionTranscript`, `DeviceSignedBuilder`, `Verifier` types | Same version Tessaliq's backend uses — eliminates one whole class of interop bugs. Browser-compatible (verified during MW0 scoping). |
| `@peculiar/x509` | Self-signed device certificate for the `x5chain` header | Browser-friendly, MIT, the de-facto X.509 toolkit in the EUDI ecosystem |
| `jose@6` | OID4VCI proof JWT + client assertion JWT signing | Already the JWT library on the Tessaliq backend; consistent signature/serialisation |
| `idb` | Promise wrapper over IndexedDB | Avoids re-implementing the IDBRequest dance in every storage call |
| `vite-plugin-pwa` | Manifest + service worker | PWA install + offline shell |
| `react@19`, `tailwindcss@4` | UI | Mature, fast, standard frontend stack |

## Data layout

### IndexedDB (`tessaliq-mock-wallet` database, version 1)

- **`keys` store** — one record, key `"device-key"`:
  ```ts
  { id: 'device-key', privateKey: CryptoKey, publicKey: CryptoKey,
    createdAt: Date, certDer?: Uint8Array }
  ```
  The two `CryptoKey` values are persisted as native IndexedDB clones —
  `privateKey` keeps its `extractable: false` flag across reloads.

- **`credentials` store** — one record per received credential, key is a uuid v4:
  ```ts
  { id: string, format: 'mdoc', namespace: string,
    rawBytes: Uint8Array,                    // CBOR IssuerSigned
    claims: Record<string, unknown>,         // decoded cache
    issuerCertSubject: string,
    issuedAt: Date, expiresAt: Date | null,
    statusListUri: string | null,
    statusListIndex: number | null }
  ```
  `rawBytes` is the source of truth. `claims` is a convenience cache for
  display; it is re-derivable from `rawBytes`.

### What is *not* persisted

- No PIN / passcode (the wallet has no lock screen in V1).
- No verifier session history (no audit log on the wallet side).
- No issuer registry (we accept any issuer that the JAR / offer points at).
- No backup / restore. Wiping browser data wipes the wallet.

## Runtime topology

The PWA is shipped pre-built (Vite production bundle) from a Vercel project.
The service worker (generated by `vite-plugin-pwa`) caches the static assets
for offline shell load, but all API calls hit the network — there is no
offline mode for receive/present.

```
[user device]
  │  HTTPS                                  HTTPS
  ├──────────────▶ Vercel (static PWA) ──▶ [browser executes]
  │
  └──── browser ────────────────────────▶ api-staging.tessaliq.com
                                          (issuer + verifier)
```

## Where the threats live

Read [CRYPTO.md](./CRYPTO.md) for the security model and what changes in a
production wallet. The short version:

- Device private key is non-extractable WebCrypto. Application code cannot
  read it; only `crypto.subtle.sign()` can use it.
- No hardware backing — a malicious browser extension with WebCrypto access
  can sign on behalf of the user. Production wallets need OS keystore /
  Secure Enclave / StrongBox.
- No JAR signature validation (we accept any verifier identity). Production
  wallets MUST validate the x509 chain referenced by the JAR header.
- No revocation enforcement on stored credentials (V1.1 work — see
  [DEBUGGING.md](./DEBUGGING.md) "Known gaps").

## Where to start reading the code

If you want to understand the wallet end-to-end, read the modules in this
order:

1. [`storage.ts`](../src/lib/storage.ts) — data model
2. [`device-key.ts`](../src/lib/device-key.ts) — key lifecycle
3. [`oid4vci.ts`](../src/lib/oid4vci.ts) — receive flow (matches FLOWS.md §1)
4. [`mdoc-context.ts`](../src/lib/mdoc-context.ts) — signing adapter
5. [`oid4vp.ts`](../src/lib/oid4vp.ts) — present flow (matches FLOWS.md §2)
6. [`src/App.tsx`](../src/App.tsx) — UI wiring on top of all of the above
