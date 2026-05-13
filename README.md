# Tessaliq Mock Wallet

EUDI test wallet for OID4VCI + OID4VP flows, written by [Tessaliq](https://tessaliq.com) to validate verifier and issuer behaviour end-to-end without depending on national wallet sandboxes.

> ⚠️ **NOT a production wallet.** This is a development / interop testing tool. **Do not store real PID, real identity credentials, or any sensitive personal data here.**

## Why this exists

The EU Age Verification blueprint (`eu.europa.ec.av.1`) defines a standard for cross-border, privacy-preserving age proofs. National wallets (France Identité, IT-Wallet, Lissi…) are still maturing, and the EU AV reference Android app currently crashes on credential enrolment as of v2026.04-2.

Without a working wallet, verifiers and issuers cannot validate their OpenID4VCI + OpenID4VP integration end-to-end. This repo provides a minimal browser-based mock wallet that:

- receives credentials over OID4VCI (pre-authorized code flow)
- stores them locally in IndexedDB
- presents them over OID4VP (direct_post)
- uses a real WebCrypto device key to sign `proof.jwt` and the mdoc DeviceAuth structure

It is not a replacement for a national EUDI Wallet. It is a development tool for verifier/issuer authors who need a wallet they can clone, modify, and run themselves.

## Scope (V1)

**Supported:**
- mdoc credentials in the `eu.europa.ec.av.1` namespace (EU AV blueprint)
- OpenID4VCI 1.0 Final — pre-authorized code flow
- OpenID4VP 1.0 Final — `direct_post` response mode
- WebCrypto device key (P-256 ECDSA, non-extractable, persistent across sessions)
- IndexedDB credential storage
- Reusable AV credential — same credential presented to multiple verifier sessions (the strategic story this repo exists for, see [Tessaliq #224](https://github.com/oliviermeunier/tessaliq/issues/224))

**Not supported (V1):**
- SD-JWT-VC credentials
- DC API browser integration + HPKE encrypted response
- iOS native app (PWA only)
- Production-grade hardening, secure enclave, ENISA certification
- Cross-device sync, backup/restore
- Revocation enforcement on stored credentials — admin endpoint works, but the mdoc MSO does not yet carry a status pointer (V1.1 follow-up, [Tessaliq #224](https://github.com/oliviermeunier/tessaliq/issues/224) P5.1)

## Running it

```bash
pnpm install
pnpm dev
```

Then open `http://localhost:5173`.

## Documentation

| Doc | When to read |
|-----|--------------|
| [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) | Component map, module responsibilities, data layout |
| [`docs/FLOWS.md`](./docs/FLOWS.md) | OID4VCI + OID4VP sequence diagrams, byte-level wire format, `SessionTranscript` mechanics |
| [`docs/CRYPTO.md`](./docs/CRYPTO.md) | Device key handling, signing pipeline, security gaps vs production wallets |
| [`docs/DEBUGGING.md`](./docs/DEBUGGING.md) | Smoke scripts, common verifier 400s, how to read mdoc CBOR + server logs |
| [`docs/E2E.md`](./docs/E2E.md) | Manual end-to-end scenario against staging |
| [`PLAN.md`](./PLAN.md) | Implementation plan, phase status, decisions log |

## Architecture (in one line)

PWA built with Vite + React + TypeScript. No backend of its own — everything happens in the browser against the Tessaliq issuer + verifier endpoints. See [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) for the full picture.

## Related projects

- **Tessaliq verifier and issuer** (the back-end this wallet talks to): https://tessaliq.com
- **Tessaliq open core**: https://github.com/Tessaliq/tessaliq-open (circuits, SDK, SD-JWT lib, shared types)
- **EU AV blueprint**: https://ageverification.dev/
- **EU reference wallet (Android, has known enrolment crash on v2026.04-2)**: https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui

## License

[MIT](./LICENSE).

This repository follows the same open-core philosophy as [`tessaliq-open`](https://github.com/Tessaliq/tessaliq-open). It is provided as-is, without warranty. Contributions welcome via issues and PRs; SLA is best-effort, this is not a vendor product.

## Contact

`contact@tessaliq.com`
