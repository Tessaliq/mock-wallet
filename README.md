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
- Reusable credential presentation across multiple verifiers
- Token status list revocation check (IETF draft-14)

**Not supported (V1):**
- SD-JWT-VC credentials
- DC API browser integration + HPKE encrypted response
- iOS native app (PWA only)
- Production-grade hardening, secure enclave, ENISA certification
- Cross-device sync, backup/restore

## Running it

```bash
pnpm install
pnpm dev
```

Then open `http://localhost:5173`.

## Architecture

PWA built with Vite + React + TypeScript. Hosted at `https://wallet-demo.tessaliq.com` (or run locally for development).

See [`PLAN.md`](./PLAN.md) for the implementation plan and decisions log.

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
