# Contributing

Thanks for considering a contribution. This repo is a small open-source
side of [Tessaliq](https://tessaliq.com) and is maintained on a
best-effort basis — there is no SLA, no roadmap commitment, and no
guarantee that a PR will be merged. That said, the project is
deliberately small and focused, and most contributions are easy to land
if they fit the scope.

## Scope

The wallet is an **interop testing tool**, not a consumer product.

Contributions are welcome on:

- Conformance to OID4VCI 1.0 Final / OID4VP 1.0 Final and HAIP profiles
- Better wallet UI for inspecting credentials (claim viewer, validity
  display, status check UI when V1.1 lands)
- Browser portability fixes (Safari, Firefox, mobile WebKit)
- Documentation improvements ([`docs/`](./docs))
- New protocol coverage (SD-JWT-VC, DC API / HPKE — both currently
  out-of-scope for V1; see [PLAN.md](./PLAN.md))

Contributions that are **out-of-scope**:

- Re-skinning as a vendor-branded production wallet (this repo will
  always carry "DEMO ONLY" disclaimers)
- Hardware-backed key storage emulation (use a real wallet for that)
- Crypto primitives reimplementation — keep relying on WebCrypto +
  `@owf/mdoc` + `jose`
- Anything that requires a backend that this repo would host

If you are unsure whether a contribution fits, open an issue first.

## How to file an issue

- **Bugs**: include the smoke output (`scripts/smoke-e2e.mjs` and/or
  `scripts/smoke-mw4-acceptance.mjs`), the browser version, and the
  relevant logs (`flyctl logs --app tessaliq-api-staging` if the issue
  is on the Tessaliq backend side — but in that case open the issue at
  [oliviermeunier/tessaliq](https://github.com/oliviermeunier/tessaliq)
  instead). See [`docs/DEBUGGING.md`](./docs/DEBUGGING.md).
- **Feature requests**: open an issue describing the use case, not just
  the feature. We will not implement things speculatively.
- **Security**: do not open a public issue. Email `contact@tessaliq.com`
  with the details and we'll coordinate disclosure.

## How to send a PR

1. Open an issue first if the change is non-trivial — saves both of us
   wasted work if the scope doesn't match.
2. Fork, branch off `main`. Keep branches short-lived.
3. Run the smoke tests against staging before pushing:
   ```bash
   node scripts/smoke-e2e.mjs
   node scripts/smoke-mw4-acceptance.mjs
   ```
4. Make sure the build is green: `pnpm install && pnpm build`.
5. Open the PR with a clear "why" in the description, not just "what".
6. CI (typecheck + build) must pass.

We will review when time allows. If we can't merge a PR — usually
because it's out of scope or it'd conflict with the broader Tessaliq
roadmap — we'll explain why and close it.

## Code style

- TypeScript strict mode is on (`tsconfig.app.json`).
- No new comments unless they explain *why* (not *what*) — the code
  should be self-explanatory through naming.
- No external dependencies added without a clear reason. The current
  dependency tree is small on purpose.
- Indentation: 2 spaces. No tabs. Trailing commas in multi-line.
- Format with the existing in-tree conventions; we don't run Prettier
  for now.

## License

By contributing, you agree that your contributions will be licensed
under the [MIT license](./LICENSE).

## Conduct

Be kind. We don't have a formal CoC document; the
[Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/)
applies in spirit. Conflicts can be resolved by emailing
`contact@tessaliq.com`.
