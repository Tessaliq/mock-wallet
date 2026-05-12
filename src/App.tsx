// Tessaliq Mock Wallet — DEMO ONLY, not a production wallet.
// See https://github.com/Tessaliq/mock-wallet for context.

export function App() {
  return (
    <div className="min-h-screen bg-white">
      <DemoBanner />
      <main className="mx-auto max-w-2xl px-6 py-12">
        <h1 className="text-3xl font-bold text-neutral-900">Tessaliq Mock Wallet</h1>
        <p className="mt-2 text-neutral-600">
          Browser-based EUDI test wallet for OID4VCI + OID4VP flows.
        </p>

        <section className="mt-10 rounded-lg border border-neutral-200 p-6">
          <h2 className="text-lg font-semibold">No credentials yet</h2>
          <p className="mt-2 text-sm text-neutral-600">
            MW1 will add the device key and credential storage. MW2 will add
            credential reception over OID4VCI. MW3 will add presentation over
            OID4VP. Track progress on{' '}
            <a
              href="https://github.com/Tessaliq/mock-wallet/issues/1"
              className="underline"
            >
              issue #1
            </a>
            .
          </p>
        </section>
      </main>
    </div>
  )
}

function DemoBanner() {
  return (
    <div className="border-b border-amber-300 bg-amber-50 px-4 py-2 text-center text-xs font-medium text-amber-900">
      ⚠️ DEMO ONLY — this is a test wallet, not a production identity wallet.
      Do not store real PID or sensitive credentials here.
    </div>
  )
}
