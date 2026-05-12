// Tessaliq Mock Wallet — DEMO ONLY, not a production wallet.
// See https://github.com/Tessaliq/mock-wallet for context.

import { useEffect, useState } from 'react'
import { getDevicePublicJwk, getDeviceKeyThumbprint } from './lib/device-key.ts'
import { listCredentials, type StoredCredential } from './lib/storage.ts'

export function App() {
  return (
    <div className="min-h-screen bg-white">
      <DemoBanner />
      <main className="mx-auto max-w-2xl px-6 py-12">
        <h1 className="text-3xl font-bold text-neutral-900">Tessaliq Mock Wallet</h1>
        <p className="mt-2 text-neutral-600">
          Browser-based EUDI test wallet for OID4VCI + OID4VP flows.
        </p>

        <DeviceKeyPanel />
        <CredentialsPanel />
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

function DeviceKeyPanel() {
  const [jwk, setJwk] = useState<JsonWebKey | null>(null)
  const [thumbprint, setThumbprint] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    void (async () => {
      try {
        const [k, t] = await Promise.all([
          getDevicePublicJwk(),
          getDeviceKeyThumbprint(),
        ])
        setJwk(k)
        setThumbprint(t)
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err))
      }
    })()
  }, [])

  return (
    <section className="mt-10 rounded-lg border border-neutral-200 p-6">
      <h2 className="text-lg font-semibold">Device key</h2>
      {error ? (
        <p className="mt-2 text-sm text-rose-600">Error: {error}</p>
      ) : !jwk ? (
        <p className="mt-2 text-sm text-neutral-500">Loading…</p>
      ) : (
        <div className="mt-3 space-y-3 text-sm">
          <p className="text-neutral-600">
            Generated once on first visit, persisted in IndexedDB.
            Private key is non-extractable — it can only sign, never be exported.
            Curve: <code className="rounded bg-neutral-100 px-1">P-256</code>{' '}
            (ES256).
          </p>
          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">
              Thumbprint (RFC 7638)
            </p>
            <code className="mt-1 block break-all rounded bg-neutral-100 px-2 py-1 font-mono text-xs">
              {thumbprint}
            </code>
          </div>
          <details>
            <summary className="cursor-pointer text-xs font-medium uppercase tracking-wide text-neutral-500">
              Public JWK
            </summary>
            <pre className="mt-2 overflow-x-auto rounded bg-neutral-100 px-2 py-2 text-xs">
              {JSON.stringify(jwk, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </section>
  )
}

function CredentialsPanel() {
  const [credentials, setCredentials] = useState<StoredCredential[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    void (async () => {
      setCredentials(await listCredentials())
      setLoading(false)
    })()
  }, [])

  return (
    <section className="mt-6 rounded-lg border border-neutral-200 p-6">
      <h2 className="text-lg font-semibold">
        Credentials{' '}
        <span className="text-sm font-normal text-neutral-500">
          ({loading ? '…' : credentials.length})
        </span>
      </h2>
      {loading ? (
        <p className="mt-2 text-sm text-neutral-500">Loading…</p>
      ) : credentials.length === 0 ? (
        <p className="mt-2 text-sm text-neutral-600">
          No credentials yet. MW2 will add credential reception over OID4VCI.
          MW3 will add presentation over OID4VP. Track progress on{' '}
          <a
            href="https://github.com/Tessaliq/mock-wallet/issues/1"
            className="underline"
          >
            issue #1
          </a>
          .
        </p>
      ) : (
        <ul className="mt-3 space-y-2 text-sm">
          {credentials.map((c) => (
            <li key={c.id} className="rounded border border-neutral-200 p-3">
              <p className="font-medium">{c.namespace}</p>
              <p className="text-xs text-neutral-500">
                Issued {c.issuedAt.toLocaleString()} · Expires{' '}
                {c.expiresAt?.toLocaleString() ?? 'never'}
              </p>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
