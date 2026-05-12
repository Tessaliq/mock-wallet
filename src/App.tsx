// Tessaliq Mock Wallet — DEMO ONLY, not a production wallet.
// See https://github.com/Tessaliq/mock-wallet for context.

import { useCallback, useEffect, useState } from 'react'
import { getDevicePublicJwk, getDeviceKeyThumbprint } from './lib/device-key.ts'
import { listCredentials, type StoredCredential } from './lib/storage.ts'
import { acceptCredentialOffer } from './lib/oid4vci.ts'

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
  const [showAdd, setShowAdd] = useState(false)

  const refresh = useCallback(async () => {
    setCredentials(await listCredentials())
    setLoading(false)
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  return (
    <section className="mt-6 rounded-lg border border-neutral-200 p-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Credentials{' '}
          <span className="text-sm font-normal text-neutral-500">
            ({loading ? '…' : credentials.length})
          </span>
        </h2>
        <button
          type="button"
          onClick={() => setShowAdd(true)}
          className="rounded-md bg-neutral-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-neutral-700"
        >
          Add credential
        </button>
      </div>

      {loading ? (
        <p className="mt-3 text-sm text-neutral-500">Loading…</p>
      ) : credentials.length === 0 ? (
        <p className="mt-3 text-sm text-neutral-600">
          No credentials yet. Click <b>Add credential</b> and paste an{' '}
          <code className="rounded bg-neutral-100 px-1">
            openid-credential-offer://
          </code>{' '}
          URL from the Tessaliq Issuer (or any OID4VCI 1.0 Final issuer).
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
              <details className="mt-2">
                <summary className="cursor-pointer text-xs text-neutral-500">
                  Claims
                </summary>
                <pre className="mt-1 overflow-x-auto rounded bg-neutral-100 px-2 py-1 text-xs">
                  {JSON.stringify(c.claims, null, 2)}
                </pre>
              </details>
            </li>
          ))}
        </ul>
      )}

      {showAdd && (
        <AddCredentialModal
          onClose={() => setShowAdd(false)}
          onAdded={() => {
            setShowAdd(false)
            void refresh()
          }}
        />
      )}
    </section>
  )
}

function AddCredentialModal({
  onClose,
  onAdded,
}: {
  onClose: () => void
  onAdded: () => void
}) {
  const [url, setUrl] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit() {
    setSubmitting(true)
    setError(null)
    try {
      await acceptCredentialOffer(url)
      onAdded()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-lg rounded-lg bg-white p-6 shadow-xl">
        <h3 className="text-lg font-semibold">Add credential</h3>
        <p className="mt-1 text-sm text-neutral-600">
          Paste an{' '}
          <code className="rounded bg-neutral-100 px-1">
            openid-credential-offer://
          </code>{' '}
          URL.
        </p>
        <textarea
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="openid-credential-offer://?credential_offer=..."
          rows={4}
          className="mt-3 w-full rounded border border-neutral-300 px-3 py-2 font-mono text-xs"
        />
        {error && (
          <p className="mt-2 text-sm text-rose-600 break-all">{error}</p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="rounded-md border border-neutral-300 px-3 py-1.5 text-sm hover:bg-neutral-100 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={!url.trim() || submitting}
            className="rounded-md bg-neutral-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-neutral-700 disabled:opacity-50"
          >
            {submitting ? 'Receiving…' : 'Receive credential'}
          </button>
        </div>
      </div>
    </div>
  )
}
