// Tessaliq Mock Wallet — DEMO ONLY, not a production wallet.
// See https://github.com/Tessaliq/mock-wallet for context.

import { useCallback, useEffect, useState } from 'react'
import { getDevicePublicJwk, getDeviceKeyThumbprint } from './lib/device-key.ts'
import { listCredentials, type StoredCredential } from './lib/storage.ts'
import {
  acceptCredentialOffer,
  parseCredentialOffer,
  type CredentialOffer,
} from './lib/oid4vci.ts'
import {
  buildAndPostPresentation,
  matchCredentialsAgainstQuery,
  parseAuthorizationRequest,
  type CredentialMatch,
  type OpenId4VpRequest,
  type PresentationResult,
} from './lib/oid4vp.ts'

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
        <PresentPanel />
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

function PresentPanel() {
  const [url, setUrl] = useState('')
  const [parsing, setParsing] = useState(false)
  const [request, setRequest] = useState<OpenId4VpRequest | null>(null)
  const [matches, setMatches] = useState<CredentialMatch[]>([])
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<PresentationResult | null>(null)

  async function parse() {
    setParsing(true)
    setError(null)
    setRequest(null)
    setMatches([])
    setResult(null)
    try {
      const parsed = await parseAuthorizationRequest(url)
      const stored = await listCredentials()
      const m = matchCredentialsAgainstQuery(parsed.dcqlQuery, stored)
      setRequest(parsed)
      setMatches(m)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setParsing(false)
    }
  }

  async function share() {
    if (!request) return
    const match = matches[0]
    const credential = match?.candidates[0]
    if (!credential) {
      setError('No matching credential to share')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const r = await buildAndPostPresentation(
        request,
        credential,
        match.requestedClaims,
        match.dcqlId,
      )
      setResult(r)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSubmitting(false)
    }
  }

  function reset() {
    setUrl('')
    setRequest(null)
    setMatches([])
    setResult(null)
    setError(null)
  }

  return (
    <section className="mt-6 rounded-lg border border-neutral-200 p-6">
      <h2 className="text-lg font-semibold">Present credential</h2>
      <p className="mt-1 text-sm text-neutral-600">
        Paste an{' '}
        <code className="rounded bg-neutral-100 px-1">openid4vp://</code> URL
        from a verifier (e.g. the Tessaliq demo) and approve the consent.
      </p>

      {!request && !result && (
        <div className="mt-3 space-y-3">
          <textarea
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="openid4vp://?request_uri=..."
            rows={3}
            className="w-full rounded border border-neutral-300 px-3 py-2 font-mono text-xs"
          />
          <button
            type="button"
            onClick={() => void parse()}
            disabled={!url.trim() || parsing}
            className="rounded-md bg-neutral-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-neutral-700 disabled:opacity-50"
          >
            {parsing ? 'Parsing…' : 'Continue'}
          </button>
        </div>
      )}

      {request && !result && (
        <ConsentScreen
          request={request}
          matches={matches}
          submitting={submitting}
          onShare={() => void share()}
          onCancel={reset}
        />
      )}

      {result && (
        <ConfirmationScreen result={result} onReset={reset} />
      )}

      {error && (
        <p className="mt-3 text-sm text-rose-600 break-all">Error: {error}</p>
      )}
    </section>
  )
}

function ConsentScreen({
  request,
  matches,
  submitting,
  onShare,
  onCancel,
}: {
  request: OpenId4VpRequest
  matches: CredentialMatch[]
  submitting: boolean
  onShare: () => void
  onCancel: () => void
}) {
  const totalCandidates = matches.reduce((n, m) => n + m.candidates.length, 0)
  const canShare = totalCandidates > 0
  return (
    <div className="mt-3 space-y-4 text-sm">
      <div className="rounded border border-neutral-200 bg-neutral-50 p-3">
        <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">
          Verifier
        </p>
        <p className="mt-1 font-mono text-xs break-all">{request.clientId}</p>
        <p className="mt-2 text-xs text-neutral-500">
          Response will be POSTed to{' '}
          <code className="break-all">{request.responseUri}</code>
        </p>
        {!request.signed && (
          <p className="mt-2 text-xs text-amber-700">
            ⚠️ The verifier request was not signed (no JAR). In a production
            wallet this would be rejected unless the verifier is on a trust
            list.
          </p>
        )}
      </div>

      {matches.map((m) => (
        <div key={m.dcqlId} className="rounded border border-neutral-200 p-3">
          <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">
            DCQL slot{' '}
            <code className="rounded bg-neutral-100 px-1">{m.dcqlId}</code>
          </p>
          <p className="mt-1 text-xs text-neutral-600">
            {m.candidates.length === 0
              ? 'No matching credential in this wallet.'
              : `${m.candidates.length} matching credential${m.candidates.length > 1 ? 's' : ''}.`}
          </p>
          {m.requestedClaims.length > 0 && (
            <>
              <p className="mt-2 text-xs font-medium text-neutral-700">
                Claims being shared:
              </p>
              <ul className="mt-1 list-disc pl-5 text-xs text-neutral-700">
                {m.requestedClaims.map((c) => (
                  <li key={c}>
                    <code className="rounded bg-neutral-100 px-1">{c}</code>
                  </li>
                ))}
              </ul>
            </>
          )}
          {m.requestedClaims.length === 0 && m.candidates.length > 0 && (
            <p className="mt-2 text-xs text-amber-700">
              Verifier did not specify claims — the full credential would be
              shared.
            </p>
          )}
        </div>
      ))}

      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          disabled={submitting}
          className="rounded-md border border-neutral-300 px-3 py-1.5 text-sm hover:bg-neutral-100 disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onShare}
          disabled={!canShare || submitting}
          className="rounded-md bg-neutral-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-neutral-700 disabled:opacity-50"
        >
          {submitting ? 'Sharing…' : 'Share'}
        </button>
      </div>
    </div>
  )
}

function ConfirmationScreen({
  result,
  onReset,
}: {
  result: PresentationResult
  onReset: () => void
}) {
  return (
    <div className="mt-3 space-y-3 text-sm">
      <div className="rounded border border-emerald-200 bg-emerald-50 p-3 text-emerald-900">
        <p className="text-sm font-semibold">Presentation accepted</p>
        <p className="mt-1 text-xs">
          Verifier returned HTTP {result.status}. The vp_token was POSTed
          successfully.
        </p>
        {result.redirectUri && (
          <p className="mt-2 text-xs">
            Redirect URI:{' '}
            <a
              href={result.redirectUri}
              className="underline"
              target="_blank"
              rel="noreferrer"
            >
              {result.redirectUri}
            </a>
          </p>
        )}
      </div>
      <details>
        <summary className="cursor-pointer text-xs font-medium uppercase tracking-wide text-neutral-500">
          Raw verifier response
        </summary>
        <pre className="mt-2 overflow-x-auto rounded bg-neutral-100 px-2 py-2 text-xs">
          {result.body || '(empty)'}
        </pre>
      </details>
      <div className="flex justify-end">
        <button
          type="button"
          onClick={onReset}
          className="rounded-md border border-neutral-300 px-3 py-1.5 text-sm hover:bg-neutral-100"
        >
          Done
        </button>
      </div>
    </div>
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
  const [offer, setOffer] = useState<CredentialOffer | null>(null)
  const [txCode, setTxCode] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const txCodeMeta =
    offer?.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']
      ?.tx_code

  async function parse() {
    setSubmitting(true)
    setError(null)
    try {
      const parsed = await parseCredentialOffer(url)
      setOffer(parsed)
      // If no tx_code is required, run the full flow immediately.
      const needsTx = !!parsed.grants[
        'urn:ietf:params:oauth:grant-type:pre-authorized_code'
      ]?.tx_code
      if (!needsTx) {
        await acceptCredentialOffer(url, {})
        onAdded()
        return
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSubmitting(false)
    }
  }

  async function submitWithPin() {
    setSubmitting(true)
    setError(null)
    try {
      await acceptCredentialOffer(url, { txCode })
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

        {!offer && (
          <>
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
          </>
        )}

        {offer && txCodeMeta && (
          <div className="mt-3 space-y-3">
            <div className="rounded border border-neutral-200 bg-neutral-50 p-3 text-sm">
              <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">
                Issuer
              </p>
              <p className="mt-1 font-mono text-xs break-all">
                {offer.credential_issuer}
              </p>
              <p className="mt-2 text-xs text-neutral-600">
                {txCodeMeta.description ??
                  'The issuer asked for a transaction code (PIN).'}
              </p>
            </div>
            <input
              value={txCode}
              onChange={(e) => setTxCode(e.target.value)}
              placeholder={`PIN (${txCodeMeta.length ?? '?'} digits)`}
              inputMode={txCodeMeta.input_mode === 'numeric' ? 'numeric' : 'text'}
              maxLength={txCodeMeta.length}
              className="w-full rounded border border-neutral-300 px-3 py-2 font-mono"
            />
          </div>
        )}

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
          {!offer && (
            <button
              type="button"
              onClick={() => void parse()}
              disabled={!url.trim() || submitting}
              className="rounded-md bg-neutral-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-neutral-700 disabled:opacity-50"
            >
              {submitting ? 'Working…' : 'Continue'}
            </button>
          )}
          {offer && txCodeMeta && (
            <button
              type="button"
              onClick={() => void submitWithPin()}
              disabled={!txCode.trim() || submitting}
              className="rounded-md bg-neutral-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-neutral-700 disabled:opacity-50"
            >
              {submitting ? 'Receiving…' : 'Receive credential'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
