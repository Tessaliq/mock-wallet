// OpenID for Verifiable Presentations 1.0 Final — client (wallet) flow.
//
// V1 scope: `direct_post` response mode only, mdoc credentials only.
// Encrypted response (`direct_post.jwt`, DC API + HPKE) is deferred to V2.
//
// Three things this module does in V1:
//   1. Parse an `openid4vp://` (or HTTPS) link into a structured request.
//   2. Resolve the Authorization Request: either inline (`request`) or fetched
//      (`request_uri`). For V1, signature validation of the request JAR is
//      best-effort — we accept self-signed verifiers and surface a warning
//      in the UI. Production wallets MUST validate the x509 chain.
//   3. Match stored credentials against the DCQL query and surface the
//      selection to the user.
//
// **NOT YET WIRED IN V1**: the actual mdoc DeviceResponse construction +
// signing + POST to direct_post. The `@owf/mdoc` API exposes the right
// primitives (`SessionTranscript.forOid4Vp`, `Holder.createDeviceResponseForDeviceRequest`,
// `DeviceSignedBuilder`) but they require an `MdocContext` (`cose`, `crypto`,
// `x509`) that needs a thin WebCrypto adapter. Adapter + presentation flow
// will land in a follow-up commit before MW4. The current code is enough to
// parse the request and drive the consent UI.

import { decodeJwt } from 'jose'
import type { StoredCredential } from './storage.ts'

export type OpenId4VpRequest = {
  /** Verifier `client_id` (e.g. x509_san_dns:api.tessaliq.com). */
  clientId: string
  /** Where the wallet POSTs the vp_token. */
  responseUri: string
  /** Fresh nonce required to bind the SessionTranscript. */
  nonce: string
  /** Optional state echoed back unchanged. */
  state?: string
  /** Response mode requested by the verifier. V1 only supports direct_post. */
  responseMode: 'direct_post' | 'direct_post.jwt' | 'dc_api.jwt' | string
  /** DCQL query (preferred in OID4VP 1.0 Final). */
  dcqlQuery: DcqlQuery | null
  /** Was the request signed (JAR via request_uri)? */
  signed: boolean
}

export type DcqlQuery = {
  credentials: Array<{
    id: string
    format: string
    meta?: { doctype_value?: string }
    claims?: Array<{
      path: string[]
      values?: unknown[]
    }>
  }>
}

const OID4VP_SCHEMES = ['openid4vp://', 'openid4vp-deeplink://']

/**
 * Parse the entry-point URL the user scanned. The URL may carry the request
 * inline (`request=...` JWT) or by reference (`request_uri=...`). In both
 * cases we return a normalised structured request.
 */
export async function parseAuthorizationRequest(rawUrl: string): Promise<OpenId4VpRequest> {
  const trimmed = rawUrl.trim()
  let queryString: string
  const matchedScheme = OID4VP_SCHEMES.find((s) => trimmed.startsWith(s))
  if (matchedScheme) {
    queryString = trimmed.slice(matchedScheme.length)
    const qIdx = queryString.indexOf('?')
    if (qIdx >= 0) queryString = queryString.slice(qIdx + 1)
  } else if (trimmed.startsWith('http')) {
    queryString = trimmed.split('?')[1] ?? ''
  } else {
    throw new Error('Invalid OID4VP authorization request URL')
  }

  const params = new URLSearchParams(queryString)

  // Inline request (request=<JWT>): no fetch, signature is implicit.
  const inlineJwt = params.get('request')
  if (inlineJwt) {
    return decodeRequestJwt(inlineJwt, true)
  }
  // Request by reference (request_uri=<URL>): fetch the JAR.
  const requestUri = params.get('request_uri')
  if (requestUri) {
    const resp = await fetch(requestUri)
    if (!resp.ok) {
      throw new Error(`request_uri fetch failed: ${resp.status}`)
    }
    const ct = resp.headers.get('content-type') ?? ''
    const body = await resp.text()
    if (ct.includes('application/oauth-authz-req+jwt')) {
      return decodeRequestJwt(body.trim(), true)
    }
    // Fall back to JSON body for unsigned requests.
    return decodeRequestJson(JSON.parse(body), false)
  }

  // Inline parameters (rare in OID4VP 1.0 but tolerated for testing).
  return decodeRequestParams(params, false)
}

function decodeRequestJwt(jwt: string, signed: boolean): OpenId4VpRequest {
  // V1: no signature validation. Production wallets MUST validate the
  // x509 cert chain referenced by the JAR header.
  const payload = decodeJwt(jwt) as Record<string, unknown>
  return shapeRequest(payload, signed)
}

function decodeRequestJson(json: Record<string, unknown>, signed: boolean): OpenId4VpRequest {
  return shapeRequest(json, signed)
}

function decodeRequestParams(params: URLSearchParams, signed: boolean): OpenId4VpRequest {
  const obj: Record<string, unknown> = {}
  for (const [k, v] of params.entries()) obj[k] = v
  if (typeof obj.dcql_query === 'string') {
    obj.dcql_query = JSON.parse(obj.dcql_query)
  }
  return shapeRequest(obj, signed)
}

function shapeRequest(raw: Record<string, unknown>, signed: boolean): OpenId4VpRequest {
  const clientId = String(raw.client_id ?? '')
  const responseUri = String(raw.response_uri ?? '')
  const nonce = String(raw.nonce ?? '')
  if (!clientId || !responseUri || !nonce) {
    throw new Error('Authorization request is missing required client_id / response_uri / nonce')
  }
  return {
    clientId,
    responseUri,
    nonce,
    state: typeof raw.state === 'string' ? raw.state : undefined,
    responseMode: String(raw.response_mode ?? 'direct_post'),
    dcqlQuery: (raw.dcql_query as DcqlQuery | undefined) ?? null,
    signed,
  }
}

/**
 * Match stored credentials against the verifier's DCQL query.
 *
 * V1 keeps the matcher very simple: for each DCQL credential, we look for
 * stored credentials whose namespace equals `meta.doctype_value`. Multi-doctype
 * queries, claim-level filtering, and disjunctive matching land in V2.
 */
export type CredentialMatch = {
  dcqlId: string
  candidates: StoredCredential[]
  requestedClaims: string[]
}

export function matchCredentialsAgainstQuery(
  query: DcqlQuery | null,
  stored: StoredCredential[],
): CredentialMatch[] {
  if (!query) {
    // No DCQL — accept all stored credentials as candidates for a single slot.
    return [
      {
        dcqlId: 'default',
        candidates: stored,
        requestedClaims: [],
      },
    ]
  }
  return query.credentials.map((c) => {
    const doctype = c.meta?.doctype_value
    const candidates = doctype
      ? stored.filter((s) => s.namespace === doctype)
      : stored
    const requestedClaims = (c.claims ?? [])
      .map((cl) => cl.path[cl.path.length - 1])
      .filter((p): p is string => typeof p === 'string')
    return {
      dcqlId: c.id,
      candidates,
      requestedClaims,
    }
  })
}

/**
 * Stub. The full implementation needs:
 *   1. SessionTranscript.forOid4Vp({ clientId, responseUri, nonce }, ctx)
 *   2. A DeviceResponse built from the selected IssuerSigned + a DeviceSigned
 *      signed by the WebCrypto device key over the session transcript bytes.
 *   3. POST direct_post to `responseUri` with vp_token=<base64url-CBOR DeviceResponse>
 *      and state echoed back.
 *
 * Blocking item: an MdocContext implementation that wraps WebCrypto so the
 * `Holder.createDeviceResponseForDeviceRequest` (or equivalent
 * DeviceSignedBuilder) can sign with the non-extractable device private key.
 * This adapter is the next focused chunk of work before MW4 E2E.
 */
export async function buildAndPostPresentation(
  _request: OpenId4VpRequest,
  _credential: StoredCredential,
): Promise<{ status: 'not_implemented_yet'; reason: string }> {
  return {
    status: 'not_implemented_yet',
    reason:
      'mdoc DeviceResponse signing requires a WebCrypto MdocContext adapter. Pending implementation before MW4.',
  }
}
