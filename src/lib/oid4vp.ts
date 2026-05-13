// OpenID for Verifiable Presentations 1.0 Final — client (wallet) flow.
//
// V1 scope: `direct_post` response mode only, mdoc credentials only.
// Encrypted response (`direct_post.jwt`, DC API + HPKE) is deferred to V2.
//
// What this module does:
//   1. Parse an `openid4vp://` (or HTTPS) link into a structured request.
//   2. Resolve the Authorization Request: either inline (`request`) or fetched
//      (`request_uri`). V1 does not validate the JAR x509 chain — production
//      wallets MUST. We surface the `signed` flag so the UI can warn.
//   3. Match stored credentials against the DCQL query and surface the
//      selection to the user.
//   4. Build a filtered mdoc DeviceResponse (selective disclosure), sign the
//      DeviceAuth with the device key via WebCrypto, and POST `vp_token` to
//      the verifier's `response_uri`.

import { decodeJwt } from 'jose'
import {
  CoseKey,
  Document,
  DeviceResponse,
  DeviceSignedBuilder,
  IssuerNamespaces,
  IssuerSigned,
  SessionTranscript,
  SignatureAlgorithm,
  base64url,
} from '@owf/mdoc'
import { getDevicePublicJwk, getOrCreateDeviceKey } from './device-key.ts'
import { getOrCreateDeviceCertB64 } from './device-cert.ts'
import { createWalletMdocContext } from './mdoc-context.ts'
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
 * Build the OID4VP SessionTranscript bytes for this presentation request.
 *
 * The SessionTranscript binds the authorization request (clientId,
 * responseUri, nonce) to the device-signed payload — without it, a malicious
 * verifier could replay a presentation against a different audience.
 */
export async function buildSessionTranscript(
  request: OpenId4VpRequest,
): Promise<SessionTranscript> {
  const { privateKey } = await getOrCreateDeviceKey()
  const ctx = createWalletMdocContext(privateKey)
  return await SessionTranscript.forOid4Vp(
    {
      clientId: request.clientId,
      responseUri: request.responseUri,
      nonce: request.nonce,
      // jwkThumbprint is only required when the verifier requested an
      // encrypted response. For V1 direct_post (unencrypted) it is omitted.
    },
    ctx,
  )
}

/**
 * Build a filtered IssuerSigned that contains only the requested claims.
 *
 * Selective disclosure: rather than send all attributes the issuer stamped
 * into the credential, we keep only those listed in `keep`. The IssuerAuth
 * (MSO + signature) remains unchanged — the verifier matches the disclosed
 * items against the digests embedded in the MSO and rejects anything that
 * doesn't match. If `keep` is empty, all items are sent (no filter).
 */
function filterIssuerSigned(
  original: IssuerSigned,
  namespace: string,
  keep: string[],
): IssuerSigned {
  if (keep.length === 0) return original
  const keepSet = new Set(keep)
  const items = original.getIssuerNamespace(namespace) ?? []
  const filteredItems = items.filter((i) => keepSet.has(i.elementIdentifier))
  const nsMap = new Map([[namespace, filteredItems]])
  // Copy any other namespaces (V1 wallets only have one, but be permissive).
  for (const [ns, nsItems] of original.issuerNamespaces.issuerNamespaces) {
    if (ns !== namespace) nsMap.set(ns, nsItems)
  }
  return IssuerSigned.create({
    issuerNamespaces: IssuerNamespaces.create({ issuerNamespaces: nsMap }),
    issuerAuth: original.issuerAuth,
  })
}

export type PresentationResult = {
  status: number
  body: string
  /** `redirect_uri` returned by the verifier in the JSON response, if any. */
  redirectUri?: string
}

/**
 * Build and POST an OID4VP presentation for the chosen credential.
 *
 * Flow:
 *   1. Reconstruct the IssuerSigned from the stored CBOR bytes.
 *   2. Filter the disclosed items down to `requestedClaims` (selective
 *      disclosure). Verifier checks them against MSO digests; trust survives.
 *   3. Build the SessionTranscript that binds clientId/responseUri/nonce.
 *   4. Use DeviceSignedBuilder to sign the DeviceAuth with the device key.
 *      DeviceNamespaces is empty in V1 — all attributes live in IssuerSigned.
 *   5. Assemble Document + DeviceResponse (one document, V1).
 *   6. POST `vp_token` (DCQL response shape) + `state` to `response_uri`.
 */
export async function buildAndPostPresentation(
  request: OpenId4VpRequest,
  credential: StoredCredential,
  requestedClaims: string[],
  dcqlId: string,
): Promise<PresentationResult> {
  if (request.responseMode !== 'direct_post') {
    throw new Error(
      `Response mode ${request.responseMode} is not supported in V1 (direct_post only).`,
    )
  }

  const { privateKey } = await getOrCreateDeviceKey()
  const ctx = createWalletMdocContext(privateKey)

  const issuerSignedFull = IssuerSigned.fromEncodedForOid4Vci(
    base64url.encode(credential.rawBytes),
  )
  const issuerSigned = filterIssuerSigned(
    issuerSignedFull,
    credential.namespace,
    requestedClaims,
  )

  const sessionTranscript = await SessionTranscript.forOid4Vp(
    {
      clientId: request.clientId,
      responseUri: request.responseUri,
      nonce: request.nonce,
    },
    ctx,
  )

  // signingKey is a public-only CoseKey — the actual signing is done by the
  // WebCrypto MdocContext adapter (which holds the non-extractable private
  // key in closure).
  const publicJwk = await getDevicePublicJwk()
  const signingKey = CoseKey.fromJwk(publicJwk as Record<string, unknown>)
  const derCertificate = await getOrCreateDeviceCertB64()

  // V1 docType equals the namespace for the EU AV blueprint
  // (`eu.europa.ec.av.1`). If we ever support multi-namespace credentials,
  // docType must be stored separately.
  const docType = credential.namespace

  const deviceSigned = await new DeviceSignedBuilder(docType, ctx).sign({
    signingKey,
    algorithm: SignatureAlgorithm.ES256,
    sessionTranscript,
    derCertificate,
  })

  const document = Document.create({
    docType,
    issuerSigned,
    deviceSigned,
  })

  const deviceResponse = DeviceResponse.createSimple({
    documents: [document],
    status: 0,
  })

  const vpTokenValue = deviceResponse.encodedForOid4Vp
  const vpToken = JSON.stringify({ [dcqlId]: vpTokenValue })

  const body = new URLSearchParams()
  body.set('vp_token', vpToken)
  if (request.state) body.set('state', request.state)

  const resp = await fetch(request.responseUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  const text = await resp.text().catch(() => '')
  if (!resp.ok) {
    throw new Error(`Verifier ${resp.status} on response_uri: ${text || resp.statusText}`)
  }
  let redirectUri: string | undefined
  try {
    const parsed = JSON.parse(text) as { redirect_uri?: unknown }
    if (typeof parsed.redirect_uri === 'string') redirectUri = parsed.redirect_uri
  } catch {
    // Verifier may return an empty 200 or non-JSON — that's fine.
  }
  return { status: resp.status, body: text, redirectUri }
}

