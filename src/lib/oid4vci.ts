// OpenID for Verifiable Credential Issuance 1.0 Final — client flow.
//
// Pre-authorized code only in V1, matching the Tessaliq Issuer P4 surface.
// Authorization code flow is deferred to V2 if ever needed.
//
// Flow:
//   1. Receive `openid-credential-offer://?credential_offer=...`
//   2. Fetch issuer metadata at /.well-known/openid-credential-issuer
//   3. POST token endpoint with pre-authorized_code → access_token + c_nonce
//   4. Build proof.jwt signed by device key
//   5. POST credential endpoint with proof.jwt → mdoc credential
//   6. Persist in IndexedDB

import { base64url, IssuerSigned } from '@owf/mdoc'
import { buildProofJwt } from './proof-jwt.ts'
import { putCredential, type StoredCredential } from './storage.ts'

export type CredentialOffer = {
  credential_issuer: string
  credential_configuration_ids: string[]
  grants: {
    'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: {
      'pre-authorized_code': string
      tx_code?: { length?: number; input_mode?: string; description?: string }
    }
  }
}

export type IssuerMetadata = {
  credential_issuer: string
  credential_endpoint: string
  token_endpoint?: string
  nonce_endpoint?: string
  notification_endpoint?: string
  credential_configurations_supported?: Record<string, unknown>
}

export type TokenResponse = {
  access_token: string
  token_type: string
  c_nonce?: string
  c_nonce_expires_in?: number
  expires_in?: number
}

export type CredentialResponse = {
  credentials: Array<{ credential: string }>
  notification_id?: string
}

const OID4VCI_OFFER_SCHEME = 'openid-credential-offer://'
const PRE_AUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'

/**
 * Parse an `openid-credential-offer://` URL.
 *
 * Supports both the `credential_offer` (inline JSON) and the
 * `credential_offer_uri` (fetch from URL) parameter forms.
 */
export async function parseCredentialOffer(rawUrl: string): Promise<CredentialOffer> {
  const trimmed = rawUrl.trim()
  let queryString: string
  if (trimmed.startsWith(OID4VCI_OFFER_SCHEME)) {
    queryString = trimmed.slice(OID4VCI_OFFER_SCHEME.length)
    // The scheme-only URL may be just `openid-credential-offer://?foo=bar` or
    // `openid-credential-offer://example.com?foo=bar`. Normalise to query
    // string after the first '?'.
    const qIdx = queryString.indexOf('?')
    if (qIdx >= 0) queryString = queryString.slice(qIdx + 1)
  } else if (trimmed.startsWith('http')) {
    queryString = trimmed.split('?')[1] ?? ''
  } else {
    throw new Error('Invalid credential offer URL')
  }
  const params = new URLSearchParams(queryString)
  const inline = params.get('credential_offer')
  if (inline) {
    return JSON.parse(inline) as CredentialOffer
  }
  const uri = params.get('credential_offer_uri')
  if (uri) {
    const resp = await fetch(uri)
    if (!resp.ok) throw new Error(`credential_offer_uri fetch failed: ${resp.status}`)
    return (await resp.json()) as CredentialOffer
  }
  throw new Error('Credential offer URL has neither credential_offer nor credential_offer_uri')
}

export async function fetchIssuerMetadata(credentialIssuer: string): Promise<IssuerMetadata> {
  const url = `${credentialIssuer.replace(/\/+$/, '')}/.well-known/openid-credential-issuer`
  const resp = await fetch(url)
  if (!resp.ok) throw new Error(`Issuer metadata fetch failed: ${resp.status}`)
  return (await resp.json()) as IssuerMetadata
}

export async function requestToken(
  tokenEndpoint: string,
  preAuthorizedCode: string,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: PRE_AUTH_GRANT_TYPE,
    'pre-authorized_code': preAuthorizedCode,
  })
  const resp = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (!resp.ok) {
    const text = await resp.text().catch(() => '')
    throw new Error(`Token endpoint ${resp.status}: ${text || resp.statusText}`)
  }
  return (await resp.json()) as TokenResponse
}

export async function requestCredential(
  credentialEndpoint: string,
  accessToken: string,
  proofJwt: string,
  credentialConfigurationId: string,
): Promise<CredentialResponse> {
  const resp = await fetch(credentialEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      credential_configuration_id: credentialConfigurationId,
      proof: { proof_type: 'jwt', jwt: proofJwt },
    }),
  })
  if (!resp.ok) {
    const text = await resp.text().catch(() => '')
    throw new Error(`Credential endpoint ${resp.status}: ${text || resp.statusText}`)
  }
  return (await resp.json()) as CredentialResponse
}

/**
 * Decode the mdoc credential and surface the claims we care about for
 * display. Source of truth remains `rawBytes` — this is a convenience cache.
 *
 * V1 only handles single-namespace mdoc credentials in the
 * `eu.europa.ec.av.1` namespace family.
 */
function extractClaims(credentialBase64: string): {
  rawBytes: Uint8Array
  namespace: string
  claims: Record<string, unknown>
} {
  const issuerSigned = IssuerSigned.fromEncodedForOid4Vci(credentialBase64)
  // Pick the first namespace — V1 assumption. `IssuerNamespaces` is a class
  // with a getter `issuerNamespaces` that returns the underlying Map.
  const nsMap = issuerSigned.issuerNamespaces.issuerNamespaces
  const firstNs = nsMap.keys().next().value
  const namespace = firstNs ?? 'unknown'
  const claims = (issuerSigned.getPrettyClaims(namespace) ?? {}) as Record<string, unknown>
  return {
    rawBytes: base64url.decode(credentialBase64),
    namespace: String(namespace),
    claims,
  }
}

/**
 * High-level helper: run the full pre-authorized OID4VCI flow against an
 * offer, persist the credential, and return it.
 */
export async function acceptCredentialOffer(rawOfferUrl: string): Promise<StoredCredential> {
  const offer = await parseCredentialOffer(rawOfferUrl)
  const preAuthGrant = offer.grants[PRE_AUTH_GRANT_TYPE]
  if (!preAuthGrant) {
    throw new Error('Only pre-authorized code grants are supported in V1')
  }
  const credentialConfigurationId = offer.credential_configuration_ids[0]
  if (!credentialConfigurationId) {
    throw new Error('Offer has no credential_configuration_ids')
  }
  const metadata = await fetchIssuerMetadata(offer.credential_issuer)
  const tokenEndpoint =
    metadata.token_endpoint ??
    `${offer.credential_issuer.replace(/\/+$/, '')}/v1/credential/token`
  const tokenResp = await requestToken(tokenEndpoint, preAuthGrant['pre-authorized_code'])
  if (!tokenResp.c_nonce) {
    throw new Error('Token response did not include c_nonce')
  }
  const proofJwt = await buildProofJwt({
    audience: offer.credential_issuer,
    nonce: tokenResp.c_nonce,
  })
  const credResp = await requestCredential(
    metadata.credential_endpoint,
    tokenResp.access_token,
    proofJwt,
    credentialConfigurationId,
  )
  const first = credResp.credentials[0]
  if (!first?.credential) {
    throw new Error('Credential endpoint returned no credential')
  }
  const extracted = extractClaims(first.credential)
  const stored: StoredCredential = {
    id: crypto.randomUUID(),
    format: 'mdoc',
    namespace: extracted.namespace,
    rawBytes: extracted.rawBytes,
    claims: extracted.claims,
    issuerCertSubject: 'unknown',
    issuedAt: new Date(),
    expiresAt: null,
    statusListUri: null,
    statusListIndex: null,
  }
  await putCredential(stored)
  return stored
}
