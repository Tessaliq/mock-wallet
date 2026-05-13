// OID4VCI `proof.jwt` builder.
//
// Per OpenID for Verifiable Credential Issuance 1.0 Final §7.2.1.4, the
// wallet proves possession of the key that will bind the issued credential
// by signing a small JWT. The Tessaliq Issuer (P4) validates:
//   - header.typ == 'openid4vci-proof+jwt'
//   - header.alg ∈ {ES256, ES384}
//   - header.jwk is present and matches the device public key
//   - payload.aud == credential issuer base URL
//   - payload.iat is recent
//   - payload.nonce == the c_nonce returned by the token endpoint

import { SignJWT, exportJWK } from 'jose'
import { getDeviceKeyThumbprint, getOrCreateDeviceKey } from './device-key.ts'

export type BuildProofJwtParams = {
  /** Credential issuer base URL — populates the `aud` claim. */
  audience: string
  /** `c_nonce` returned by the token endpoint. */
  nonce: string
}

export async function buildProofJwt(params: BuildProofJwtParams): Promise<string> {
  const { privateKey, publicKey } = await getOrCreateDeviceKey()
  const jwk = await exportJWK(publicKey)
  return await new SignJWT({
    nonce: params.nonce,
  })
    .setProtectedHeader({
      typ: 'openid4vci-proof+jwt',
      alg: 'ES256',
      jwk,
    })
    .setAudience(params.audience)
    .setIssuedAt()
    .sign(privateKey)
}

/**
 * Build a `client_assertion` JWT for the OIDF private_key_jwt client auth
 * method (RFC 7523 §3). The Tessaliq issuer accepts a key-by-value
 * (header `jwk`) — no prior client registration needed.
 *
 * `iss` and `sub` are both set to the device JWK thumbprint (RFC 7638),
 * which doubles as the wallet's stable client identifier.
 */
export async function buildClientAssertion(audience: string | string[]): Promise<string> {
  const { privateKey, publicKey } = await getOrCreateDeviceKey()
  const jwk = await exportJWK(publicKey)
  const clientId = await getDeviceKeyThumbprint()
  const audClaim = Array.isArray(audience) ? audience[0] : audience
  return await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', jwk })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(audClaim)
    .setIssuedAt()
    .setExpirationTime('5m')
    .setJti(crypto.randomUUID())
    .sign(privateKey)
}
