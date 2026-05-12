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
import { getOrCreateDeviceKey } from './device-key.ts'

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
