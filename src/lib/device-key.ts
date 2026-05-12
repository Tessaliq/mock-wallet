// Device key management for the mock wallet.
//
// The device key is a P-256 ECDSA key pair generated once on first use and
// persisted in IndexedDB. The private key is marked non-extractable so it
// cannot be exported by application code — the only thing we can do with it
// is sign payloads via WebCrypto. This mirrors the security model of a real
// EUDI wallet binding, just without hardware backing.
//
// Why P-256 / ES256:
//   - default curve for OID4VCI proof.jwt + mdoc DeviceAuth on the EU AV
//     blueprint side (matches our Tessaliq Issuer P4 acceptance: ES256 / ES384)
//   - first-class WebCrypto support across all modern browsers
//   - mature interop story with mdoc's COSE_Sign1 structures

import { exportJWK } from 'jose'
import { getStoredKey, putStoredKey, type StoredKeyEntry, DEVICE_KEY_ID } from './storage.ts'

const ALGO: EcKeyGenParams = {
  name: 'ECDSA',
  namedCurve: 'P-256',
}
const KEY_USAGES: KeyUsage[] = ['sign', 'verify']

async function generateDeviceKey(): Promise<StoredKeyEntry> {
  const pair = await crypto.subtle.generateKey(
    ALGO,
    // extractable: false on the private key. The public key is extractable
    // because we need to export it as JWK to put it in the OID4VCI proof JWT
    // header and in the mdoc DeviceKeyInfo. WebCrypto generateKey returns the
    // same `extractable` flag on both halves, so we generate as extractable
    // and rely on `crypto.subtle.exportKey` only being callable on the public
    // key in practice.
    true,
    KEY_USAGES,
  )
  // Re-import the private key as non-extractable to enforce the policy at
  // the storage layer. structuredClone copying the original CryptoKey into
  // IndexedDB would otherwise preserve the original (extractable) flag.
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey)
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    ALGO,
    false,
    ['sign'],
  )
  return {
    id: DEVICE_KEY_ID,
    privateKey,
    publicKey: pair.publicKey,
    createdAt: new Date(),
  }
}

/**
 * Returns the device key pair, generating a new one on first use.
 *
 * Subsequent calls return the same pair stored in IndexedDB.
 */
export async function getOrCreateDeviceKey(): Promise<StoredKeyEntry> {
  const existing = await getStoredKey()
  if (existing) return existing
  const fresh = await generateDeviceKey()
  await putStoredKey(fresh)
  return fresh
}

/**
 * Exports the device public key as a JWK. Used to embed in OID4VCI proof.jwt
 * header (`jwk`) and in mdoc DeviceKeyInfo at credential issuance time.
 */
export async function getDevicePublicJwk(): Promise<JsonWebKey> {
  const { publicKey } = await getOrCreateDeviceKey()
  return exportJWK(publicKey)
}

/**
 * Computes a stable fingerprint of the device public key (JWK thumbprint
 * RFC 7638 SHA-256, base64url).
 *
 * Used to give the user a visual identifier for "this device" without
 * exposing the full JWK in the UI.
 */
export async function getDeviceKeyThumbprint(): Promise<string> {
  const jwk = await getDevicePublicJwk()
  // RFC 7638 thumbprint: SHA-256 over the canonical JSON of {crv, kty, x, y}
  // with keys sorted lexicographically and no whitespace.
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  })
  const buf = new TextEncoder().encode(canonical)
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return base64url(new Uint8Array(digest))
}

function base64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
