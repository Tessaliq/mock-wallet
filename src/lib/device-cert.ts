// Self-signed X.509 certificate for the device key.
//
// The mdoc DeviceSignedBuilder in @owf/mdoc embeds an X.509 cert in the
// COSE_Sign1 x5chain unprotected header. The wallet does not need a real PKI
// — trust in the device key is established via the MSO `deviceKeyInfo` that
// the issuer signed at issuance time. The cert is protocol bookkeeping.
//
// We generate a self-signed cert once on first presentation, sign it with
// the (non-extractable) device private key, and persist the DER bytes
// alongside the key in IndexedDB.

import * as x509 from '@peculiar/x509'
import { base64 } from '@owf/mdoc'
import { getOrCreateDeviceKey } from './device-key.ts'
import { getStoredKey, putStoredKey } from './storage.ts'

/**
 * Returns the device certificate as base64-encoded DER, ready to be passed
 * to `DeviceSignedBuilder.sign({ derCertificate })`. Generates and persists
 * the cert on first call.
 */
export async function getOrCreateDeviceCertB64(): Promise<string> {
  const der = await getOrCreateDeviceCertDer()
  return base64.encode(der)
}

export async function getOrCreateDeviceCertDer(): Promise<Uint8Array> {
  const existing = await getStoredKey()
  if (existing?.certDer) return existing.certDer

  // Need a fresh cert. We must have a key pair already.
  const key = await getOrCreateDeviceKey()
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerialHex(),
    subject: 'CN=Tessaliq Mock Wallet Device',
    issuer: 'CN=Tessaliq Mock Wallet Device',
    notBefore: new Date(Date.now() - 5 * 60 * 1000),
    notAfter: new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: key.publicKey,
    signingKey: key.privateKey,
  })

  const certDer = new Uint8Array(cert.rawData)
  await putStoredKey({ ...key, certDer })
  return certDer
}

function randomSerialHex(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8))
  let s = ''
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  // X.509 serial must be a positive integer — strip leading 0x80+ bit by
  // forcing the first byte's MSB to 0.
  return (parseInt(s.slice(0, 2), 16) & 0x7f).toString(16).padStart(2, '0') + s.slice(2)
}
