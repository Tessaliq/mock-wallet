// WebCrypto adapter for the @owf/mdoc `MdocContext` interface.
//
// `@owf/mdoc` is platform-agnostic on purpose — every signing / hashing /
// x509 operation goes through an `MdocContext` object that the caller
// provides. This file is the wallet-side adapter that wires those calls into
// the browser's WebCrypto and our non-extractable device key.
//
// The trick we use:
//   `cose.sign1.sign({ toBeSigned, key, algorithm })` ignores the provided
//   `key` parameter and signs with the device CryptoKey captured in this
//   adapter's closure. That keeps the device private key non-extractable —
//   we never have to hand it to anyone, we just expose a signing function.
//
// Limitations in V1:
//   - MAC0 (device authentication via MAC) is not supported. Signature mode
//     only. If a verifier requires MAC, this adapter throws.
//   - `crypto.calculateEphemeralMacKey` is not supported (same reason).
//   - x509 chain verification is not implemented. Wallet does not validate
//     verifier x509 chains in V1; production wallets MUST.

import type { MdocContext } from '@owf/mdoc'

export type WalletMdocContext = Pick<MdocContext, 'crypto' | 'cose'>

export function createWalletMdocContext(devicePrivateKey: CryptoKey): WalletMdocContext {
  return {
    crypto: {
      random: (length) => crypto.getRandomValues(new Uint8Array(length)),
      digest: async ({ digestAlgorithm, bytes }) => {
        const algo = digestToWebCrypto(digestAlgorithm)
        // Re-wrap into a plain ArrayBuffer-backed Uint8Array — TS 5.9 is
        // strict about ArrayBufferLike vs ArrayBuffer when calling
        // crypto.subtle.digest.
        const out = await crypto.subtle.digest(algo, toArrayBuffer(bytes))
        return new Uint8Array(out)
      },
      calculateEphemeralMacKey: () => {
        throw new Error(
          'MAC mode is not supported in V1 mock wallet. Use signature device-auth.',
        )
      },
    },
    cose: {
      sign1: {
        sign: async ({ toBeSigned, algorithm }) => {
          // We deliberately ignore the `key` argument and sign with the
          // device private key captured in closure. This is the whole point
          // of keeping the key non-extractable.
          const hash = algorithmToHash(String(algorithm ?? 'ES256'))
          const sig = await crypto.subtle.sign(
            { name: 'ECDSA', hash },
            devicePrivateKey,
            toArrayBuffer(toBeSigned),
          )
          // WebCrypto SubtleCrypto returns ECDSA signatures as raw r||s
          // (IEEE P-1363 form), which is also what COSE_Sign1 expects per
          // RFC 8152 §8.1. No re-encoding needed.
          return new Uint8Array(sig)
        },
        verify: () => {
          // Wallet side does not verify Sign1 — verifier does. If something
          // calls this, it's a programming mistake.
          throw new Error('Sign1 verify is not implemented in the wallet adapter')
        },
      },
      mac0: {
        sign: () => {
          throw new Error('MAC mode is not supported in V1 mock wallet')
        },
        verify: () => {
          throw new Error('Mac0 verify is not implemented in the wallet adapter')
        },
      },
    },
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  // Forces the underlying buffer to be a plain ArrayBuffer (not
  // SharedArrayBuffer). Necessary for WebCrypto under strict TS settings.
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

function digestToWebCrypto(algo: string): AlgorithmIdentifier {
  switch (algo) {
    case 'SHA-256':
      return 'SHA-256'
    case 'SHA-384':
      return 'SHA-384'
    case 'SHA-512':
      return 'SHA-512'
    default:
      throw new Error(`Unsupported digest algorithm: ${algo}`)
  }
}

function algorithmToHash(algorithm: string): 'SHA-256' | 'SHA-384' | 'SHA-512' {
  switch (algorithm) {
    case 'ES256':
      return 'SHA-256'
    case 'ES384':
      return 'SHA-384'
    case 'ES512':
      return 'SHA-512'
    default:
      throw new Error(`Unsupported signature algorithm: ${algorithm}`)
  }
}
