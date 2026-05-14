// MW4 acceptance smoke: reusability + revocation.
//
// Validates the MW4 acceptance criteria (https://github.com/Tessaliq/mock-wallet/issues/1):
//   1. Same credential reused across 2 distinct verifier sessions → 2 valid receipts
//   2. Revocation via the Tessaliq admin endpoint → subsequent presentation rejected
//
// The credential reception path is identical to scripts/smoke-e2e.mjs — this
// script extends it with the multi-session and revocation steps. Run from the
// repo root:
//
//   node scripts/smoke-mw4-acceptance.mjs
//
// V1.1 follow-up (Tessaliq #224): buildAvCredential does not currently embed
// a status_list reference in the MSO, so the verifier does NOT check the
// status list for revocation. The admin endpoint succeeds, but the post-
// revocation presentation is still accepted. This script logs that
// expectation so the gap is visible to anyone running the smoke.

import 'reflect-metadata'
import {
  SignJWT, exportJWK, generateKeyPair, calculateJwkThumbprint, decodeJwt,
} from 'jose'
import {
  CoseKey, Document, DeviceResponse, DeviceSignedBuilder,
  IssuerNamespaces, IssuerSigned, SessionTranscript, SignatureAlgorithm,
} from '@owf/mdoc'
import * as x509 from '@peculiar/x509'

const STAGING = 'https://api-staging.tessaliq.com'
const API_KEY = 'tsl_live_KOeL1k1ID_puLRqvsRDT2yTtqWQp8MUSSe87Ce4Ihv4'

function makeCtx(privateKey) {
  return {
    crypto: {
      random: (length) => crypto.getRandomValues(new Uint8Array(length)),
      digest: async ({ digestAlgorithm, bytes }) => {
        const out = await crypto.subtle.digest(digestAlgorithm, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength))
        return new Uint8Array(out)
      },
      calculateEphemeralMacKey: () => { throw new Error('MAC not supported') },
    },
    cose: {
      sign1: {
        sign: async ({ toBeSigned }) => {
          const sig = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' }, privateKey,
            toBeSigned.buffer.slice(toBeSigned.byteOffset, toBeSigned.byteOffset + toBeSigned.byteLength),
          )
          return new Uint8Array(sig)
        },
        verify: () => { throw new Error('verify not impl in wallet') },
      },
      mac0: { sign: () => { throw new Error() }, verify: () => { throw new Error() } },
    },
  }
}

async function receiveCredential(privateKey, jwk, thumbprint) {
  const offer = await (await fetch(`${STAGING}/v1/test-helpers/oidf-credential-offer`, { method: 'POST' })).json()
  const issuer = offer.credential_offer.credential_issuer
  const clientAssertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', jwk })
    .setIssuer(thumbprint).setSubject(thumbprint).setAudience(issuer)
    .setIssuedAt().setExpirationTime('5m').setJti(crypto.randomUUID())
    .sign(privateKey)
  const token = await (await fetch(`${issuer}/v1/credential/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': offer.pre_authorized_code,
      tx_code: offer.tx_code,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: clientAssertion,
    }),
  })).json()
  const proofJwt = await new SignJWT({ nonce: token.c_nonce })
    .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk })
    .setAudience(issuer).setIssuedAt().sign(privateKey)
  const cred = await (await fetch(`${issuer}/v1/credential/issue`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token.access_token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential_configuration_id: offer.credential_offer.credential_configuration_ids[0],
      proof: { proof_type: 'jwt', jwt: proofJwt },
    }),
  })).json()
  return cred.credentials[0].credential
}

async function presentToVerifier(credentialB64, privateKey, publicKey, jwk, label) {
  const session = await (await fetch(`${STAGING}/v1/sessions`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ useCase: 'age_verification_18_plus', jurisdiction: 'FR' }),
  })).json()
  const link = await (await fetch(`${STAGING}/v1/openid4vp/link/${session.id}?profile=eu_av_blueprint`)).json()
  // av:// and openid4vp:// are non-special URL schemes; normalise to https
  // so URL.searchParams works as expected on Node.
  const u = new URL(link.deep_link.replace(/^(av|openid4vp):\/\//, 'https://x/'))
  const requestUri = u.searchParams.get('request_uri')
  if (!requestUri) throw new Error(`no request_uri in deep_link: ${link.deep_link.slice(0, 120)}`)
  const jarText = (await (await fetch(requestUri)).text()).trim()
  if (!jarText.startsWith('ey')) throw new Error(`JAR fetch returned non-JWT: ${jarText.slice(0, 120)}`)
  const req = decodeJwt(jarText)

  const ctx = makeCtx(privateKey)
  const sessionTranscript = await SessionTranscript.forOid4Vp({
    clientId: req.client_id, responseUri: req.response_uri, nonce: req.nonce,
  }, ctx)

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '01', subject: 'CN=Smoke Wallet', issuer: 'CN=Smoke Wallet',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 365 * 24 * 60 * 60_000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey, signingKey: privateKey,
  })
  const derB64 = Buffer.from(cert.rawData).toString('base64')

  const issuerSignedFull = IssuerSigned.fromEncodedForOid4Vci(credentialB64)
  const namespace = issuerSignedFull.issuerNamespaces.issuerNamespaces.keys().next().value
  const items = issuerSignedFull.getIssuerNamespace(namespace) ?? []
  const requested = (req.dcql_query?.credentials ?? []).flatMap(c => c.claims ?? []).map(cl => cl.path[cl.path.length - 1])
  const keep = new Set(requested)
  const filtered = keep.size === 0 ? items : items.filter(i => keep.has(i.elementIdentifier))
  const issuerSigned = IssuerSigned.create({
    issuerNamespaces: IssuerNamespaces.create({ issuerNamespaces: new Map([[namespace, filtered]]) }),
    issuerAuth: issuerSignedFull.issuerAuth,
  })

  const deviceSigned = await new DeviceSignedBuilder(namespace, ctx).sign({
    signingKey: CoseKey.fromJwk(jwk),
    algorithm: SignatureAlgorithm.ES256,
    sessionTranscript, derCertificate: derB64,
  })
  const document = Document.create({ docType: namespace, issuerSigned, deviceSigned })
  const encoded = DeviceResponse.createSimple({ documents: [document], status: 0 }).encodedForOid4Vp

  const dcqlId = req.dcql_query?.credentials?.[0]?.id ?? 'default'
  const presentRes = await fetch(req.response_uri + '?details=1', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ vp_token: JSON.stringify({ [dcqlId]: encoded }), state: req.state }),
  })
  const presentBody = await presentRes.text()

  const receiptRes = await fetch(`${STAGING}/v1/sessions/${session.id}/receipt`, {
    headers: { Authorization: `Bearer ${API_KEY}` },
  })
  const receiptBody = await receiptRes.json()

  console.log(`[${label}] session=${session.id.slice(0, 8)} verify=${presentRes.status} receipt=${receiptRes.status}`)
  if (presentRes.status !== 200) console.log(`  verifier body: ${presentBody.slice(0, 200)}`)
  return {
    sessionId: session.id,
    verifyStatus: presentRes.status,
    verifyBody: presentBody,
    receiptStatus: receiptRes.status,
    receiptToken: receiptBody.receipt_token,
  }
}

async function revokeCredential({ index, fingerprint, listId }) {
  const body = { list_id: listId, action: 'revoke' }
  if (typeof index === 'number') body.index = index
  if (fingerprint) body.fingerprint = fingerprint
  const res = await fetch(`${STAGING}/v1/credential/status`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.text() }
}

// P5.1 — compute the Tessaliq fingerprint for an emitted credential.
// Mirror of `extractFingerprint` from packages/api/src/lib/issuer.ts :
//   fingerprint = sha256(IssuerAuth.signature)
async function computeFingerprintHex(credentialB64) {
  const issuerSigned = IssuerSigned.fromEncodedForOid4Vci(credentialB64)
  const sig = issuerSigned.issuerAuth.signature
  const digest = await crypto.subtle.digest('SHA-256', sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength))
  return Buffer.from(new Uint8Array(digest)).toString('hex')
}

async function main() {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
  const jwk = await exportJWK(publicKey)
  const thumbprint = await calculateJwkThumbprint(jwk)

  console.log('\n=== MW4 acceptance: reusability ===')
  console.log('1. Receive one credential from the Tessaliq issuer...')
  const credentialB64 = await receiveCredential(privateKey, jwk, thumbprint)
  console.log('   credential len:', credentialB64.length)

  console.log('2. Present to session A (first verifier)...')
  const a = await presentToVerifier(credentialB64, privateKey, publicKey, jwk, 'A')

  console.log('3. Present the SAME credential to session B (second verifier)...')
  const b = await presentToVerifier(credentialB64, privateKey, publicKey, jwk, 'B')

  const reuseOk = a.verifyStatus === 200 && b.verifyStatus === 200
    && a.receiptStatus === 200 && b.receiptStatus === 200
    && a.sessionId !== b.sessionId
  console.log(reuseOk
    ? '   ✓ REUSABILITY: same credential accepted across 2 distinct sessions with 2 valid receipts'
    : '   ✗ REUSABILITY FAILED: sessions accepted A=' + a.verifyStatus + ' B=' + b.verifyStatus)

  console.log('\n=== MW4 acceptance: revocation (P5.1 enforcement) ===')
  console.log('Since P5.1 (2026-05-14), the Tessaliq verifier enforces credential')
  console.log('revocation server-side via PG-backed fingerprint→idx mapping. The')
  console.log('credential MSO does NOT yet embed a status pointer (V2), so the')
  console.log('enforcement is Tessaliq-verifier-only — third-party verifiers will')
  console.log('not honor revocations until the MSO wire-up lands.')

  const fingerprintHex = await computeFingerprintHex(credentialB64)
  console.log('4. Revoke via /v1/credential/status with fingerprint =', fingerprintHex.slice(0, 16) + '…')
  const revokeRes = await revokeCredential({ fingerprint: fingerprintHex, listId: 'issuer-list-1' })
  console.log('   revoke:', revokeRes.status, revokeRes.body.slice(0, 200))

  console.log('5. Present the same credential AGAIN (session C) — expect rejection...')
  const c = await presentToVerifier(credentialB64, privateKey, publicKey, jwk, 'C')
  const revocationEnforced = c.verifyStatus !== 200 && c.verifyBody.includes('credential_revoked')
  if (revocationEnforced) {
    console.log('   ✓ REVOCATION ENFORCED: verify status', c.verifyStatus, '— error: credential_revoked')
  } else {
    console.log('   ✗ REVOCATION NOT ENFORCED: verify status', c.verifyStatus)
    console.log('     body excerpt:', c.verifyBody.slice(0, 200))
  }

  console.log('\n=== Summary ===')
  console.log('Reusability:', reuseOk ? 'PASS' : 'FAIL')
  console.log('Revocation:  admin endpoint', revokeRes.status === 200 ? 'OK' : 'FAIL',
    '; verifier enforcement', revocationEnforced ? 'PASS' : 'FAIL')
  process.exit(reuseOk && revocationEnforced ? 0 : 1)
}

main().catch(e => { console.error('FAIL:', e); process.exit(1) })
