// Full Variante C E2E smoke-test against api-staging.tessaliq.com.
//
// Run: `node scripts/smoke-e2e.mjs` from the repo root.
//
// Mirrors what the browser wallet does, end to end:
//   1. Get a credential (OID4VCI) — receives an mdoc AV credential.
//   2. Create a verifier session and fetch its openid4vp:// link.
//   3. Parse the JAR, build a filtered DeviceResponse, POST direct_post.
//   4. Read back the receipt JWT to confirm the verifier accepted us.
//
// Half 1 (OID4VCI) is GREEN as of 2026-05-13. Half 2 still 400s on the
// DeviceAuth signature check (`"Device signature must be valid: undefined"`).
// See PLAN.md MW4 for the open hypotheses to investigate. Set NO_FILTER=1
// to ship the unfiltered IssuerSigned (rules out MSO digest mismatch).

import 'reflect-metadata'
import {
  SignJWT,
  exportJWK,
  generateKeyPair,
  calculateJwkThumbprint,
  decodeJwt,
} from 'jose'
import {
  CoseKey,
  Document,
  DeviceAuthentication,
  DeviceResponse,
  DeviceSignedBuilder,
  IssuerNamespaces,
  IssuerSigned,
  SessionTranscript,
  SignatureAlgorithm,
  Verifier,
  base64url,
} from '@owf/mdoc'
import { p256 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha256'
import * as x509 from '@peculiar/x509'

const STAGING = 'https://api-staging.tessaliq.com'
const API_KEY = 'tsl_live_KOeL1k1ID_puLRqvsRDT2yTtqWQp8MUSSe87Ce4Ihv4'

// --- WebCrypto MdocContext adapter (same logic as src/lib/mdoc-context.ts) ---
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
            { name: 'ECDSA', hash: 'SHA-256' },
            privateKey,
            toBeSigned.buffer.slice(toBeSigned.byteOffset, toBeSigned.byteOffset + toBeSigned.byteLength),
          )
          return new Uint8Array(sig)
        },
        verify: () => { throw new Error('verify not impl in wallet') },
      },
      mac0: {
        sign: () => { throw new Error('mac not supported') },
        verify: () => { throw new Error('mac not supported') },
      },
    },
  }
}

async function half1Receive(privateKey, publicKey, jwk, thumbprint) {
  const offerRes = await fetch(`${STAGING}/v1/test-helpers/oidf-credential-offer`, { method: 'POST' })
  const offer = await offerRes.json()

  const issuer = offer.credential_offer.credential_issuer
  const tokenEndpoint = `${issuer}/v1/credential/token`
  const clientAssertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', jwk })
    .setIssuer(thumbprint).setSubject(thumbprint).setAudience(issuer)
    .setIssuedAt().setExpirationTime('5m').setJti(crypto.randomUUID())
    .sign(privateKey)
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    'pre-authorized_code': offer.pre_authorized_code,
    tx_code: offer.tx_code,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
  })
  const tokenRes = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  const token = await tokenRes.json()

  const proofJwt = await new SignJWT({ nonce: token.c_nonce })
    .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk })
    .setAudience(issuer).setIssuedAt().sign(privateKey)

  const credRes = await fetch(`${issuer}/v1/credential/issue`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token.access_token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential_configuration_id: offer.credential_offer.credential_configuration_ids[0],
      proof: { proof_type: 'jwt', jwt: proofJwt },
    }),
  })
  const cred = await credRes.json()
  console.log('half1 receive OK — credential base64url len:', cred.credentials[0].credential.length)
  return cred.credentials[0].credential
}

async function half2Present(credentialB64, privateKey, publicKey, jwk) {
  // Create a verifier session.
  const sessionRes = await fetch(`${STAGING}/v1/sessions`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ useCase: 'age_verification_18_plus', jurisdiction: 'FR' }),
  })
  const session = await sessionRes.json()
  const linkRes = await fetch(`${STAGING}/v1/openid4vp/link/${session.id}?profile=eu_av_blueprint`)
  const link = await linkRes.json()

  // Parse the deep_link query.
  const u = new URL(link.deep_link.replace('openid4vp://', 'https://x/'))
  const requestUri = u.searchParams.get('request_uri')
  const jarRes = await fetch(requestUri)
  const jarText = await jarRes.text()
  // The JAR is application/oauth-authz-req+jwt → just decode the payload.
  const req = decodeJwt(jarText.trim())
  console.log('half2 JAR parsed —', {
    clientId: req.client_id,
    responseUri: req.response_uri,
    responseMode: req.response_mode,
    state: req.state,
    nonce: req.nonce,
    hasDcql: !!req.dcql_query,
  })

  // Build SessionTranscript via the WebCrypto adapter.
  const ctx = makeCtx(privateKey)
  const sessionTranscript = await SessionTranscript.forOid4Vp({
    clientId: req.client_id,
    responseUri: req.response_uri,
    nonce: req.nonce,
  }, ctx)

  // Self-signed device cert (in node we can extract; mock wallet uses
  // non-extractable in browser).
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '01',
    subject: 'CN=Smoke Wallet',
    issuer: 'CN=Smoke Wallet',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 365 * 24 * 60 * 60_000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    signingKey: privateKey,
  })
  const derB64 = Buffer.from(cert.rawData).toString('base64')

  // Filter the credential.
  const issuerSignedFull = IssuerSigned.fromEncodedForOid4Vci(credentialB64)
  const namespace = issuerSignedFull.issuerNamespaces.issuerNamespaces.keys().next().value
  const mso = issuerSignedFull.issuerAuth.mobileSecurityObject
  const msoKey = mso.deviceKeyInfo.deviceKey
  console.log('half2 MSO:', {
    docType: mso.docType,
    namespace,
    deviceKeyAlg: msoKey?.algorithm,
    msoKeyX: msoKey?.x ? Buffer.from(msoKey.x).toString('hex').slice(0, 16) + '…' : null,
    walletKeyX: Buffer.from(Buffer.from(jwk.x, 'base64url')).toString('hex').slice(0, 16) + '…',
    keysMatch: msoKey?.x && Buffer.from(msoKey.x).equals(Buffer.from(jwk.x, 'base64url')),
  })
  const items = issuerSignedFull.getIssuerNamespace(namespace) ?? []
  // DCQL claims path is [namespace, claimName] for mdoc. Pick what the verifier asked for.
  const requested = (req.dcql_query?.credentials ?? [])
    .flatMap((c) => c.claims ?? [])
    .map((cl) => cl.path[cl.path.length - 1])
  const keep = new Set(requested)
  const filteredItems = keep.size === 0 ? items : items.filter((i) => keep.has(i.elementIdentifier))
  console.log('half2 filter — keep:', requested, 'kept items:', filteredItems.length, '/', items.length)
  // Option B: pass the full IssuerSigned (no filter) to isolate whether the
  // failure is digest-mismatch or signature-mismatch.
  const issuerSigned = process.env.NO_FILTER
    ? issuerSignedFull
    : IssuerSigned.create({
        issuerNamespaces: IssuerNamespaces.create({
          issuerNamespaces: new Map([[namespace, filteredItems]]),
        }),
        issuerAuth: issuerSignedFull.issuerAuth,
      })

  // Sign DeviceAuth.
  const signingKey = CoseKey.fromJwk(jwk)
  const deviceSigned = await new DeviceSignedBuilder(namespace, ctx).sign({
    signingKey,
    algorithm: SignatureAlgorithm.ES256,
    sessionTranscript,
    derCertificate: derB64,
  })

  const document = Document.create({ docType: namespace, issuerSigned, deviceSigned })
  const deviceResponse = DeviceResponse.createSimple({ documents: [document], status: 0 })
  const encoded = deviceResponse.encodedForOid4Vp

  // Find the DCQL id to key the response.
  const dcqlId = req.dcql_query?.credentials?.[0]?.id ?? 'default'
  const vpToken = JSON.stringify({ [dcqlId]: encoded })
  const formBody = new URLSearchParams({ vp_token: vpToken })
  if (req.state) formBody.set('state', req.state)

  // Local sanity: simulate the verifier's exact recompute path.
  // Rebuild SessionTranscript from JAR inputs, rebuild
  // DeviceAuthentication from the wire doc, then overwrite the detached
  // payload before verifying — this is exactly what
  // `Verifier.verifyDeviceResponse` does internally.
  {
    const verifierTranscript = await SessionTranscript.forOid4Vp({
      clientId: req.client_id,
      responseUri: req.response_uri,
      nonce: req.nonce,
    }, ctx)
    const doc = deviceResponse.documents[0]
    const verifierDeviceAuthBytes = DeviceAuthentication.create({
      sessionTranscript: verifierTranscript,
      docType: doc.docType,
      deviceNamespaces: doc.deviceSigned.deviceNamespaces,
    }).encode({ asDataItem: true })

    const sign1 = doc.deviceSigned.deviceAuth.deviceSignature
    const walletTbs = sign1.toBeSigned

    // Recompute what the toBeSigned WOULD be if we substituted the verifier's
    // deviceAuthenticationBytes for the detached payload.
    sign1.detachedPayload = verifierDeviceAuthBytes
    const verifierTbs = sign1.toBeSigned

    const sig = sign1.signature
    const deviceKey = doc.issuerSigned.issuerAuth.mobileSecurityObject.deviceKeyInfo.deviceKey
    const { x, y } = { x: deviceKey.x, y: deviceKey.y }
    const pub = new Uint8Array(1 + x.length + y.length)
    pub[0] = 0x04; pub.set(x, 1); pub.set(y, 1 + x.length)
    const ok = p256.verify(sig, sha256(verifierTbs), pub)
    console.log('half2 LOCAL verify (verifier recompute) — p256.verify:', ok)
    console.log('half2 walletTbs == verifierTbs?', Buffer.from(walletTbs).equals(Buffer.from(verifierTbs)))
    if (!Buffer.from(walletTbs).equals(Buffer.from(verifierTbs))) {
      console.log('  walletTbs len:', walletTbs.length, 'hex:', Buffer.from(walletTbs).toString('hex'))
      console.log('  verifierTbs len:', verifierTbs.length, 'hex:', Buffer.from(verifierTbs).toString('hex'))
    }
  }

  const responseUri = req.response_uri + '?details=1'
  console.log('half2 posting to', responseUri)
  const presentRes = await fetch(responseUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: formBody,
  })
  const presentText = await presentRes.text()
  console.log('half2 verifier:', presentRes.status, presentText.slice(0, 200))

  // Fetch the receipt to confirm.
  const recRes = await fetch(`${STAGING}/v1/sessions/${session.id}/receipt`, {
    headers: { Authorization: `Bearer ${API_KEY}` },
  })
  const rec = await recRes.json()
  console.log('half2 receipt:', recRes.status, JSON.stringify(rec).slice(0, 240))
}

async function main() {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
  const jwk = await exportJWK(publicKey)
  const thumbprint = await calculateJwkThumbprint(jwk)
  const credentialB64 = await half1Receive(privateKey, publicKey, jwk, thumbprint)
  await half2Present(credentialB64, privateKey, publicKey, jwk)
}

main().catch((e) => {
  console.error('FAIL:', e.message)
  console.error(e.stack)
  process.exit(1)
})
