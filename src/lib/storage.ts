// IndexedDB wrapper for the mock wallet — device key and credential storage.
//
// Why a real persistence layer in a "mock" wallet:
//   The Variante C scenario we are testing requires that a credential issued
//   once can be presented on N subsequent verifier sessions, ideally across
//   browser reloads. localStorage isn't acceptable for a CryptoKey, and the
//   stored mdoc bytes can exceed a few kB so we don't want to round-trip JSON
//   in localStorage either. IndexedDB is the right primitive here.

import { openDB, type DBSchema, type IDBPDatabase } from 'idb'

const DB_NAME = 'tessaliq-mock-wallet'
const DB_VERSION = 1
const KEYS_STORE = 'keys'
const CREDENTIALS_STORE = 'credentials'

// Fixed slot for the single device key pair. The wallet only manages one
// device identity at a time in V1.
export const DEVICE_KEY_ID = 'device-key'

export type StoredCredential = {
  // Stable identifier (uuid v4 by convention).
  id: string
  // Only mdoc is supported in V1.
  format: 'mdoc'
  // mdoc namespace, e.g. 'eu.europa.ec.av.1'.
  namespace: string
  // Raw IssuerSigned bytes (CBOR) as returned by the issuer's
  // /v1/credential/issue endpoint.
  rawBytes: Uint8Array
  // Already-decoded claims for display purposes. Source of truth remains the
  // raw bytes; this is a cache.
  claims: Record<string, unknown>
  // Subject of the issuer's Document Signer certificate (for the UI).
  issuerCertSubject: string
  // Wall-clock timestamps. expiresAt may be null when the credential has no
  // notion of validity period.
  issuedAt: Date
  expiresAt: Date | null
  // Token Status List reference, if any (IETF draft-14).
  statusListUri: string | null
  statusListIndex: number | null
}

export type StoredKeyEntry = {
  id: typeof DEVICE_KEY_ID
  privateKey: CryptoKey
  publicKey: CryptoKey
  createdAt: Date
  // Self-signed DER-encoded X.509 certificate for the device public key.
  // Populated lazily by device-cert.ts the first time a presentation needs it.
  // @owf/mdoc's DeviceSignedBuilder embeds this in the COSE_Sign1 x5chain
  // unprotected header (RFC 9360). The verifier reads it for protocol
  // bookkeeping; trust is established via the MSO deviceKeyInfo.
  certDer?: Uint8Array
}

interface MockWalletDB extends DBSchema {
  [KEYS_STORE]: {
    key: string
    value: StoredKeyEntry
  }
  [CREDENTIALS_STORE]: {
    key: string
    value: StoredCredential
    indexes: { 'by-namespace': string }
  }
}

let dbPromise: Promise<IDBPDatabase<MockWalletDB>> | null = null

function getDb(): Promise<IDBPDatabase<MockWalletDB>> {
  if (!dbPromise) {
    dbPromise = openDB<MockWalletDB>(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(KEYS_STORE)) {
          db.createObjectStore(KEYS_STORE, { keyPath: 'id' })
        }
        if (!db.objectStoreNames.contains(CREDENTIALS_STORE)) {
          const store = db.createObjectStore(CREDENTIALS_STORE, {
            keyPath: 'id',
          })
          store.createIndex('by-namespace', 'namespace')
        }
      },
    })
  }
  return dbPromise
}

export async function getStoredKey(): Promise<StoredKeyEntry | undefined> {
  const db = await getDb()
  return db.get(KEYS_STORE, DEVICE_KEY_ID)
}

export async function putStoredKey(entry: StoredKeyEntry): Promise<void> {
  const db = await getDb()
  await db.put(KEYS_STORE, entry)
}

export async function listCredentials(): Promise<StoredCredential[]> {
  const db = await getDb()
  return db.getAll(CREDENTIALS_STORE)
}

export async function putCredential(credential: StoredCredential): Promise<void> {
  const db = await getDb()
  await db.put(CREDENTIALS_STORE, credential)
}

export async function deleteCredential(id: string): Promise<void> {
  const db = await getDb()
  await db.delete(CREDENTIALS_STORE, id)
}

// Test / dev helper: wipe everything. Not exposed in the production UI.
export async function resetDb(): Promise<void> {
  const db = await getDb()
  await Promise.all([db.clear(KEYS_STORE), db.clear(CREDENTIALS_STORE)])
}
