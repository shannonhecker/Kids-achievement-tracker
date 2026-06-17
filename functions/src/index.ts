// Callable entry point for the F1 sheet-scan pipeline.
//
// Client (iOS app) calls this with a base64-encoded photo of the
// printed reward sheet plus the SheetMetadata (boardId, kidId,
// weekKey). The handler verifies the caller is a member of the board,
// loads the kid's activity list to know the grid dimensions, runs
// the CV pipeline, and returns the detection map for the confirm
// screen.

import { onCall, HttpsError } from 'firebase-functions/v2/https'
import { defineSecret } from 'firebase-functions/params'
import { initializeApp, getApps } from 'firebase-admin/app'
import { FieldValue, getFirestore } from 'firebase-admin/firestore'
import {
  Environment,
  SignedDataVerifier,
  VerificationException,
  type JWSTransactionDecodedPayload,
} from '@apple/app-store-server-library'
import { createPrivateKey, sign as signJwt } from 'node:crypto'
import { readFileSync } from 'node:fs'
import type { ScanRequest, SheetDetection } from './types.js'
import { appAccountTokenMatchesBoard } from './iap/premiumBoardToken.js'

if (!getApps().length) initializeApp()

const MAX_PHOTO_BYTES = 8 * 1024 * 1024
// IAP product ID. Originally `weekly_superstar_premium_unlock` was created in
// ASC with the wrong type (CONSUMABLE) and Apple does not allow type changes
// after creation. The replacement product `weekly_superstar_lifetime` was
// created as NON_CONSUMABLE (PR weekly-superstar-ios#158, 2026-05-26).
// The client now sends the new ID; the server must validate against it.
//
// The OLD id has not been released to any production user — no in-flight
// purchases need backwards-compat allowlisting. The stale ASC record is
// being deprecated after the new IAP's first approval.
const PREMIUM_PRODUCT_ID = 'weekly_superstar_lifetime'
const APP_BUNDLE_ID = 'com.winkingstar.app'
const APP_APPLE_ID = 6765767262
const APPLE_PRODUCTION_API = 'https://api.storekit.apple.com'
const APPLE_SANDBOX_API = 'https://api.storekit-sandbox.apple.com'
const APPLE_ROOT_CERTIFICATE_PATHS = [
  '../certs/apple-root/AppleIncRootCertificate.cer',
  '../certs/apple-root/AppleRootCA-G2.cer',
  '../certs/apple-root/AppleRootCA-G3.cer',
]

const APP_STORE_ISSUER_ID = defineSecret('APP_STORE_ISSUER_ID')
const APP_STORE_KEY_ID = defineSecret('APP_STORE_KEY_ID')
const APP_STORE_PRIVATE_KEY = defineSecret('APP_STORE_PRIVATE_KEY')

interface KidDoc {
  activities?: Array<{ id?: string }>
}

interface BoardDoc {
  memberIds?: string[]
}

interface VerifyPremiumUnlockRequest {
  boardId?: unknown
  productId?: unknown
  transactionId?: unknown
  environment?: unknown
}

interface VerifyPremiumUnlockResponse {
  premium: boolean
}

interface AppleTransactionInfo {
  appAccountToken?: string
  bundleId?: string
  environment?: string
  inAppOwnershipType?: string
  originalTransactionId?: string
  productId?: string
  purchaseDate?: number
  revocationDate?: number
  signedDate?: number
  transactionId?: string
  type?: string
}

interface RedeemShareCodeRequest {
  code?: unknown
}

interface RedeemShareCodeResponse {
  boardId: string
}

function base64Url(input: Buffer | string) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

function appleSecret(value: string, label: string) {
  if (!value) {
    throw new HttpsError('failed-precondition', `${label} is not configured`)
  }
  return value
}

function createAppStoreServerJwt() {
  const keyId = appleSecret(APP_STORE_KEY_ID.value(), 'APP_STORE_KEY_ID')
  const issuerId = appleSecret(APP_STORE_ISSUER_ID.value(), 'APP_STORE_ISSUER_ID')
  const privateKeyValue = appleSecret(APP_STORE_PRIVATE_KEY.value(), 'APP_STORE_PRIVATE_KEY')
    .replace(/\\n/g, '\n')

  const now = Math.floor(Date.now() / 1000)
  const header = base64Url(JSON.stringify({ alg: 'ES256', kid: keyId, typ: 'JWT' }))
  const payload = base64Url(
    JSON.stringify({
      iss: issuerId,
      iat: now,
      exp: now + 10 * 60,
      aud: 'appstoreconnect-v1',
      bid: APP_BUNDLE_ID,
    }),
  )
  const body = `${header}.${payload}`
  const signature = signJwt('sha256', Buffer.from(body), {
    key: createPrivateKey(privateKeyValue),
    dsaEncoding: 'ieee-p1363',
  })
  return `${body}.${base64Url(signature)}`
}

function preferredAppleEnvironments(rawEnvironment: unknown) {
  const env = typeof rawEnvironment === 'string' ? rawEnvironment.toLowerCase() : ''
  if (env === 'sandbox') return [APPLE_SANDBOX_API, APPLE_PRODUCTION_API]
  if (env === 'production') return [APPLE_PRODUCTION_API, APPLE_SANDBOX_API]
  return [APPLE_PRODUCTION_API, APPLE_SANDBOX_API]
}

let cachedAppleRootCertificates: Buffer[] | null = null

function appleRootCertificates() {
  cachedAppleRootCertificates ??= APPLE_ROOT_CERTIFICATE_PATHS.map((path) =>
    readFileSync(new URL(path, import.meta.url)),
  )
  return cachedAppleRootCertificates
}

function appleEnvironmentForApiBaseUrl(apiBaseUrl: string) {
  return apiBaseUrl === APPLE_SANDBOX_API ? Environment.SANDBOX : Environment.PRODUCTION
}

function productionAppAppleId() {
  return APP_APPLE_ID
}

async function verifyAppleTransactionJws(
  signedTransactionInfo: string,
  environment: Environment,
): Promise<JWSTransactionDecodedPayload> {
  const verifier = new SignedDataVerifier(
    appleRootCertificates(),
    true,
    environment,
    APP_BUNDLE_ID,
    environment === Environment.PRODUCTION ? productionAppAppleId() : undefined,
  )

  try {
    return await verifier.verifyAndDecodeTransaction(signedTransactionInfo)
  } catch (err) {
    if (err instanceof VerificationException) {
      throw new HttpsError('permission-denied', 'Apple transaction signature could not be verified')
    }
    throw err
  }
}

async function fetchAppleTransaction(
  transactionId: string,
  apiBaseUrl: string,
): Promise<AppleTransactionInfo | null> {
  const jwt = createAppStoreServerJwt()
  const response = await fetch(
    `${apiBaseUrl}/inApps/v1/transactions/${encodeURIComponent(transactionId)}`,
    {
      method: 'GET',
      headers: { Authorization: `Bearer ${jwt}` },
    },
  )

  if (response.status === 400 || response.status === 404) return null
  if (!response.ok) {
    throw new HttpsError(
      'failed-precondition',
      `Apple transaction validation failed (${response.status})`,
    )
  }

  const body = (await response.json()) as { signedTransactionInfo?: unknown }
  if (typeof body.signedTransactionInfo !== 'string') {
    throw new HttpsError('failed-precondition', 'Apple transaction response missing signed info')
  }
  return verifyAppleTransactionJws(
    body.signedTransactionInfo,
    appleEnvironmentForApiBaseUrl(apiBaseUrl),
  )
}

async function lookupAppleTransaction(
  transactionId: string,
  environment: unknown,
): Promise<AppleTransactionInfo> {
  for (const apiBaseUrl of preferredAppleEnvironments(environment)) {
    const transaction = await fetchAppleTransaction(transactionId, apiBaseUrl)
    if (transaction) return transaction
  }
  throw new HttpsError('not-found', 'Apple transaction not found')
}

function transactionIdFromPayload(data: VerifyPremiumUnlockRequest) {
  if (typeof data.transactionId === 'string' && data.transactionId.length > 0) {
    return data.transactionId
  }
  throw new HttpsError('invalid-argument', 'transactionId missing')
}

export const verifyPremiumUnlock = onCall<
  VerifyPremiumUnlockRequest,
  Promise<VerifyPremiumUnlockResponse>
>(
  {
    region: 'us-central1',
    cors: true,
    secrets: [APP_STORE_ISSUER_ID, APP_STORE_KEY_ID, APP_STORE_PRIVATE_KEY],
  },
  async (request) => {
    const uid = request.auth?.uid
    if (!uid) throw new HttpsError('unauthenticated', 'sign-in required')

    const data = request.data
    if (!data || typeof data !== 'object') {
      throw new HttpsError('invalid-argument', 'missing payload')
    }
    if (data.productId !== PREMIUM_PRODUCT_ID) {
      throw new HttpsError('invalid-argument', 'unexpected product')
    }
    if (typeof data.boardId !== 'string' || data.boardId.length === 0) {
      throw new HttpsError('invalid-argument', 'boardId missing')
    }

    const db = getFirestore()
    const boardRef = db.collection('boards').doc(data.boardId)
    const boardSnap = await boardRef.get()
    if (!boardSnap.exists) throw new HttpsError('not-found', 'board not found')
    const board = boardSnap.data() as BoardDoc
    if (!board.memberIds?.includes(uid)) {
      throw new HttpsError('permission-denied', 'not a member of this board')
    }

    const transactionId = transactionIdFromPayload(data)
    const transaction = await lookupAppleTransaction(transactionId, data.environment)
    if (transaction.bundleId !== APP_BUNDLE_ID) {
      throw new HttpsError('permission-denied', 'transaction belongs to a different app')
    }
    if (transaction.productId !== PREMIUM_PRODUCT_ID) {
      throw new HttpsError('invalid-argument', 'transaction product mismatch')
    }
    if (transaction.type !== 'Non-Consumable') {
      throw new HttpsError('failed-precondition', 'transaction is not a non-consumable')
    }
    if (transaction.revocationDate) {
      throw new HttpsError('failed-precondition', 'purchase has been revoked')
    }
    // Authoritative binding: the purchase must carry an appAccountToken (from
    // Apple's signed transaction) that resolves to THIS board. Token-absent or
    // wrong-board transactions are refused, so a purchase can never unlock a
    // board it was not made for.
    if (!appAccountTokenMatchesBoard(transaction.appAccountToken, data.boardId)) {
      throw new HttpsError('permission-denied', 'purchase is linked to another family board')
    }

    const originalTransactionId = transaction.originalTransactionId || transaction.transactionId
    if (!originalTransactionId) {
      throw new HttpsError('failed-precondition', 'Apple transaction missing original id')
    }
    const claimRef = db.collection('iapTransactions').doc(`apple_${originalTransactionId}`)

    await db.runTransaction(async (tx) => {
      const claimSnap = await tx.get(claimRef)
      const claim = claimSnap.exists ? claimSnap.data() : null
      if (claim?.boardId && claim.boardId !== data.boardId) {
        throw new HttpsError('already-exists', 'purchase is already linked to another family board')
      }

      tx.set(
        claimRef,
        {
          boardId: data.boardId,
          claimedBy: uid,
          environment: transaction.environment ?? null,
          inAppOwnershipType: transaction.inAppOwnershipType ?? null,
          originalTransactionId,
          productId: PREMIUM_PRODUCT_ID,
          purchaseDate: transaction.purchaseDate ?? null,
          signedDate: transaction.signedDate ?? null,
          transactionId: transaction.transactionId ?? transactionId,
          updatedAt: FieldValue.serverTimestamp(),
        },
        { merge: true },
      )
      tx.update(boardRef, {
        premium: true,
        premiumProductId: PREMIUM_PRODUCT_ID,
        premiumOriginalTransactionId: originalTransactionId,
        premiumTransactionId: transaction.transactionId ?? transactionId,
        premiumUnlockedAt: FieldValue.serverTimestamp(),
        premiumUnlockedBy: uid,
        premiumSource: 'apple',
        premiumEnvironment: transaction.environment ?? null,
      })
    })

    return { premium: true }
  },
)

export const scanSheet = onCall<ScanRequest, Promise<SheetDetection>>(
  {
    region: 'us-central1',
    memory: '1GiB',
    timeoutSeconds: 60,
    cors: true,
  },
  async (request) => {
    const uid = request.auth?.uid
    if (!uid) throw new HttpsError('unauthenticated', 'sign-in required')

    const data = request.data
    if (!data || typeof data !== 'object') throw new HttpsError('invalid-argument', 'missing payload')
    if (typeof data.photoBase64 !== 'string' || data.photoBase64.length === 0) {
      throw new HttpsError('invalid-argument', 'photoBase64 missing')
    }
    if (data.photoBase64.length > MAX_PHOTO_BYTES * 1.4) {
      throw new HttpsError('invalid-argument', 'photo too large — downscale before upload')
    }
    if (!data.meta || typeof data.meta !== 'object') {
      throw new HttpsError('invalid-argument', 'meta missing')
    }
    const { boardId, kidId, weekKey } = data.meta
    if (typeof boardId !== 'string' || typeof kidId !== 'string' || typeof weekKey !== 'string') {
      throw new HttpsError('invalid-argument', 'meta fields must be strings')
    }

    const db = getFirestore()

    const boardSnap = await db.collection('boards').doc(boardId).get()
    if (!boardSnap.exists) throw new HttpsError('not-found', 'board not found')
    const board = boardSnap.data() as BoardDoc
    if (!board.memberIds?.includes(uid)) {
      throw new HttpsError('permission-denied', 'not a member of this board')
    }

    const kidSnap = await db.collection('boards').doc(boardId).collection('kids').doc(kidId).get()
    if (!kidSnap.exists) throw new HttpsError('not-found', 'kid not found')
    const kid = kidSnap.data() as KidDoc
    const activityIds: string[] = (kid.activities ?? [])
      .map((a) => a.id)
      .filter((id): id is string => typeof id === 'string' && id.length > 0)

    if (activityIds.length === 0) {
      return { detections: {}, confidence: {} }
    }

    try {
      const { processSheetPhoto } = await import('./sheet-scan.js')
      return await processSheetPhoto(data, activityIds)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'scan failed'
      throw new HttpsError('failed-precondition', message)
    }
  },
)

export const redeemShareCode = onCall<RedeemShareCodeRequest, Promise<RedeemShareCodeResponse>>(
  {
    region: 'us-central1',
    cors: true,
  },
  async (request) => {
    const uid = request.auth?.uid
    if (!uid) throw new HttpsError('unauthenticated', 'sign-in required')

    const provider = request.auth?.token.firebase?.sign_in_provider
    if (provider === 'anonymous') {
      throw new HttpsError('failed-precondition', 'create or sign in to a parent account first')
    }

    const rawCode = request.data?.code
    if (typeof rawCode !== 'string') {
      throw new HttpsError('invalid-argument', 'invite code missing')
    }
    const code = rawCode.trim().toLowerCase()
    if (!/^[a-z0-9-]{5,40}$/.test(code)) {
      throw new HttpsError('invalid-argument', 'invite code invalid')
    }

    const db = getFirestore()
    const snap = await db
      .collection('boards')
      .where('shareCode', '==', code)
      .limit(1)
      .get()

    if (snap.empty) {
      throw new HttpsError('not-found', 'invite link expired')
    }

    const boardDoc = snap.docs[0]
    const board = boardDoc.data() as BoardDoc
    if (!Array.isArray(board.memberIds) || !board.memberIds.includes(uid)) {
      await boardDoc.ref.update({
        memberIds: FieldValue.arrayUnion(uid),
      })
    }

    return { boardId: boardDoc.id }
  },
)

export { createCheckoutSession } from './stripe/createCheckoutSession.js'
export { stripeWebhookHandler } from './stripe/stripeWebhookHandler.js'
export { appleServerNotification } from './apple/appleServerNotification.js'
