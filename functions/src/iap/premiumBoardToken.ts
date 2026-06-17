import { createHash } from 'node:crypto'

// Mirrors the iOS client's lib/iap.ts appAccountTokenForBoard: SHA256 of
// `winking-star-board:<boardId>` rendered as a v5-shaped UUID. The client sets
// this as the StoreKit appAccountToken at purchase, Apple records it on the
// transaction, and verifyPremiumUnlock reads it back from Apple's signed
// payload. The two derivations MUST stay byte-identical — any drift would make
// Apple's echoed token stop matching and reject every real purchase.
export function appAccountTokenForBoard(boardId: string): string {
  const hash = createHash('sha256')
    .update(`winking-star-board:${boardId}`)
    .digest('hex')
    .slice(0, 32)
    .split('')
  hash[12] = '5'
  hash[16] = ((parseInt(hash[16] || '0', 16) & 0x3) | 0x8).toString(16)
  const value = hash.join('')
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`
}

// Authoritative binding check for a premium unlock. The appAccountToken comes
// from Apple's signed transaction (un-spoofable by the client), so a token that
// resolves to THIS board proves the purchase was made for it.
//
// Apple renders the token uppercase (UUID.uuidString) while our derivation is
// lowercase, so the comparison is case-insensitive.
//
// Hardened 2026-06-17: a transaction with NO appAccountToken does NOT satisfy
// the binding. Premium unlock now requires a token that resolves to this board,
// so a purchase can never land on a board it was not made for, even on a replay
// or a transaction whose token is absent. (Previously a token-less transaction
// skipped the check and relied only on the claim-dedup.)
export function appAccountTokenMatchesBoard(
  appAccountToken: string | null | undefined,
  boardId: string,
): boolean {
  if (!appAccountToken) return false
  return appAccountToken.toLowerCase() === appAccountTokenForBoard(boardId)
}
