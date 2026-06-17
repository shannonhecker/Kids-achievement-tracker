import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  appAccountTokenForBoard,
  appAccountTokenMatchesBoard,
} from './premiumBoardToken.js'

// Cross-repo contract. These UUIDs are exactly what the iOS client's
// lib/iap.ts appAccountTokenForBoard produces for the same boardId (SHA256 of
// `winking-star-board:<id>` rendered as a v5-shaped UUID). Apple echoes that
// token on the signed transaction and the server checks it here, so if the two
// derivations ever drift, every real purchase would be rejected. The literals
// are pinned so a derivation change breaks this test loudly.
test('appAccountTokenForBoard matches the iOS client derivation (pinned UUIDs)', () => {
  assert.equal(appAccountTokenForBoard('board-abc-123'), 'ddecd0b0-f17c-5b6c-ac31-a6a2c6b08437')
  assert.equal(appAccountTokenForBoard('family-7f3'), '7373ae3c-431b-5887-ac69-120e54e05d25')
  assert.equal(appAccountTokenForBoard('Z'), 'edce6670-8a8b-552e-9608-5cf4ecfc22fa')
})

test('appAccountTokenForBoard is deterministic and board-specific', () => {
  assert.equal(appAccountTokenForBoard('x'), appAccountTokenForBoard('x'))
  assert.notEqual(appAccountTokenForBoard('a'), appAccountTokenForBoard('b'))
})

test("appAccountTokenMatchesBoard accepts Apple's uppercase token for the right board", () => {
  // Apple renders appAccountToken uppercase (UUID.uuidString); ours is lowercase.
  const appleToken = appAccountTokenForBoard('board-abc-123').toUpperCase()
  assert.equal(appAccountTokenMatchesBoard(appleToken, 'board-abc-123'), true)
})

test('appAccountTokenMatchesBoard rejects a token minted for a different board', () => {
  const tokenForA = appAccountTokenForBoard('board-A')
  assert.equal(appAccountTokenMatchesBoard(tokenForA, 'board-B'), false)
})

test('appAccountTokenMatchesBoard rejects a transaction with no token (hardened)', () => {
  assert.equal(appAccountTokenMatchesBoard(null, 'board-abc-123'), false)
  assert.equal(appAccountTokenMatchesBoard(undefined, 'board-abc-123'), false)
  assert.equal(appAccountTokenMatchesBoard('', 'board-abc-123'), false)
})
