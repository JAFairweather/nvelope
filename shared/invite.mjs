// invite.mjs — bearer invite links (M3). An invite is a normal NIP-DA grant
// issued to a throwaway keypair I whose nsec rides ONLY in a URL fragment —
// never in a query string (no request line, no Referer), never on a relay,
// never persisted. Whoever holds the link holds the key. Claiming upgrades
// the bearer to a durable keypair R via a gift-wrapped claim request, and
// approval rotates every outstanding bearer key out of the scope — a link
// that has served its purpose is dead.
//
// DOM-free on purpose: test/invite.mjs drives this module directly.

import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, nip19, nip44, verifyEvent } from 'nostr-tools'
import { grant, localSigner, rotateScope } from '../lib/nipxx.mjs'

/** Claim requests are kind-14-shape rumors; they only ever exist inside a
 *  1059 gift wrap, so relays see neither the kind nor the claimer's pubkey. */
export const KIND_CLAIM = 14

const now = () => Math.floor(Date.now() / 1000)
const fuzz = () => now() - Math.floor(Math.random() * 2 * 24 * 60 * 60)
const asSigner = (s) => s instanceof Uint8Array ? localSigner(s) : s

// NIP-59 wrap/unwrap, same construction as the lib's internal grant delivery
// (the vendored lib doesn't export its helpers, so they are mirrored here —
// app code, not protocol surface).

export async function wrapRumor(signer, recipientPub, rumor) {
  rumor.id = getEventHash(rumor)
  const seal = await signer.signEvent({
    kind: 13, created_at: fuzz(), tags: [],
    content: await signer.nip44Encrypt(recipientPub, JSON.stringify(rumor)),
  })
  const ephemeral = generateSecretKey()
  return finalizeEvent({
    kind: 1059, created_at: fuzz(), tags: [['p', recipientPub]],
    content: nip44.v2.encrypt(JSON.stringify(seal),
      nip44.v2.utils.getConversationKey(ephemeral, recipientPub)),
  }, ephemeral)
}

export async function unwrapRumor(signer, wrap) {
  const seal = JSON.parse(await signer.nip44Decrypt(wrap.pubkey, wrap.content))
  if (seal.kind !== 13 || !verifyEvent(seal)) throw new Error('bad seal')
  const rumor = JSON.parse(await signer.nip44Decrypt(seal.pubkey, seal.content))
  if (rumor.pubkey !== seal.pubkey) throw new Error('seal/rumor pubkey mismatch')
  return rumor
}

// --- the link itself ---------------------------------------------------------

export const buildInviteUrl = (base, inviteSk, relays = []) =>
  `${base}#i=${nip19.nsecEncode(inviteSk)}` +
  (relays.length ? `&r=${encodeURIComponent(relays.join(','))}` : '')

/** Parse `#i=<nsec>&r=<relays>` → { sk, relays } or null. Pure — the caller
 *  is responsible for stripping the fragment from the URL bar immediately. */
export function parseInviteFragment(hash) {
  const m = /^#i=(nsec1[a-z0-9]+)(?:&r=([^&]+))?$/.exec(hash ?? '')
  if (!m) return null
  try {
    const { type, data } = nip19.decode(m[1])
    if (type !== 'nsec') return null
    return { sk: data, relays: m[2] ? decodeURIComponent(m[2]).split(',').filter(Boolean) : [] }
  } catch { return null }
}

// --- sender side --------------------------------------------------------------

/**
 * Mint a bearer grant: a fresh keypair I gets a normal grant to the share.
 * Returns { sk, pub }. The caller records `pub` in its invite ledger (an
 * app-level `nvelope_invites` field on the Grant Index — the index payload
 * is app-extensible JSON, no lib change) and builds the URL from `sk`,
 * which is then forgotten: the link is the only copy of the secret.
 */
export async function createInvite(relay, signer, share, relayHint = '') {
  const sk = generateSecretKey()
  const pub = getPublicKey(sk)
  await grant(relay, signer, pub, { ...share, relayHint })
  return { sk, pub }
}

/**
 * Find pending claim requests among the sender's gift wraps. A claim counts
 * only if its rumor is signed by a live (unclaimed) invite key for the scope
 * it names — possession of the link IS the credential; anything else is
 * noise or forgery and is dropped without comment.
 */
export async function pollClaims(relay, signer, invites) {
  const live = (invites ?? []).filter(i => !i.claimed_by)
  if (!live.length) return []
  const s = asSigner(signer)
  const wraps = await relay.query({ kinds: [1059], '#p': [await s.getPublicKey()] })
  const claims = []
  for (const wrap of wraps) {
    let rumor
    try { rumor = await unwrapRumor(s, wrap) } catch { continue }
    if (rumor.kind !== KIND_CLAIM) continue
    let body
    try { body = JSON.parse(rumor.content) } catch { continue }
    if (body?.nvelope_claim !== 1 || !/^[0-9a-f]{64}$/.test(body.r_pub ?? '')) continue
    if (!live.some(i => i.pub === rumor.pubkey && i.scope === body.scope)) continue
    if (claims.some(c => c.invitePub === rumor.pubkey && c.rPub === body.r_pub)) continue
    claims.push({ invitePub: rumor.pubkey, scope: body.scope, rPub: body.r_pub, requestedAt: rumor.created_at })
  }
  return claims
}

/**
 * Approve a claim: rotate the scope so R is in and EVERY outstanding bearer
 * key for it is out — bearer tokens don't outlive an upgrade, including
 * other unclaimed links to the same share. Survivors = all non-invite
 * grantees + R. Returns the rotation result plus the survivor list; the
 * caller updates its share record and invite ledger.
 */
export async function approveClaim(relay, signer, share, invites, claim) {
  const bearerPubs = (invites ?? [])
    .filter(i => i.scope === share.scopeId && !i.claimed_by).map(i => i.pub)
  const survivors = [
    ...share.grantees.filter(p => !bearerPubs.includes(p) && p !== claim.rPub),
    claim.rPub,
  ]
  const rotated = await rotateScope(relay, signer, {
    scopeId: share.scopeId, generation: share.generation, scopeName: share.scopeName,
    payload: share.manifest, survivors,
  })
  return { ...rotated, survivors, retired: bearerPubs }
}

// --- opener side ---------------------------------------------------------------

/**
 * From the link opener: ask the sender to move this bearer access onto the
 * durable pubkey rPub. Rides a gift wrap from I to the sender — the relay
 * sees an ephemeral pubkey delivering an opaque blob; rPub and the scope
 * are never exposed.
 */
export async function sendClaimRequest(relay, inviteSk, senderPub, scopeId, rPub) {
  const signer = localSigner(inviteSk)
  const rumor = {
    pubkey: getPublicKey(inviteSk),
    kind: KIND_CLAIM,
    created_at: now(),
    tags: [['p', senderPub]],
    content: JSON.stringify({ nvelope_claim: 1, scope: scopeId, r_pub: rPub }),
  }
  const wrap = await wrapRumor(signer, senderPub, rumor)
  return relay.publish(wrap)
}
