// main.mjs — Nvelope shell: sign-in (NIP-07 or local key), tabs, shared state.
// shares.mjs renders "My shares" (sender side); receive.mjs renders
// "Shared with me" (recipient side). Pure client of NIP-DA.

import { generateSecretKey, nip19 } from 'nostr-tools'
import { LiveRelay } from '../lib/liverelay.mjs'
import { localSigner, receiveGrants, latestGrants, fetchScope, loadGrantIndex, fromIssuedEntry } from '../lib/nipxx.mjs'
import { parseInviteFragment, pollClaims } from '../shared/invite.mjs'
import { renderMine } from './shares.mjs'
import { renderReceived } from './receive.mjs'
import { openInvite } from './invite.mjs'

// Bearer-link hygiene: if the fragment carries an invite secret, capture it
// and scrub the URL bar before anything else can observe location — it must
// never survive into history entries or be re-read later.
const inviteLink = parseInviteFragment(location.hash)
if (inviteLink) history.replaceState(null, '', location.pathname + location.search)

export const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']

export const $ = (id) => document.getElementById(id)
export const esc = (s) => String(s).replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
export const short = (pk) => { const n = nip19.npubEncode(pk); return n.slice(0, 12) + '…' + n.slice(-4) }
export const fmtSize = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`

export const state = {
  relay: null, signer: null, me: null,
  myIndex: { issued: [], received: [] },
  myShares: [],          // { scopeId, scopeName, generation, scopeKey, grantees, manifest }
  incoming: [],          // { ...grantRecord, status, data? }
  pendingClaims: [],     // { invitePub, scope, rPub, requestedAt } awaiting approval
  profiles: new Map(),
  contacts: [],          // follows + grant counterparts, for the picker
}

function parseKey(input) {
  const s = input.trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return Uint8Array.from(s.match(/../g), h => parseInt(h, 16))
  const { type, data } = nip19.decode(s)
  if (type !== 'nsec') throw new Error('not an nsec')
  return data
}

function nip07Signer() {
  const n = window.nostr
  let pub = null
  return {
    getPublicKey: async () => (pub ??= await n.getPublicKey()),
    signEvent: (e) => n.signEvent(e),
    nip44Encrypt: (pk, pt) => n.nip44.encrypt(pk, pt),
    nip44Decrypt: (pk, ct) => n.nip44.decrypt(pk, ct),
  }
}

function showTab(t) {
  for (const b of document.querySelectorAll('.tab')) b.classList.toggle('active', b.dataset.tab === t)
  $('mine').style.display = t === 'mine' ? '' : 'none'
  $('received').style.display = t === 'received' ? '' : 'none'
  location.hash = t
}
for (const b of document.querySelectorAll('.tab')) b.onclick = () => showTab(b.dataset.tab)

export async function login(signer, remember) {
  state.signer = signer
  try { state.me = await signer.getPublicKey() }
  catch (err) { $('err').textContent = `extension refused: ${err.message}`; return }
  sessionStorage.setItem('nvelope-login', remember)
  state.relay ??= new LiveRelay(RELAYS)
  $('login').style.display = 'none'
  $('invite').style.display = 'none'
  $('me').style.display = 'flex'
  $('tabs').style.display = 'flex'
  showTab(location.hash === '#received' ? 'received' : 'mine')
  const npub = nip19.npubEncode(state.me)
  $('my-npub').textContent = npub.slice(0, 12) + '…' + npub.slice(-4)
  $('my-npub').onclick = () => navigator.clipboard.writeText(npub)
  load()
}

export async function load() {
  const { relay, signer, me } = state
  $('status').textContent = 'scanning relays for your shares, grants, and contacts…'
  try {
    const [index, grants, myLists] = await Promise.all([
      loadGrantIndex(relay, signer),
      receiveGrants(relay, signer),
      relay.query({ kinds: [3], authors: [me], limit: 2 }),
    ])
    state.myIndex = index
    const drafts = state.myShares.filter(s => s.draft)
    const [mine, incoming, pendingClaims] = await Promise.all([
      Promise.all(index.issued.map(async e => {
        const s = { ...fromIssuedEntry(e), publisher: me }
        const res = await fetchScope(relay, s)
        return { ...s, manifest: res.status === 'ok' ? res.data : null, lost: res.status !== 'ok' }
      })),
      Promise.all(latestGrants(grants).map(async g => ({ ...g, ...await fetchScope(relay, g) }))),
      pollClaims(relay, signer, index.nvelope_invites),
    ])
    state.myShares = [...mine, ...drafts]
    state.incoming = incoming
    state.pendingClaims = pendingClaims
    const follows = (myLists[0]?.tags ?? []).filter(t => t[0] === 'p').map(t => t[1])
    state.contacts = [...new Set([...follows, ...incoming.map(g => g.publisher),
      ...state.myShares.flatMap(s => s.grantees)])].filter(p => p !== me)
    state.profiles = new Map()
    if (state.contacts.length)
      for (const ev of await relay.query({ kinds: [0], authors: state.contacts, limit: state.contacts.length * 3 }))
        if (!state.profiles.has(ev.pubkey)) {
          try { state.profiles.set(ev.pubkey, JSON.parse(ev.content)) } catch { /* skip */ }
        }
    $('status').textContent =
      `${state.myShares.length} share${state.myShares.length === 1 ? '' : 's'} sent · ` +
      `${incoming.filter(i => i.status === 'ok').length} live share${incoming.filter(i => i.status === 'ok').length === 1 ? '' : 's'} with you. ` +
      (pendingClaims.length ? `${pendingClaims.length} link claim${pendingClaims.length === 1 ? '' : 's'} awaiting your approval. ` : '') +
      `Everything below is dereferenced live — nothing is a stored copy.`
    renderMine()
    renderReceived()
  } catch (err) { $('status').textContent = `relay error: ${err.message}` }
}

export const contactName = (pk) =>
  state.profiles.get(pk)?.display_name || state.profiles.get(pk)?.name || short(pk)

export const hexOf = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
$('go').onclick = () => {
  try { const k = parseKey($('nsec').value); login(localSigner(k), hexOf(k)) }
  catch { $('err').textContent = 'Expected nsec1… or 64 hex chars.' }
}
$('nsec').onkeydown = (e) => { if (e.key === 'Enter') $('go').onclick() }
$('gen').onclick = () => {
  // The key is shown in-page (selectable, with a Copy button) — an alert()
  // can't be copied, and this key is the only way back in.
  const k = generateSecretKey()
  $('err').textContent = ''
  $('newkey').style.display = ''
  $('newkey-nsec').textContent = nip19.nsecEncode(k)
  $('newkey-copy').onclick = async () => {
    await navigator.clipboard.writeText(nip19.nsecEncode(k))
    $('newkey-copy').textContent = 'Copied ✓'
    setTimeout(() => { $('newkey-copy').textContent = 'Copy' }, 2000)
  }
  $('newkey-continue').onclick = () => login(localSigner(k), hexOf(k))
}
$('nip07').onclick = () => {
  if (!window.nostr?.nip44) { $('err').textContent = 'No NIP-07 extension found (needs nip44 support — Alby or nos2x).'; return }
  login(nip07Signer(), 'nip07')
}
$('refresh').onclick = () => load()
$('logout').onclick = () => { sessionStorage.removeItem('nvelope-login'); location.hash = ''; location.reload() }

// An invite link takes precedence over any saved session: the opener flow
// runs logged-out, with the bearer key held in memory only.
const saved = sessionStorage.getItem('nvelope-login')
if (inviteLink) openInvite(inviteLink)
else if (saved === 'nip07') setTimeout(() => { if (window.nostr?.nip44) login(nip07Signer(), 'nip07') }, 250)
else if (saved) login(localSigner(Uint8Array.from(saved.match(/../g), h => parseInt(h, 16))), saved)
