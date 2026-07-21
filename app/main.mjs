// main.mjs — Nvelope shell: sign-in via nave-connect (NIP-07 extension or
// NIP-46 bunker as the front door; the local key with its NIP-49 protect
// offer stays as a gated advanced path), tabs, shared state. shares.mjs
// renders "My shares" (sender side); receive.mjs renders "Shared with me"
// (recipient side). Pure client of NIP-DA.

import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import * as nip49 from 'nostr-tools/nip49'
import { LiveRelay } from '../lib/liverelay.mjs'
import { localSigner, receiveGrants, latestGrants, fetchScope, loadGrantIndex, fromIssuedEntry } from '../lib/nipxx.mjs'
import { nip07Signer, nip46Signer, serializeSession, parseSession, signerFromSession } from '../lib/nave-connect.mjs'
import { renderTitlebar, updateTitlebar } from '../lib/nave-titlebar.mjs'
import { parseInviteFragment, pollClaims } from '../shared/invite.mjs'
import { loadConfig } from '../shared/config.mjs'
import { renderMine } from './shares.mjs'
import { renderReceived } from './receive.mjs'
import { openInvite } from './invite.mjs'
import { renderSettings } from './settings.mjs'

// Bearer-link hygiene: if the fragment carries an invite secret, capture it
// and scrub the URL bar before anything else can observe location — it must
// never survive into history entries or be re-read later.
const inviteLink = parseInviteFragment(location.hash)
if (inviteLink) history.replaceState(null, '', location.pathname + location.search)

// Endpoints are per-device configuration (Settings tab), loaded once per page
// — saving settings reloads, so every module sees one consistent snapshot.
// Defaults live in shared/config.mjs; user overrides in localStorage.
export const config = loadConfig()
export const RELAYS = config.relays
export const SERVERS = config.servers.map(s => s.url)

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

const TABS = ['mine', 'received', 'settings']
function showTab(t) {
  for (const b of document.querySelectorAll('.tab')) b.classList.toggle('active', b.dataset.tab === t)
  for (const id of TABS) $(id).style.display = t === id ? '' : 'none'
  if (t === 'settings') renderSettings()
  location.hash = t
}
for (const b of document.querySelectorAll('.tab')) b.onclick = () => showTab(b.dataset.tab)

export async function login(signer, remember) {
  state.signer = signer
  try { state.me = await signer.getPublicKey() }   // nip46: first use → lazy bunker connect
  catch (err) {
    state.signer = null
    try { await signer.close?.() } catch { /* best effort */ }
    $('err').textContent = `sign-in failed: ${err.message}`
    return
  }
  // A passphrase-protected key is persisted ONLY as ncryptsec in localStorage;
  // sessionStorage keeps nothing for it (remember = null on the unlock path).
  if (remember) sessionStorage.setItem('nvelope-login', remember)
  state.relay ??= new LiveRelay(RELAYS)
  $('login').style.display = 'none'
  $('unlock').style.display = 'none'
  $('invite').style.display = 'none'
  $('tabs').style.display = 'flex'
  showTab(TABS.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'mine')
  updateTitlebar('#titlebar', {
    npub: nip19.npubEncode(state.me), kind: signer.kind,
    onRefresh: () => load(), onLogout: logout,
  })
  if (remember && parseSession(remember)?.kind === 'local') offerProtect(remember)
  load()
}

// --- NIP-49: passphrase-protected key at rest ---------------------------------
// The ncryptsec in localStorage is the ONLY persisted secret. NIP-07 keys
// never touch us; unprotected local keys live in sessionStorage for the tab
// session only (demo convenience) until the user takes the protect offer.

const NC_KEY = 'nvelope-ncryptsec'

function offerProtect(hex) {
  if (localStorage.getItem(NC_KEY) || sessionStorage.getItem('nvelope-no-protect')) return
  $('protect').style.display = 'flex'
  $('protect-go').onclick = async () => {
    const pass = $('protect-pass').value
    if (pass.length < 8) { $('protect-msg').textContent = 'use at least 8 characters'; return }
    $('protect-msg').textContent = 'encrypting key (scrypt — a second or two)…'
    await new Promise(r => setTimeout(r, 30))                // let the message paint
    const sk = Uint8Array.from(hex.match(/../g), h => parseInt(h, 16))
    localStorage.setItem(NC_KEY, nip49.encrypt(sk, pass))
    sessionStorage.removeItem('nvelope-login')               // ncryptsec replaces it
    $('protect-pass').value = ''
    $('protect').style.display = 'none'
    $('status').textContent = 'Key protected. Next visit asks for the passphrase; the nsec still works anywhere.'
  }
  $('protect-pass').onkeydown = (e) => { if (e.key === 'Enter') $('protect-go').onclick() }
  $('protect-skip').onclick = () => {
    sessionStorage.setItem('nvelope-no-protect', '1')
    $('protect').style.display = 'none'
  }
}

function showUnlock(ncryptsec) {
  $('login').style.display = 'none'
  $('unlock').style.display = ''
  $('unlock-pass').focus()
  $('unlock-go').onclick = async () => {
    $('unlock-err').textContent = 'decrypting (scrypt — a second or two)…'
    await new Promise(r => setTimeout(r, 30))
    try {
      const sk = nip49.decrypt(ncryptsec, $('unlock-pass').value)
      $('unlock-pass').value = ''
      login(keySigner(sk), null)                             // nothing new persisted
    } catch { $('unlock-err').textContent = 'wrong passphrase' }
  }
  $('unlock-pass').onkeydown = (e) => { if (e.key === 'Enter') $('unlock-go').onclick() }
  $('unlock-forget').onclick = () => {
    if (!confirm('Forget the protected key stored on this device?\n\nThis deletes the only local copy — make sure the nsec is written down; it is the only way back into this account.')) return
    localStorage.removeItem(NC_KEY)
    $('unlock').style.display = 'none'
    $('login').style.display = ''
  }
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

/** Print a paper recovery card: the nsec IS the account, and paper survives
 *  dead laptops. @media print CSS hides everything but the card. */
export function printKey(sk, what = 'account') {
  const nsec = nip19.nsecEncode(sk)
  const npub = nip19.npubEncode(getPublicKey(sk))
  $('printcard').innerHTML = `
    <h1>Nvelope recovery key</h1>
    <p>This key is the whole ${esc(what)} — there is no reset and no server copy.
       Sign in with the secret key on any device and everything reconstitutes:
       your shares, your audience, everything shared with you.</p>
    <div class="lbl">Secret key — keep this on paper, never in email or chat</div>
    <div class="k">${esc(nsec)}</div>
    <div class="lbl">Public key — safe to give out; people share to it</div>
    <div class="k">${esc(npub)}</div>
    <div class="foot">Printed ${new Date().toISOString().slice(0, 10)} ·
      nvelope — encrypted document sharing on nostr</div>`
  window.print()
  $('printcard').innerHTML = ''            // the key does not linger in the DOM
}

export const hexOf = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')

// nave-connect supplies nip07 + nip46; local keys stay on nipxx's localSigner.
// (The module's own localSigner has no nip44, and the Grant Index is NIP-44
// encrypted to self — signerFromSession returning null for `local` is the
// module telling the app to rebuild from its own key material.) Exported for
// the invite claim flow, which logs in with a freshly minted local key.
export function keySigner(sk) { return { kind: 'local', ...localSigner(sk) } }

// NIP-46: the bunker may want a one-time interactive approval — surface its
// auth_url as a link rather than window.open (popup blockers eat those).
function onAuthUrl(url) {
  $('bunker-auth').style.display = ''
  $('bunker-auth').innerHTML = `The bunker asks for a one-time approval:
    <a href="${esc(url)}" target="_blank" rel="noopener noreferrer">open its dashboard</a>,
    approve, then return here.`
}

$('bunker-go').onclick = async () => {
  const uri = $('bunker-uri').value.trim()
  if (!uri) { $('err').textContent = 'Paste the bunker:// URI from your remote signer first.'; return }
  $('err').textContent = 'connecting to the bunker over its relays… (approve there if asked)'
  $('bunker-go').disabled = true
  try {
    const signer = nip46Signer(uri, { onAuthUrl })
    await login(signer, serializeSession('nip46', { uri, clientSecretHex: signer.clientSecretHex }))
    if (state.me) { $('err').textContent = ''; $('bunker-auth').style.display = 'none' }
  } finally { $('bunker-go').disabled = false }
}
$('bunker-uri').onkeydown = (e) => { if (e.key === 'Enter') $('bunker-go').onclick() }

// The local key is deliberately not a headline option (Director, nact#16):
// it stays available, behind this explicit reveal.
$('advanced-toggle').onclick = () => {
  const open = $('advanced').style.display === 'none'
  $('advanced').style.display = open ? '' : 'none'
  $('advanced-toggle').textContent = open
    ? 'Hide the local-key option'
    : 'Advanced: use a local key in this tab (demo / recovery)'
  if (open) $('nsec').focus()
}

$('go').onclick = () => {
  try { const k = parseKey($('nsec').value); login(keySigner(k), hexOf(k)) }
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
  $('newkey-print').onclick = () => printKey(k)
  $('newkey-continue').onclick = () => login(keySigner(k), hexOf(k))
}
$('nip07').onclick = () => {
  if (!window.nostr?.nip44) { $('err').textContent = 'No NIP-07 extension found (needs nip44 support — Alby or nos2x).'; return }
  login(nip07Signer(), 'nip07')
}
function logout() {
  try { state.signer?.close?.() } catch { /* best effort */ }   // drop a live bunker pairing
  sessionStorage.removeItem('nvelope-login'); location.hash = ''; location.reload()
}

// The unified Nave title bar (nact#16): boots signed out (brand only — the
// login card in <main> is the sign-in affordance); login() flips it via
// updateTitlebar. Refresh / Log out / copy-npub live inside the component.
const NVELOPE_SEAL = `<svg viewBox="0 0 32 32" aria-hidden="true">
  <rect x="1" y="1" width="30" height="30" rx="7" fill="#0b0906" stroke="#9a83c0" stroke-opacity=".5" stroke-width="1.2"/>
  <g transform="translate(4 4)" fill="none" stroke="#9a83c0" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3.5" y="6" width="17" height="12" rx="1.5"/><path d="M4 7 L12 13 L20 7"/></g>
</svg>`
renderTitlebar('#titlebar', { appName: 'Nvelope', tagline: 'live folders, not stale attachments', sealSvg: NVELOPE_SEAL })

// Boot order: an invite link takes precedence over everything (the opener
// flow runs logged-out, bearer key in memory only); then any tab-session
// sign-in (nave-connect parses all three kinds — a bare-hex legacy remember
// still reads as `local`); then a protected key (ncryptsec present →
// passphrase prompt); else the login screen. nip46 remembers carry the
// bunker URI + client key, so a reload re-pairs the SAME bunker session
// without re-approval.
const saved = sessionStorage.getItem('nvelope-login')
const sess = parseSession(saved)
if (inviteLink) openInvite(inviteLink)
else if (sess?.kind === 'nip07') setTimeout(() => { if (window.nostr?.nip44) login(nip07Signer(), 'nip07') }, 250)
else if (sess?.kind === 'nip46') login(signerFromSession(sess, { onAuthUrl }), saved)
else if (sess?.kind === 'local') login(keySigner(parseKey(sess.hexKey)), saved)
else if (localStorage.getItem(NC_KEY)) showUnlock(localStorage.getItem(NC_KEY))
