// shares.mjs — sender side: create shares, add/replace files, manage the
// audience, revoke, delete. A Share = one 30440 scope whose payload is the
// manifest; grants deliver the scope key; the Grant Index is the ledger.

import { nip19 } from 'nostr-tools'
import {
  newScopeKey, publishScope, grant, rotateScope, deleteScope,
  saveGrantIndex, toIssuedEntry,
} from '../lib/nipxx.mjs'
import { newManifest, inlineFileEntry, inlineBytes, replaceFile } from '../shared/manifest.mjs'
import { state, $, esc, fmtSize, contactName, load, RELAYS } from './main.mjs'

// M1: files ride inline in the encrypted manifest — keep them small until
// the Blossom pipeline (M2) moves bodies to blob servers.
const INLINE_CAP = 48 * 1024

const syncIndex = () => saveGrantIndex(state.relay, state.signer, {
  ...state.myIndex,
  issued: state.myShares.filter(s => !s.draft).map(s => toIssuedEntry(s, s.grantees)),
})

function parsePub(input) {
  const s = input.trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase()
  const { type, data } = nip19.decode(s)
  if (type !== 'npub') throw new Error('not an npub')
  return data
}

const fileRow = (f) => `
  <div class="file" data-f="${esc(f.name)}">
    <span class="fname">${esc(f.name)}</span>
    <span class="fsize">${fmtSize(f.size)}</span>
    <button class="icon delfile" title="remove file">×</button>
  </div>`

function shareCard(s, i) {
  const m = s.manifest
  const chips = s.grantees.map(pk =>
    `<span class="chip" data-pub="${pk}">${esc(contactName(pk))}<button class="unshare" title="stop sharing (rotates key)">×</button></span>`
  ).join('') || '<span class="msg">shared with nobody yet</span>'
  const picker = state.contacts.filter(p => !s.grantees.includes(p)).slice(0, 8).map(pk =>
    `<option value="${nip19.npubEncode(pk)}">${esc(contactName(pk))}</option>`).join('')
  return `<div class="card" data-i="${i}">
    <div class="head">
      <div>
        <span class="name">${esc(s.scopeName)}</span>
        ${s.draft ? '<span class="badge stale">draft</span>' : `<span class="badge live">live · v${s.generation}</span>`}
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <span class="meta">${esc(s.scopeId)}</span>
        <button class="icon delshare" title="delete share (tombstone on relays)">🗑</button>
      </div>
    </div>
    ${m?.note ? `<div class="note">${esc(m.note)}</div>` : ''}
    <div class="files">${(m?.files ?? []).map(fileRow).join('') || '<span class="msg">no files yet</span>'}</div>
    <div class="drop">drop files here — or click to pick (≤48 KB each until blob support lands)</div>
    <input type="file" multiple style="display:none" class="fpick">
    <div class="sect2">shared with</div>
    <div class="chips">${chips}</div>
    <div class="actions">
      <input class="share-pub" list="contacts-${i}" placeholder="add by name or npub1…">
      <datalist id="contacts-${i}">${picker}</datalist>
      <button class="share">Share</button>
      <span class="msg act-msg"></span>
    </div>
  </div>`
}

export function renderMine() {
  $('mine').innerHTML = `
    <div class="newbar">
      <input id="ns-name" placeholder="new share name (e.g. Q3 board materials)">
      <button class="primary" id="ns-go">+ New share</button>
    </div>
    ${state.myShares.map(shareCard).join('') ||
      '<div class="empty">No shares yet. Name one above, drop files in, pick recipients.<br>Updates are free; unsharing actually revokes.</div>'}`

  $('ns-go').onclick = () => {
    const name = $('ns-name').value.trim()
    if (!name) return
    state.myShares.push({
      scopeId: 'nv' + crypto.getRandomValues(new Uint32Array(1))[0].toString(36),
      scopeName: name, generation: 1, scopeKey: newScopeKey(),
      grantees: [], publisher: state.me, draft: true, manifest: newManifest(name),
    })
    renderMine()
  }

  for (const card of document.querySelectorAll('#mine .card')) {
    const i = Number(card.dataset.i)
    const s = state.myShares[i]
    const msg = card.querySelector('.act-msg')
    const drop = card.querySelector('.drop')
    const pick = card.querySelector('.fpick')

    drop.onclick = () => pick.click()
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over') }
    drop.ondragleave = () => drop.classList.remove('over')
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); addFiles(s, e.dataTransfer.files, msg, card) }
    pick.onchange = () => addFiles(s, pick.files, msg, card)

    card.querySelector('.delshare').onclick = () => delShare(s, i, msg)
    card.querySelector('.share').onclick = () => shareWith(s, card.querySelector('.share-pub').value, msg)
    for (const un of card.querySelectorAll('.unshare'))
      un.onclick = (e) => unshare(s, e.target.closest('.chip').dataset.pub, msg)
    for (const df of card.querySelectorAll('.delfile'))
      df.onclick = async (e) => {
        const name = e.target.closest('.file').dataset.f
        s.manifest.files = s.manifest.files.filter(f => f.name !== name)
        await publish(s, msg)
      }
  }
}

async function publish(s, msg) {
  msg.textContent = 'publishing…'
  try {
    s.manifest.updated_at = Math.floor(Date.now() / 1000)
    await publishScope(state.relay, state.signer, { ...s, payload: s.manifest })
    const wasDraft = s.draft
    s.draft = false
    await syncIndex()
    msg.textContent = wasDraft ? 'live' :
      `updated — ${s.grantees.length} recipient${s.grantees.length === 1 ? '' : 's'} see this on next fetch`
    renderMine()
  } catch (err) { msg.textContent = err.message }
}

async function addFiles(s, fileList, msg, card) {
  for (const file of fileList) {
    if (file.size > INLINE_CAP) { msg.textContent = `${file.name}: over the 48 KB inline cap (blob support is next milestone)`; return }
    const bytes = new Uint8Array(await file.arrayBuffer())
    const entry = inlineFileEntry({ name: file.name, mime: file.type || 'application/octet-stream', bytes })
    if (s.manifest.files.some(f => f.name === file.name)) replaceFile(s.manifest, file.name, entry)
    else s.manifest.files.push(entry)
  }
  await publish(s, msg)
}

async function shareWith(s, input, msg) {
  if (s.draft) { msg.textContent = 'add a file first — publishing happens on first file drop'; return }
  try {
    const pub = parsePub(input)
    msg.textContent = 'delivering grant…'
    await grant(state.relay, state.signer, pub, { ...s, relayHint: RELAYS[0] })
    if (!s.grantees.includes(pub)) s.grantees.push(pub)
    await syncIndex()
    renderMine()
  } catch (err) { msg.textContent = err.message === 'not an npub' ? 'pick a contact or paste an npub' : err.message }
}

async function unshare(s, pub, msg) {
  if (!confirm(`Stop sharing "${s.scopeName}" with ${contactName(pub)}?\n\nThe key rotates and the ${s.grantees.length - 1} other recipient(s) are re-granted. They keep anything already downloaded — that is physics — but see nothing new.`)) return
  msg.textContent = 'rotating key…'
  try {
    const survivors = s.grantees.filter(p => p !== pub)
    const rotated = await rotateScope(state.relay, state.signer, {
      scopeId: s.scopeId, generation: s.generation, scopeName: s.scopeName,
      payload: s.manifest, survivors,
    })
    Object.assign(s, { generation: rotated.generation, scopeKey: rotated.scopeKey, grantees: survivors })
    await syncIndex()
    renderMine()
  } catch (err) { msg.textContent = err.message }
}

async function delShare(s, i, msg) {
  if (s.draft) { state.myShares.splice(i, 1); renderMine(); return }
  if (!confirm(`Delete "${s.scopeName}"?\n\nThe manifest on relays is replaced by an empty tombstone under a key nobody holds, plus a NIP-09 deletion request. Recipients keep anything already downloaded.`)) return
  msg.textContent = 'tombstoning…'
  try {
    await deleteScope(state.relay, state.signer, s)
    state.myShares.splice(i, 1)
    await syncIndex()
    renderMine()
  } catch (err) { msg.textContent = err.message }
}
