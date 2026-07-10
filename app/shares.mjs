// shares.mjs — sender side: create shares, add/replace files, manage the
// audience, revoke, delete. A Share = one 30440 scope whose payload is the
// manifest; grants deliver the scope key; the Grant Index is the ledger.

import { nip19 } from 'nostr-tools'
import {
  newScopeKey, publishScope, grant, rotateScope, deleteScope,
  saveGrantIndex, toIssuedEntry,
} from '../lib/nipxx.mjs'
import { newManifest, inlineFileEntry, blobFileEntry, replaceFile } from '../shared/manifest.mjs'
import { DEFAULT_SERVERS, newFileKey, encryptBlob, uploadBlob, deleteBlob } from '../shared/blossom.mjs'
import { state, $, esc, fmtSize, contactName, load, RELAYS } from './main.mjs'

// Files ≤48 KB ride inline in the encrypted manifest; bigger ones are
// padded, encrypted under a fresh filekey, and mirrored to Blossom.
const INLINE_CAP = 48 * 1024
const BLOB_CAP = 250 * 1048576
// Old ciphertext lingers this long after a replace/remove so recipients
// mid-download aren't cut off; then BUD-02 delete (best-effort — the timer
// only lives as long as this tab, and servers may GC on their own clock).
const GRACE_MS = 60_000

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

// --- blob pipeline -----------------------------------------------------------

// fetch can't report upload progress; XHR can. Same (url, opts) → Response
// shape uploadBlob expects, plus a per-request percentage callback.
const progressFetch = (onpct) => (url, opts = {}) => new Promise((resolve, reject) => {
  const xhr = new XMLHttpRequest()
  xhr.open(opts.method ?? 'GET', url)
  for (const [k, v] of Object.entries(opts.headers ?? {})) xhr.setRequestHeader(k, v)
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) onpct(url, e.loaded / e.total) }
  xhr.onload = () => resolve(new Response(xhr.response || null, { status: xhr.status }))
  xhr.onerror = () => reject(new Error('network error'))
  xhr.onabort = () => reject(new Error('timed out'))
  opts.signal?.addEventListener('abort', () => xhr.abort())
  xhr.send(opts.body)
})

/** Pad → encrypt under a fresh filekey → mirror upload, narrating into msg. */
async function uploadEntry(file, bytes, msg) {
  const filekey = newFileKey()
  msg.textContent = `${file.name}: encrypting ${fmtSize(bytes.length)}…`
  await new Promise(r => setTimeout(r))                    // let the message paint
  const cipher = encryptBlob(filekey, bytes)
  const pct = new Map()
  const desc = await uploadBlob(DEFAULT_SERVERS, state.signer, cipher, {
    fetchImpl: progressFetch((url, p) => {
      pct.set(url, p)
      msg.textContent = `${file.name}: uploading ${fmtSize(cipher.length)} — ` +
        [...pct].map(([u, x]) => `${new URL(u).host} ${Math.floor(x * 100)}%`).join(' · ')
    }),
  })
  return blobFileEntry({ name: file.name, mime: file.type || 'application/octet-stream',
    size: bytes.length, filekey, desc })
}

/** BUD-02 delete superseded ciphertext once the grace window passes. */
function scheduleBlobDelete(entries, why) {
  for (const f of entries) {
    if (!f?.sha256_cipher || !f.servers?.length) continue
    setTimeout(() => deleteBlob(f.servers, state.signer, f.sha256_cipher)
      .then(n => console.log(`nvelope: ${why} — blob ${f.sha256_cipher.slice(0, 12)}… deleted from ${n}/${f.servers.length} server(s)`))
      .catch(() => { /* best-effort; servers GC on their own clock */ }), GRACE_MS)
  }
}

// --- rendering ---------------------------------------------------------------

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
    <div class="drop">drop files here — or click to pick (up to 250 MB; big files upload encrypted to blob servers)</div>
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
        const removed = s.manifest.files.find(f => f.name === name)
        s.manifest.files = s.manifest.files.filter(f => f.name !== name)
        if (await publish(s, msg)) scheduleBlobDelete([removed], 'file removed')
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
    return true
  } catch (err) { msg.textContent = err.message; return false }
}

async function addFiles(s, fileList, msg, card) {
  const replaced = []                        // superseded blob entries → grace-window delete
  let added = 0
  for (const file of fileList) {
    if (file.size > BLOB_CAP) { msg.textContent = `${file.name}: over the 250 MB cap`; break }
    const bytes = new Uint8Array(await file.arrayBuffer())
    let entry
    try {
      entry = file.size > INLINE_CAP
        ? await uploadEntry(file, bytes, msg)
        : inlineFileEntry({ name: file.name, mime: file.type || 'application/octet-stream', bytes })
    } catch (err) { msg.textContent = `${file.name}: ${err.message}`; break }
    const prior = s.manifest.files.find(f => f.name === file.name)
    if (prior) { replaced.push(prior); replaceFile(s.manifest, file.name, entry) }
    else s.manifest.files.push(entry)
    added++
  }
  if (!added) return
  if (await publish(s, msg)) scheduleBlobDelete(replaced, 'file replaced')
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
  if (!confirm(`Delete "${s.scopeName}"?\n\nThe manifest on relays is replaced by an empty tombstone under a key nobody holds, plus a NIP-09 deletion request. Its encrypted blobs are deleted from the blob servers after a short grace window. Recipients keep anything already downloaded.`)) return
  msg.textContent = 'tombstoning…'
  try {
    await deleteScope(state.relay, state.signer, s)
    scheduleBlobDelete(s.manifest?.files ?? [], 'share deleted')
    state.myShares.splice(i, 1)
    await syncIndex()
    renderMine()
  } catch (err) { msg.textContent = err.message }
}
