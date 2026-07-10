// shares.mjs — sender side: create shares, add/replace files, manage the
// audience, revoke, delete. A Share = one 30440 scope whose payload is the
// manifest; grants deliver the scope key; the Grant Index is the ledger.

import { nip19 } from 'nostr-tools'
import {
  newScopeKey, publishScope, grant, rotateScope, deleteScope,
  saveGrantIndex, toIssuedEntry,
} from '../lib/nipxx.mjs'
import { newManifest, inlineFileEntry, blobFileEntry, replaceFile } from '../shared/manifest.mjs'
import { newFileKey, encryptBlob, uploadBlob, deleteBlob } from '../shared/blossom.mjs'
import { buildInviteUrl, createInvite, approveClaim } from '../shared/invite.mjs'
import { scrubShare, scrubBytes, scrubSeconds } from '../shared/scrub.mjs'
import { state, $, esc, fmtSize, contactName, short, load, RELAYS, SERVERS, config } from './main.mjs'

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

// Bearer-link ledger: which grantee pubkeys are invite keys. An app-level
// `nvelope_invites` field on the Grant Index — the index payload is
// app-extensible JSON, so the flag persists without touching lib/.
const invitesOf = (scopeId) => (state.myIndex.nvelope_invites ?? []).filter(v => v.scope === scopeId)
const setInvites = (list) => { state.myIndex.nvelope_invites = list }

// Named share URLs (M5 seam): an optional friendly alias per share, stored
// app-level in the Grant Index like nvelope_invites (encrypted to self,
// device-independent). RESOLVING an alias to a public URL needs a naming
// service (DNS or a hosted directory) — a paid-tier concern, out of scope;
// see README. Here it names the share and labels its bearer links.
const aliasOf = (scopeId) => (state.myIndex.nvelope_aliases ?? {})[scopeId]
const setAlias = (scopeId, alias) => {
  const map = { ...(state.myIndex.nvelope_aliases ?? {}) }
  if (alias) map[scopeId] = alias; else delete map[scopeId]
  state.myIndex.nvelope_aliases = map
}

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

// The managed-endpoint seam: a 401/402/403 is a server demanding an account
// or payment — actionable, not mysterious. BUD-01 auth is already signed on
// every request; what's missing is provisioning, which lives outside Nvelope.
function explainFailure(f) {
  const host = (() => { try { return new URL(f.server).host } catch { return f.server } })()
  const managed = config.servers.find(x => x.url === f.server)?.requiresAuth
  const fix = managed
    ? 'it is marked managed — provision your account/payment with the operator, then retry'
    : 'configure a managed server you have access to, or remove it in Settings'
  if (f.status === 402) return `${host}: requires payment — ${fix}`
  if (f.status === 401 || f.status === 403) return `${host}: requires auth beyond the signed BUD-01 event — ${fix}`
  if (f.status === 415) return `${host}: refuses ciphertext uploads — replace it in Settings`
  if (f.status === 413) return `${host}: blob too large for this server — a managed server would raise the cap`
  return `${host}: ${f.message}`
}

/** Pad → encrypt under a fresh filekey → mirror upload, narrating into msg.
 *  Returns { entry, failures } — partial-mirror failures surface per server. */
async function uploadEntry(file, bytes, msg) {
  const filekey = newFileKey()
  msg.textContent = `${file.name}: encrypting ${fmtSize(bytes.length)}…`
  await new Promise(r => setTimeout(r))                    // let the message paint
  const cipher = encryptBlob(filekey, bytes)
  const pct = new Map()
  const desc = await uploadBlob(SERVERS, state.signer, cipher, {
    fetchImpl: progressFetch((url, p) => {
      pct.set(url, p)
      msg.textContent = `${file.name}: uploading ${fmtSize(cipher.length)} — ` +
        [...pct].map(([u, x]) => `${new URL(u).host} ${Math.floor(x * 100)}%`).join(' · ')
    }),
  })
  return {
    entry: blobFileEntry({ name: file.name, mime: file.type || 'application/octet-stream',
      size: bytes.length, filekey, desc }),
    failures: desc.failures ?? [],
  }
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

// Storage-quota surfacing (M5): what a share actually occupies on the blob
// servers is the PADDED ciphertext, not the file sizes — that is the number
// a storage quota (free or managed) would meter.
function quotaLine(m) {
  const blobs = (m?.files ?? []).filter(f => f.servers?.length)
  if (!blobs.length) return ''
  const hosts = [...new Set(blobs.flatMap(f => f.servers))]
    .map(u => { try { return new URL(u).host } catch { return u } })
  return `<div class="quota">${fmtSize(scrubBytes(m))} padded ciphertext ·
    ${blobs.length} blob${blobs.length === 1 ? '' : 's'} on ${esc(hosts.join(', '))}</div>`
}

function shareCard(s, i) {
  const m = s.manifest
  const invites = invitesOf(s.scopeId)
  const bearer = new Set(invites.filter(v => !v.claimed_by).map(v => v.pub))
  const claimedVia = new Set(invites.map(v => v.claimed_by).filter(Boolean))
  const chips = s.grantees.map(pk => bearer.has(pk)
    ? `<span class="chip invite" data-pub="${pk}" title="bearer link — anyone holding the URL can open this share">invite link · ${esc(short(pk))}<button class="unshare" title="revoke this link (rotates key)">×</button></span>`
    : `<span class="chip" data-pub="${pk}"${claimedVia.has(pk) ? ' title="claimed via invite link"' : ''}>${esc(contactName(pk))}<button class="unshare" title="stop sharing (rotates key)">×</button></span>`
  ).join('') || '<span class="msg">shared with nobody yet</span>'
  const pend = state.pendingClaims.filter(c => c.scope === s.scopeId)
  const claims = pend.map(c =>
    `<span class="chip claim" data-r="${c.rPub}" data-inv="${c.invitePub}" title="someone opened your link and wants durable access on their own key">claim from ${esc(short(c.rPub))}<button class="approve">Approve</button></span>`
  ).join('')
  const picker = state.contacts.filter(p => !s.grantees.includes(p)).slice(0, 8).map(pk =>
    `<option value="${nip19.npubEncode(pk)}">${esc(contactName(pk))}</option>`).join('')
  return `<div class="card" data-i="${i}">
    <div class="head">
      <div>
        <span class="name">${esc(s.scopeName)}</span>
        ${s.draft ? '<span class="badge stale">draft</span>' : `<span class="badge live">live · v${s.generation}</span>`}
        <button class="aliasbtn${aliasOf(s.scopeId) ? ' set' : ''}"
          title="a friendly name for this share, kept in your encrypted Grant Index — resolving it as a public URL is a hosted-tier service, not part of this app">${
          aliasOf(s.scopeId) ? `/${esc(aliasOf(s.scopeId))}` : '+ alias'}</button>
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <span class="meta">${esc(s.scopeId)}</span>
        <button class="icon delshare" title="delete share (tombstone on relays)">🗑</button>
      </div>
    </div>
    ${m?.note ? `<div class="note">${esc(m.note)}</div>` : ''}
    <div class="files">${(m?.files ?? []).map(fileRow).join('') || '<span class="msg">no files yet</span>'}</div>
    ${quotaLine(m)}
    ${(s.warnings ?? []).map(w => `<div class="upwarn">⚠ ${esc(w)}</div>`).join('')}
    <div class="drop">drop files here — or click to pick (up to 250 MB; big files upload encrypted to blob servers)</div>
    <input type="file" multiple style="display:none" class="fpick">
    <div class="sect2">shared with</div>
    <div class="chips">${chips}</div>
    ${claims ? `<div class="sect2">pending claims</div><div class="chips">${claims}</div>` : ''}
    <div class="actions">
      <input class="share-pub" list="contacts-${i}" placeholder="add by name or npub1…">
      <datalist id="contacts-${i}">${picker}</datalist>
      <button class="share">Share</button>
      <button class="bylink" title="mint a bearer URL — anyone holding it can open this share until it is claimed or revoked">Share by link</button>
      <span class="msg act-msg"></span>
    </div>
    ${s.inviteUrl ? `<div class="invite-out">
      <div class="phrase">${esc(s.inviteUrl)}</div>
      <div class="actions"><button class="copylink">Copy link</button>
        <span class="msg">Copy it now — it is not stored anywhere. Anyone with this URL can open
        the share until it is claimed or you revoke the link chip above.</span></div>
      ${aliasOf(s.scopeId) ? `<div class="msg">This share is named “/${esc(aliasOf(s.scopeId))}”, but a
        friendly URL that resolves to this link needs a naming service (DNS or a hosted
        directory) — a paid-tier concern, out of scope here. Share the URL above.</div>` : ''}
    </div>` : ''}
  </div>`
}

export function renderMine() {
  const totalBytes = state.myShares.reduce((n, s) => n + scrubBytes(s.manifest), 0)
  const totalBlobs = state.myShares.reduce((n, s) =>
    n + (s.manifest?.files ?? []).filter(f => f.servers?.length).length, 0)
  $('mine').innerHTML = `
    <div class="newbar">
      <input id="ns-name" placeholder="new share name (e.g. Q3 board materials)">
      <button class="primary" id="ns-go">+ New share</button>
    </div>
    ${totalBlobs ? `<div class="quota total">blob storage in use: <b>${fmtSize(totalBytes)}</b> padded ciphertext
      across ${totalBlobs} blob${totalBlobs === 1 ? '' : 's'} — public servers make no persistence
      promise (see Settings)</div>` : ''}
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
    card.querySelector('.aliasbtn').onclick = () => editAlias(s, msg)
    card.querySelector('.share').onclick = () => shareWith(s, card.querySelector('.share-pub').value, msg)
    card.querySelector('.bylink').onclick = () => shareByLink(s, msg)
    const cp = card.querySelector('.copylink')
    if (cp) cp.onclick = async () => {
      await navigator.clipboard.writeText(s.inviteUrl)
      cp.textContent = 'Copied ✓'
      setTimeout(() => { cp.textContent = 'Copy link' }, 2000)
    }
    for (const ap of card.querySelectorAll('.approve'))
      ap.onclick = (e) => {
        const chip = e.target.closest('.chip')
        const claim = state.pendingClaims.find(c =>
          c.scope === s.scopeId && c.rPub === chip.dataset.r && c.invitePub === chip.dataset.inv)
        if (claim) approve(s, claim, msg)
      }
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
  const warnings = []                        // per-server refusals, distinct and actionable
  let added = 0
  for (const file of fileList) {
    if (file.size > BLOB_CAP) { msg.textContent = `${file.name}: over the 250 MB cap`; break }
    const bytes = new Uint8Array(await file.arrayBuffer())
    let entry
    try {
      if (file.size > INLINE_CAP) {
        const up = await uploadEntry(file, bytes, msg)
        entry = up.entry
        for (const f of up.failures)
          warnings.push(`${file.name}: mirrored to ${entry.servers.length}/${SERVERS.length} — ${explainFailure(f)}`)
      } else {
        entry = inlineFileEntry({ name: file.name, mime: file.type || 'application/octet-stream', bytes })
      }
    } catch (err) { msg.textContent = `${file.name}: ${err.message}`; break }
    const prior = s.manifest.files.find(f => f.name === file.name)
    if (prior) { replaced.push(prior); replaceFile(s.manifest, file.name, entry) }
    else s.manifest.files.push(entry)
    added++
  }
  s.warnings = warnings                      // session-only; next drop resets it
  if (!added) return
  if (await publish(s, msg)) scheduleBlobDelete(replaced, 'file replaced')
}

/** Set/clear a share's friendly name. Stored in the Grant Index (encrypted
 *  to self); shown here and on the invite reveal. Not a URL — see README. */
async function editAlias(s, msg) {
  const raw = prompt(
    'Friendly name for this share (letters, digits, dashes — e.g. q3-board).\n\n' +
    'Kept in your encrypted Grant Index and shown in the UI. Turning it into a public URL ' +
    '(nvelope.example/s/<name>) would need a naming service — a hosted-tier concern, not part ' +
    'of this app.\n\nLeave empty to remove the name.', aliasOf(s.scopeId) ?? '')
  if (raw === null) return
  const alias = raw.trim().toLowerCase()
  if (alias && !/^[a-z0-9][a-z0-9-]{0,39}$/.test(alias)) {
    msg.textContent = 'alias: letters, digits, dashes; start with a letter or digit; 40 max'
    return
  }
  setAlias(s.scopeId, alias)
  try { if (!s.draft) await syncIndex() } catch (err) { msg.textContent = err.message; return }
  renderMine()
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

const fmtDur = (sec) => sec < 90 ? `${Math.max(1, sec)} s` : `~${Math.ceil(sec / 60)} min`

async function unshare(s, pub, msg) {
  const isBearer = invitesOf(s.scopeId).some(v => !v.claimed_by && v.pub === pub)
  const others = s.grantees.length - 1
  const prompt = isBearer
    ? `Revoke this invite link?\n\nThe key rotates and every copy of the URL goes dead. The ${others} other recipient(s) are re-granted and unaffected.`
    : `Stop sharing "${s.scopeName}" with ${contactName(pub)}?\n\nThe key rotates and the ${others} other recipient(s) are re-granted. They keep anything already downloaded — that is physics — but see nothing new.`
  if (!confirm(prompt)) return
  // Paranoid variant: when the share has blobs, offer to scrub them too —
  // re-key + re-upload every blob and destroy the old ciphertext immediately,
  // so a saved copy of the old manifest dereferences to nothing.
  const bytes = scrubBytes(s.manifest)
  const nBlobs = (s.manifest?.files ?? []).filter(f => f.servers?.length).length
  const scrub = bytes > 0 && confirm(
    `Also scrub the ${nBlobs} encrypted blob${nBlobs === 1 ? '' : 's'}?\n\n` +
    `Plain revocation leaves the current ciphertext on the blob servers until they garbage-collect; ` +
    `if ${isBearer ? 'a link holder' : contactName(pub)} saved the manifest, its file keys still open those blobs. ` +
    `Scrubbing re-encrypts every file under fresh keys, re-uploads, and deletes the old ciphertext immediately.\n\n` +
    `Cost: ${fmtSize(bytes * 2)} through your connection (download + re-upload), roughly ${fmtDur(scrubSeconds(s.manifest))} at 2 MB/s.\n\n` +
    `OK = revoke and scrub · Cancel = plain revoke`)
  msg.textContent = scrub ? 'scrubbing blobs and rotating key…' : 'rotating key…'
  try {
    const survivors = s.grantees.filter(p => p !== pub)
    const rotated = scrub
      ? await scrubShare(state.relay, state.signer, s, survivors, {
          onProgress: (name, stage) => { msg.textContent = name ? `${name}: ${stage}…` : `${stage}…` },
        })
      : await rotateScope(state.relay, state.signer, {
          scopeId: s.scopeId, generation: s.generation, scopeName: s.scopeName,
          payload: s.manifest, survivors,
        })
    Object.assign(s, { generation: rotated.generation, scopeKey: rotated.scopeKey, grantees: survivors })
    if (scrub) s.manifest = rotated.manifest
    if (isBearer) {
      setInvites((state.myIndex.nvelope_invites ?? []).filter(v => !(v.scope === s.scopeId && v.pub === pub)))
      delete s.inviteUrl  // the displayed URL just went dead
    }
    await syncIndex()
    renderMine()
  } catch (err) { msg.textContent = err.message }
}

/** Mint a bearer invite: fresh keypair, normal grant, URL carrying the nsec
 *  in the fragment. The secret exists only in the displayed link. */
async function shareByLink(s, msg) {
  if (s.draft) { msg.textContent = 'add a file first — publishing happens on first file drop'; return }
  msg.textContent = 'minting bearer key…'
  try {
    const { sk, pub } = await createInvite(state.relay, state.signer, s, RELAYS[0])
    if (!s.grantees.includes(pub)) s.grantees.push(pub)
    setInvites([...(state.myIndex.nvelope_invites ?? []),
      { pub, scope: s.scopeId, created_at: Math.floor(Date.now() / 1000) }])
    await syncIndex()
    s.inviteUrl = buildInviteUrl(new URL('.', location.href).href, sk, RELAYS)
    renderMine()
  } catch (err) { msg.textContent = err.message }
}

/** Approve a claim: R becomes a durable grantee; every outstanding bearer
 *  key for this share is rotated out — the link served its purpose. */
async function approve(s, claim, msg) {
  msg.textContent = 'granting their key, rotating the link out…'
  try {
    const res = await approveClaim(state.relay, state.signer, s, state.myIndex.nvelope_invites ?? [], claim)
    Object.assign(s, { generation: res.generation, scopeKey: res.scopeKey, grantees: res.survivors })
    setInvites((state.myIndex.nvelope_invites ?? [])
      .map(v => v.scope === s.scopeId && v.pub === claim.invitePub
        ? { ...v, claimed_by: claim.rPub, claimed_at: Math.floor(Date.now() / 1000) }
        : v)
      .filter(v => v.scope !== s.scopeId || v.claimed_by))  // other unclaimed links are dead now
    state.pendingClaims = state.pendingClaims.filter(c => c.scope !== s.scopeId)
    delete s.inviteUrl
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
    setInvites((state.myIndex.nvelope_invites ?? []).filter(v => v.scope !== s.scopeId))
    setAlias(s.scopeId, null)
    await syncIndex()
    renderMine()
  } catch (err) { msg.textContent = err.message }
}
