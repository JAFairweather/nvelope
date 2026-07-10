// receive.mjs — recipient side: shares granted to you, dereferenced live.
// Revocation surfaces honestly: "access ended", never a silent disappearance.

import { state, $, esc, fmtSize, contactName } from './main.mjs'
import { inlineBytes, blobKey } from '../shared/manifest.mjs'
import { fetchBlob, decryptBlob } from '../shared/blossom.mjs'

function fileRow(f, si, fi) {
  return `<div class="file">
    <span class="fname">${esc(f.name)}</span>
    <span class="fsize">${fmtSize(f.size)}</span>
    <a href="#" data-s="${si}" data-f="${fi}" class="dl">download</a>
  </div>`
}

function incomingCard(g, si) {
  const from = contactName(g.publisher)
  if (g.status !== 'ok') {
    return `<div class="card">
      <div class="head"><div><span class="name">${esc(g.scopeName || 'share')}</span>
        <span class="badge stale">access ended</span></div>
        <span class="meta">from ${esc(from)}</span></div>
      <div class="note">The sender rotated the key or removed this share. Anything you
        already downloaded is still yours; there is nothing new to see.</div>
    </div>`
  }
  const m = g.data
  return `<div class="card">
    <div class="head">
      <div><span class="name">${esc(m.name)}</span> <span class="badge live">live · v${g.generation}</span></div>
      <span class="meta">from ${esc(from)}</span>
    </div>
    ${m.note ? `<div class="note">${esc(m.note)}</div>` : ''}
    <div class="files">${m.files.map((f, fi) => fileRow(f, si, fi)).join('') || '<span class="msg">empty share</span>'}</div>
  </div>`
}

export function renderReceived() {
  const items = state.incoming
  $('received').innerHTML = items.map(incomingCard).join('') ||
    `<div class="empty">Nothing shared with you yet.<br>
      When someone shares an Nvelope with your npub, it appears here — live,
      always the current version.</div>`

  for (const a of document.querySelectorAll('#received .dl'))
    a.onclick = (e) => {
      e.preventDefault()
      const g = state.incoming[Number(a.dataset.s)]
      saveFile(g.data.files[Number(a.dataset.f)], a)
    }
}

/** Materialize a manifest file entry as a browser download, narrating
 *  progress into the clicked anchor. Shared with the invite viewer. */
export async function saveFile(f, a) {
  let bytes
  if (f.inline) bytes = inlineBytes(f)
  else {
    // Blob entry: fetch ciphertext from any mirror (hash-verified inside
    // fetchBlob — a lying server is never accepted), decrypt, unpad.
    a.textContent = `fetching ${fmtSize(f.size_padded)}…`
    try {
      const cipher = await fetchBlob(f.servers, f.sha256_cipher)
      a.textContent = 'decrypting…'
      bytes = decryptBlob(blobKey(f), cipher)
    } catch (err) {
      a.textContent = 'download'
      alert(`${f.name}: ${err.message}`)
      return
    }
    a.textContent = 'download'
  }
  const blob = new Blob([bytes], { type: f.mime })
  const url = URL.createObjectURL(blob)
  const link = Object.assign(document.createElement('a'), { href: url, download: f.name })
  link.click()
  URL.revokeObjectURL(url)
}
