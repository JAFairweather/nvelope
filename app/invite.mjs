// invite.mjs (app) — the open-link viewer: someone followed a bearer URL.
// The invite nsec was parsed out of the fragment and the fragment already
// stripped (main.mjs does that before anything else runs); the key lives
// in memory only — never sessionStorage, never the URL bar. No login.

import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { LiveRelay } from '../lib/liverelay.mjs'
import { localSigner, receiveGrants, latestGrants, fetchScope } from '../lib/nipxx.mjs'
import { sendClaimRequest } from '../shared/invite.mjs'
import { $, esc, fmtSize, hexOf, login, RELAYS } from './main.mjs'
import { saveFile } from './receive.mjs'

export async function openInvite({ sk, relays }) {
  $('login').style.display = 'none'
  const view = $('invite')
  view.style.display = ''
  view.innerHTML = `
    <div class="banner">Anyone with this link can open this share until it is claimed or revoked.</div>
    <div class="empty">opening the share…</div>`
  const relay = new LiveRelay(relays.length ? relays : RELAYS)
  let shares
  try {
    const grants = latestGrants(await receiveGrants(relay, sk))
    shares = await Promise.all(grants.map(async g => ({ ...g, ...await fetchScope(relay, g) })))
  } catch (err) {
    view.querySelector('.empty').textContent = `relay error: ${err.message}`
    return
  }
  render(view, relay, sk, shares.filter(s => s.status === 'ok'), shares.length)
}

const fileRow = (f, si, fi) => `
  <div class="file">
    <span class="fname">${esc(f.name)}</span>
    <span class="fsize">${fmtSize(f.size)}</span>
    <a href="#" data-s="${si}" data-f="${fi}" class="dl">download</a>
  </div>`

const shareCard = (s, si) => `
  <div class="card">
    <div class="head">
      <div><span class="name">${esc(s.data.name)}</span> <span class="badge live">live · v${s.generation}</span></div>
      <span class="meta">shared by ${esc(nip19.npubEncode(s.publisher).slice(0, 12))}…</span>
    </div>
    ${s.data.note ? `<div class="note">${esc(s.data.note)}</div>` : ''}
    <div class="files">${s.data.files.map((f, fi) => fileRow(f, si, fi)).join('') || '<span class="msg">empty share</span>'}</div>
  </div>`

function render(view, relay, sk, live, total) {
  if (!live.length) {
    view.innerHTML = `
      <div class="card">
        <div class="head"><span class="name">This link is no longer active</span>
          <span class="badge stale">${total ? 'claimed or revoked' : 'nothing here'}</span></div>
        <div class="note">Links are bearer tokens: when someone claims the share — or the sender
          revokes the link — the key rotates and every copy of the URL goes dead. Anything
          already downloaded stays downloaded.</div>
      </div>`
    return
  }
  view.innerHTML = `
    <div class="banner">Anyone with this link can open this share until it is claimed or revoked.
      Claim it to move access onto a key only you hold.</div>
    ${live.map(shareCard).join('')}
    <div class="card">
      <div class="head"><span class="name">Make it yours</span></div>
      <div class="note">Claiming generates a private key only you hold and asks the sender to move
        this share onto it. Once they approve, this link stops working for everyone —
        including anyone else it was forwarded to.</div>
      <div class="actions">
        <button class="primary" id="claim">Claim this share</button>
        <span class="msg" id="claim-msg"></span>
      </div>
      <div id="claimed" style="display:none">
        <div class="phrase" id="claim-nsec"></div>
        <p class="warn">This key IS your access — write it down; there is no reset. Once the
          sender approves, sign in with it to see the share and every future update.</p>
        <div style="display:flex;gap:10px">
          <button id="claim-copy">Copy</button>
          <button class="primary" id="claim-continue" style="flex:1">Continue with this key</button>
        </div>
      </div>
    </div>`

  for (const a of view.querySelectorAll('.dl'))
    a.onclick = (e) => {
      e.preventDefault()
      saveFile(live[Number(a.dataset.s)].data.files[Number(a.dataset.f)], a)
    }

  $('claim').onclick = async () => {
    $('claim').disabled = true
    $('claim-msg').textContent = 'generating your key, asking the sender…'
    const rSk = generateSecretKey()
    try {
      for (const s of live) await sendClaimRequest(relay, sk, s.publisher, s.scopeId, getPublicKey(rSk))
    } catch (err) {
      $('claim-msg').textContent = err.message
      $('claim').disabled = false
      return
    }
    $('claim-msg').textContent = 'claim sent — the sender approves it on their next visit'
    const nsec = nip19.nsecEncode(rSk)
    $('claimed').style.display = ''
    $('claim-nsec').textContent = nsec
    $('claim-copy').onclick = async () => {
      await navigator.clipboard.writeText(nsec)
      $('claim-copy').textContent = 'Copied ✓'
      setTimeout(() => { $('claim-copy').textContent = 'Copy' }, 2000)
    }
    $('claim-continue').onclick = () => {
      relay.close()
      view.style.display = 'none'
      login(localSigner(rSk), hexOf(rSk))
    }
  }
}
