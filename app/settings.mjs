// settings.mjs — per-device endpoint configuration (M5: the paid-tier seams).
// Relays and Blossom servers are user policy: edit them here, stored in
// localStorage (non-secret), defaults = the shipped public free-tier list.
// Saving reloads the page so every module reads one consistent snapshot.
//
// Deliberately seams only: a "managed" flag marks a server the user expects
// to demand auth or payment — Nvelope already signs BUD-01 (kind 24242) auth
// events on every upload and delete, so a managed server that honors those
// signatures needs no code change. Payment and account provisioning are out
// of scope; so is friendly-name URL resolution (see README).

import { CONFIG_KEY, defaultConfig, loadConfig, saveConfig, resetConfig } from '../shared/config.mjs'
import { $, esc } from './main.mjs'

let draft = null            // working copy; edits live here until Save

const validRelay = (u) => { try { return new URL(u).protocol === 'wss:' } catch { return false } }
const validServer = (u) => { try { return /^https?:$/.test(new URL(u).protocol) } catch { return false } }

const relayRow = (r, i) => `
  <div class="row cfg">
    <input class="r-url" data-i="${i}" value="${esc(r)}" placeholder="wss://relay.example" spellcheck="false" autocomplete="off">
    <button class="icon r-del" data-i="${i}" title="remove relay">×</button>
  </div>`

const serverRow = (s, i) => `
  <div class="row cfg">
    <input class="s-url" data-i="${i}" value="${esc(s.url)}" placeholder="https://blossom.example" spellcheck="false" autocomplete="off">
    <label class="managed" title="Mark a server you expect to require an account or payment. Nvelope signs BUD-01 auth on every upload/delete either way — this flag only sharpens the error copy when a server refuses.">
      <input type="checkbox" class="s-auth" data-i="${i}" ${s.requiresAuth ? 'checked' : ''}> managed</label>
    <button class="icon s-del" data-i="${i}" title="remove server">×</button>
  </div>`

export function renderSettings() {
  draft ??= loadConfig()
  const custom = !!localStorage.getItem(CONFIG_KEY)
  $('settings').innerHTML = `
    <div class="banner">Free tier, honestly: the default relays and blob servers are public
      infrastructure — no accounts, no payment, and <b>no persistence guarantee</b>. They may
      garbage-collect your ciphertext on their own clock. Your key re-creates everything you
      publish, but durability is what a managed (paid) endpoint would sell. Nvelope carries no
      payment machinery — when you have a managed relay or Blossom server, configure it here.</div>
    <div class="card">
      <div class="head"><span class="name">Relays</span>
        <span class="badge ${custom ? 'live' : ''}">${custom ? 'custom · this device' : 'defaults'}</span></div>
      <div class="note">Where manifests, grants, and your Grant Index live. wss:// only;
        every relay sees only ciphertext.</div>
      <div id="cfg-relays">${draft.relays.map(relayRow).join('')}</div>
      <div class="actions"><button id="r-add">+ add relay</button></div>
      <div class="sect2">blob servers (blossom)</div>
      <div class="note">Where encrypted file bodies live, mirrored to every server listed.
        Servers hold ciphertext sized by padding class only. New uploads go to this list;
        already-shared files stay on the servers named in their manifest entry.</div>
      <div id="cfg-servers">${draft.servers.map(serverRow).join('')}</div>
      <div class="actions"><button id="s-add">+ add server</button></div>
      <div class="actions" style="margin-top:16px">
        <button class="primary" id="cfg-save">Save &amp; reload</button>
        <button id="cfg-reset">Restore defaults</button>
        <span class="msg" id="cfg-msg"></span>
      </div>
    </div>`

  const msg = $('cfg-msg')
  const pull = () => {       // DOM → draft (keeps typing across add/remove re-renders)
    draft.relays = [...document.querySelectorAll('#cfg-relays .r-url')].map(x => x.value.trim())
    draft.servers = [...document.querySelectorAll('#cfg-servers .s-url')].map((x, i) => ({
      url: x.value.trim(),
      requiresAuth: document.querySelector(`#cfg-servers .s-auth[data-i="${i}"]`).checked,
    }))
  }
  $('r-add').onclick = () => { pull(); draft.relays.push(''); renderSettings() }
  $('s-add').onclick = () => { pull(); draft.servers.push({ url: '', requiresAuth: false }); renderSettings() }
  for (const d of document.querySelectorAll('.r-del'))
    d.onclick = () => { pull(); draft.relays.splice(Number(d.dataset.i), 1); renderSettings() }
  for (const d of document.querySelectorAll('.s-del'))
    d.onclick = () => { pull(); draft.servers.splice(Number(d.dataset.i), 1); renderSettings() }

  $('cfg-save').onclick = () => {
    pull()
    draft.relays = draft.relays.filter(Boolean)
    draft.servers = draft.servers.filter(s => s.url)
    const bad = [
      ...draft.relays.filter(r => !validRelay(r)).map(r => `${r} is not a wss:// URL`),
      ...draft.servers.filter(s => !validServer(s.url)).map(s => `${s.url} is not an http(s) URL`),
    ]
    if (!draft.relays.length) bad.push('need at least one relay')
    if (!draft.servers.length) bad.push('need at least one blob server')
    if (bad.length) { msg.textContent = bad[0]; return }
    saveConfig(draft)
    draft = null
    msg.textContent = 'saved — reloading…'
    location.reload()
  }
  $('cfg-reset').onclick = () => {
    resetConfig()
    draft = null
    msg.textContent = 'defaults restored — reloading…'
    location.reload()
  }
}
