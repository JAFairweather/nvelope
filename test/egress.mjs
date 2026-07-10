// egress.mjs — the zero-egress guarantee, enforced at the strongest level
// that is feasible without a headless browser:
//
//   1. STATIC SCAN: every absolute URL in shipped code (app/, shared/, lib/,
//      the root redirect page) must resolve to an allowed origin. Network
//      origins are exactly the configured relays, the default Blossom hosts,
//      and esm.sh (pinned module CDN). github.com is allowed ONLY as an
//      <a href> in HTML (user-initiated navigation, not egress); w3.org is
//      allowed ONLY as an XML namespace identifier (never fetched);
//      localhost/URL-parse bases are allowed ONLY in the dev server.
//   2. CONSISTENCY: the allowlist is cross-checked against the live
//      constants — DEFAULT_SERVERS (imported) and RELAYS (extracted from
//      app/main.mjs source) must be subsets of it, so the list can't drift.
//   3. IMPORT-TIME INTERCEPTION: fetch / WebSocket / XMLHttpRequest are
//      replaced with recording traps, then every DOM-free module is
//      imported; zero network calls may occur at module load. Nothing
//      phones home just by being loaded.
//
// What this does NOT cover (documented, not hidden): runtime calls in a real
// browser (nostr-tools opens sockets only to the relay URLs we pass it — the
// static scan pins those; browser behavior is additionally verified against
// the preview server's network log during development), and a tampered CDN
// serving different code than audited (see SECURITY.md, "code delivery").
//
//   node test/egress.mjs

import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

// The one and only egress allowlist.
const NETWORK = new Set([
  'wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net',  // relays
  'https://nostr.download', 'https://cdn.hzrd149.com',                // Blossom
  'https://esm.sh',                                                   // pinned modules
])
const LINK_ONLY = new Set(['https://github.com'])       // <a href> in HTML only
const NAMESPACE = new Set(['http://www.w3.org'])        // svg xmlns, never fetched
const DEV_ONLY = new Set(['http://localhost:4441', 'http://x'])  // serve.mjs

console.log('\n1. Static scan: every URL in shipped code resolves to an allowed origin')
const files = [
  join(root, 'index.html'),
  ...readdirSync(join(root, 'app')).filter(f => /\.(mjs|html)$/.test(f)).map(f => join(root, 'app', f)),
  ...readdirSync(join(root, 'shared')).filter(f => f.endsWith('.mjs')).map(f => join(root, 'shared', f)),
  ...readdirSync(join(root, 'lib')).filter(f => f.endsWith('.mjs')).map(f => join(root, 'lib', f)),
]
const urlRx = /\b(?:https?|wss?):\/\/[^\s"'`<>\\)\]{},]*/g
const offenders = []
let scanned = 0, found = 0
for (const file of files) {
  const src = readFileSync(file, 'utf8')
  scanned++
  for (const raw of src.match(urlRx) ?? []) {
    let origin, host
    try { ({ origin, host } = new URL(raw)) } catch { origin = raw; host = '' }
    if (!host) continue                       // bare "wss://" in prose, not a destination
    found++
    const rel = file.slice(root.length + 1)
    if (NETWORK.has(origin)) continue
    if (LINK_ONLY.has(origin) && rel.endsWith('.html')
        && new RegExp(`href="${origin}[^"]*"`).test(src)) continue
    if (NAMESPACE.has(origin) && src.includes(`xmlns='${origin}`)) continue
    if (DEV_ONLY.has(origin) && rel === 'app/serve.mjs') continue
    offenders.push(`${rel}: ${raw}`)
  }
}
check(`no unexpected origins in ${scanned} files (${found} URLs found)`,
  offenders.length === 0, offenders.join(' | '))
check('the scan itself sees the expected surface', found >= 10,
  'regex or file list broke if this number collapses')

console.log('\n2. Consistency: the allowlist matches the live configuration')
const mainSrc = readFileSync(join(root, 'app', 'main.mjs'), 'utf8')
const relays = mainSrc.match(/wss:\/\/[a-z0-9.-]+/g) ?? []
check('every configured relay is allowlisted', relays.length >= 3
  && relays.every(r => NETWORK.has(r)), relays.join(', '))
const htmlSrc = readFileSync(join(root, 'app', 'index.html'), 'utf8')
const importMap = htmlSrc.match(/<script type="importmap">([\s\S]*?)<\/script>/)?.[1] ?? ''
const imports = Object.values(JSON.parse(importMap).imports).map(u => new URL(u).origin)
check('import map points only at esm.sh', imports.length >= 3
  && imports.every(o => o === 'https://esm.sh'), [...new Set(imports)].join(', '))

console.log('\n3. Import-time interception: nothing phones home on module load')
const calls = []
globalThis.fetch = (u) => { calls.push(String(u)); return Promise.reject(new Error('egress blocked')) }
globalThis.XMLHttpRequest = class { open(m, u) { calls.push(String(u)) } send() { throw new Error('egress blocked') } setRequestHeader() {} }
globalThis.WebSocket = class { constructor(u) { calls.push(String(u)); throw new Error('egress blocked') } }
const modules = ['../shared/pad.mjs', '../shared/blossom.mjs', '../shared/manifest.mjs',
  '../shared/invite.mjs', '../shared/scrub.mjs', '../lib/nipxx.mjs', '../lib/liverelay.mjs', '../lib/relay.mjs']
let importErr = null
let blossom
try {
  for (const m of modules) if (m.includes('blossom')) blossom = await import(m); else await import(m)
} catch (err) { importErr = err }
check('all shipped modules import cleanly under the traps', importErr === null, importErr?.message ?? '')
check('zero network calls at import time', calls.length === 0, calls.join(', '))
check('DEFAULT_SERVERS are allowlisted',
  blossom.DEFAULT_SERVERS.length >= 2 && blossom.DEFAULT_SERVERS.every(s => NETWORK.has(new URL(s).origin)),
  blossom.DEFAULT_SERVERS.join(', '))

console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
process.exit(failed === 0 ? 0 : 1)
