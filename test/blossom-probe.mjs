// blossom-probe.mjs — live probe: does a server accept random
// (ciphertext-like) bytes from a throwaway key, and up to what size?
// Uploads then deletes each blob. Findings as of 2026-07-10 are recorded
// in CLAUDE.md (short version: nostr.download and cdn.hzrd149.com yes,
// primal/band/satellite no).
//
//   node test/blossom-probe.mjs [host] [size-bytes]

import { finalizeEvent, generateSecretKey } from 'nostr-tools'

const sk = generateSecretKey()
const servers = process.argv[2] ? [process.argv[2]] : ['nostr.download', 'cdn.hzrd149.com']
const sizes = (process.argv[3] ? [Number(process.argv[3])] : [64 * 1024, 1048576, 10 * 1048576])

const auth = (verb, hash) => 'Nostr ' + Buffer.from(JSON.stringify(finalizeEvent({
  kind: 24242,
  created_at: Math.floor(Date.now() / 1000),
  tags: [['t', verb], ['x', hash], ['expiration', String(Math.floor(Date.now() / 1000) + 600)]],
  content: `${verb} probe`,
}, sk))).toString('base64')

for (const h of servers) {
  for (const size of sizes) {
    const blob = new Uint8Array(size)
    // fill with random in 64KB chunks (getRandomValues cap)
    for (let i = 0; i < size; i += 65536)
      crypto.getRandomValues(blob.subarray(i, Math.min(i + 65536, size)))
    const hash = Buffer.from(await crypto.subtle.digest('SHA-256', blob)).toString('hex')
    const t0 = Date.now()
    try {
      const up = await fetch(`https://${h}/upload`, {
        method: 'PUT', body: blob,
        headers: { authorization: auth('upload', hash), 'content-type': 'application/octet-stream' },
        signal: AbortSignal.timeout(120000),
      })
      const body = await up.text()
      console.log(`${h} ${(size / 1048576).toFixed(2)}MB: PUT ${up.status} in ${Date.now() - t0}ms — ${body.slice(0, 120)}`)
      if (up.ok) {
        const back = await fetch(`https://${h}/${hash}`, { signal: AbortSignal.timeout(60000) })
        const echo = new Uint8Array(await back.arrayBuffer())
        const ok = echo.length === blob.length && echo.every((b, i) => b === blob[i])
        console.log(`  GET: ${back.status} type=${back.headers.get('content-type')} roundtrip=${ok}`)
        const del = await fetch(`https://${h}/${hash}`, {
          method: 'DELETE', headers: { authorization: auth('delete', hash) },
          signal: AbortSignal.timeout(30000),
        })
        console.log(`  DELETE: ${del.status}`)
      }
    } catch (err) { console.log(`${h} ${(size / 1048576).toFixed(2)}MB: ERROR ${err.message}`) }
  }
}
