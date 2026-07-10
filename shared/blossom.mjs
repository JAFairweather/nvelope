// blossom.mjs — encrypted blob transport over public Blossom servers
// (BUD-01/02). The pipeline: pad → encrypt under a random per-file key →
// upload ciphertext (mirrored, kind-24242 auth) → fetch from any mirror →
// verify sha256 of the ciphertext → decrypt → unpad. Servers hold ciphertext
// whose size reveals only the padding class; the per-file key travels inside
// the share's encrypted manifest, never near a server.
//
// Cipher note: NIP-44 v2 hard-caps plaintext at 64 KiB — files can't ride
// it directly. We use XChaCha20-Poly1305 from audited @noble/ciphers (the
// same family NIP-44 builds on) with the 32-byte filekey used directly, no
// ECDH — the exact trust construction of NIP-DA scope keys.

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { pad, unpad } from './pad.mjs'

// Public servers verified live (2026-07-10, test/blossom-probe.mjs) to take
// anonymous ciphertext uploads at 50 MB+ with working BUD-02 delete.
export const DEFAULT_SERVERS = ['https://nostr.download', 'https://cdn.hzrd149.com']

export const newFileKey = () => crypto.getRandomValues(new Uint8Array(32))

export async function sha256hex(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(d), b => b.toString(16).padStart(2, '0')).join('')
}

/** Pad + encrypt: returns nonce‖ciphertext, sized by padding class alone. */
export function encryptBlob(filekey, bytes) {
  const nonce = crypto.getRandomValues(new Uint8Array(24))
  const cipher = xchacha20poly1305(filekey, nonce).encrypt(pad(bytes))
  const out = new Uint8Array(24 + cipher.length)
  out.set(nonce)
  out.set(cipher, 24)
  return out
}

/** Decrypt + unpad; throws on any tampering (Poly1305 tag). */
export function decryptBlob(filekey, blob) {
  return unpad(xchacha20poly1305(filekey, blob.slice(0, 24)).decrypt(blob.slice(24)))
}

// --- BUD-01/02 HTTP, via the NIP-DA signer interface -------------------------

const b64 = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)))

async function authHeader(signer, verb, sha256) {
  const event = await signer.signEvent({
    kind: 24242,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['t', verb], ['x', sha256],
      ['expiration', String(Math.floor(Date.now() / 1000) + 600)]],
    content: `${verb} blob`,
  })
  return 'Nostr ' + b64(JSON.stringify(event))
}

const url = (server, path) => new URL(path, server.endsWith('/') ? server : server + '/').href

/**
 * Upload ciphertext to every server (mirroring); ≥1 success is success,
 * like the relay publish contract. Per-server retries with backoff.
 * Returns { sha256, size, servers } — servers that actually hold the blob.
 */
export async function uploadBlob(servers, signer, cipher,
  { retries = 2, timeout = 120_000, fetchImpl = fetch } = {}) {
  const sha256 = await sha256hex(cipher)
  const auth = await authHeader(signer, 'upload', sha256)
  const results = await Promise.allSettled(servers.map(async (server) => {
    for (let attempt = 0; ; attempt++) {
      try {
        const res = await fetchImpl(url(server, 'upload'), {
          method: 'PUT', body: cipher,
          headers: { authorization: auth, 'content-type': 'application/octet-stream' },
          signal: AbortSignal.timeout(timeout),
        })
        if (!res.ok) throw new Error(`${server}: HTTP ${res.status} ${(await res.text()).slice(0, 80)}`)
        return server
      } catch (err) {
        if (attempt >= retries) throw err
        await new Promise(r => setTimeout(r, 500 * (attempt + 1)))
      }
    }
  }))
  const ok = results.filter(r => r.status === 'fulfilled').map(r => r.value)
  if (!ok.length) throw new Error('no server accepted the blob: ' +
    results.map(r => String(r.reason).slice(0, 100)).join(' | '))
  return { sha256, size: cipher.length, servers: ok }
}

/**
 * Fetch ciphertext by hash, trying servers in order. A blob whose bytes
 * don't hash to `sha256` is a lying server — skipped, never returned.
 */
export async function fetchBlob(servers, sha256, { timeout = 120_000, fetchImpl = fetch } = {}) {
  const errors = []
  for (const server of servers) {
    try {
      const res = await fetchImpl(url(server, sha256), { signal: AbortSignal.timeout(timeout) })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const bytes = new Uint8Array(await res.arrayBuffer())
      if (await sha256hex(bytes) !== sha256) throw new Error('hash mismatch — server returned wrong bytes')
      return bytes
    } catch (err) { errors.push(`${server}: ${err.message}`) }
  }
  throw new Error(`blob ${sha256.slice(0, 12)}… unavailable: ${errors.join(' | ')}`)
}

/** BUD-02 delete on every server; best-effort, returns how many confirmed. */
export async function deleteBlob(servers, signer, sha256, { timeout = 30_000, fetchImpl = fetch } = {}) {
  const auth = await authHeader(signer, 'delete', sha256)
  const results = await Promise.allSettled(servers.map(async (server) => {
    const res = await fetchImpl(url(server, sha256), {
      method: 'DELETE', headers: { authorization: auth },
      signal: AbortSignal.timeout(timeout),
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
  }))
  return results.filter(r => r.status === 'fulfilled').length
}
