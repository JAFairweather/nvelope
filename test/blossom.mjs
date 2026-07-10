// blossom.mjs — pad + encrypted-blob pipeline against local mock Blossom
// servers (real HTTP, in-memory storage, kind-24242 auth enforced).
//
//   node test/blossom.mjs

import { createServer } from 'node:http'
import { localSigner } from '../lib/nipxx.mjs'
import { generateSecretKey } from 'nostr-tools'
import { bucketSize, pad, unpad } from '../shared/pad.mjs'
import { newFileKey, encryptBlob, decryptBlob, sha256hex,
         uploadBlob, fetchBlob, deleteBlob } from '../shared/blossom.mjs'

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

/** Mock Blossom server: BUD-01 GET/PUT/DELETE, auth required to write,
 *  records every byte it ever saw for the adversarial assertions. */
function mockBlossom() {
  const blobs = new Map()
  const seen = []                       // everything an operator could log
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', async () => {
      const body = new Uint8Array(Buffer.concat(chunks))
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization ?? null, body })
      const hash = req.url.slice(1)
      if (req.method === 'PUT' && req.url === '/upload') {
        if (!req.headers.authorization?.startsWith('Nostr ')) { res.writeHead(401); return res.end('auth required') }
        const sha = await sha256hex(body)
        blobs.set(sha, body)
        res.writeHead(201, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ sha256: sha, size: body.length }))
      }
      if (req.method === 'GET' && blobs.has(hash)) {
        res.writeHead(200, { 'content-type': 'application/octet-stream' })
        return res.end(Buffer.from(blobs.get(hash)))
      }
      if (req.method === 'DELETE') {
        if (!req.headers.authorization?.startsWith('Nostr ')) { res.writeHead(401); return res.end() }
        res.writeHead(blobs.delete(hash) ? 204 : 404)
        return res.end()
      }
      res.writeHead(404)
      res.end()
    })
  })
  return new Promise(r => server.listen(0, '127.0.0.1', () =>
    r({ url: `http://127.0.0.1:${server.address().port}/`, blobs, seen, server })))
}

const a = await mockBlossom()
const b = await mockBlossom()
const servers = [a.url, b.url]
const signer = localSigner(generateSecretKey())

console.log('\n1. Padding: sizes leak only the class')
check('64 KiB is the smallest class', bucketSize(1) === 65536)
check('classes are 2^n × 64 KiB', bucketSize(65537) === 131072 && bucketSize(131073) === 262144)
const secretText = 'the merger term sheet, revision 7'
const p1 = pad(new TextEncoder().encode(secretText))
const p2 = pad(new Uint8Array(41000))
check('two different sizes, same class, identical padded length', p1.length === p2.length)
check('unpad round-trips', new TextDecoder().decode(unpad(p1)) === secretText)

console.log('\n2. Encrypt / decrypt')
const filekey = newFileKey()
const plain = new TextEncoder().encode(secretText)
const cipher = encryptBlob(filekey, plain)
check('ciphertext sized by class alone', cipher.length === 24 + 65536 + 16)
check('decrypt round-trips', new TextDecoder().decode(decryptBlob(filekey, cipher)) === secretText)
check('wrong key throws', (() => {
  try { decryptBlob(newFileKey(), cipher); return false } catch { return true }
})())
const tampered = cipher.slice()
tampered[100] ^= 1
check('tampered ciphertext throws (Poly1305)', (() => {
  try { decryptBlob(filekey, tampered); return false } catch { return true }
})())

console.log('\n3. Upload: mirrored, authed')
const desc = await uploadBlob(servers, signer, cipher)
check('both mirrors hold the blob', desc.servers.length === 2 &&
  a.blobs.has(desc.sha256) && b.blobs.has(desc.sha256))
check('descriptor hash is the ciphertext hash', desc.sha256 === await sha256hex(cipher))

console.log('\n4. Fetch: verify, survive a dead mirror, reject a lying one')
const got = await fetchBlob(servers, desc.sha256)
check('fetch → verify → decrypt round-trips',
  new TextDecoder().decode(decryptBlob(filekey, got)) === secretText)
a.server.close()                                    // first mirror goes dark
const got2 = await fetchBlob(servers, desc.sha256, { timeout: 3000 })
check('second mirror serves when the first is dead', got2.length === cipher.length)
const evil = b.blobs.get(desc.sha256).slice()       // second mirror starts lying
evil[0] ^= 1
b.blobs.set(desc.sha256, evil)
check('lying server (hash mismatch) is never returned', await (async () => {
  try { await fetchBlob([b.url], desc.sha256); return false }
  catch (err) { return err.message.includes('hash mismatch') }
})())
b.blobs.set(desc.sha256, Buffer.from(cipher))       // restore

console.log('\n5. Delete (BUD-02)')
check('unauthed delete refused', (await fetch(b.url + desc.sha256, { method: 'DELETE' })).status === 401)
check('authed delete confirmed', await deleteBlob([b.url], signer, desc.sha256) === 1)
check('blob gone', !b.blobs.has(desc.sha256))

console.log('\n6. Adversarial: what the blob host operator saw')
const everything = Buffer.concat(b.seen.map(s => Buffer.from(s.body))).toString('latin1')
  + JSON.stringify(b.seen.map(({ method, url, auth }) => ({ method, url, auth })))
check('no plaintext bytes ever crossed the wire', !everything.includes('merger') && !everything.includes(secretText))
check('no filekey on the wire', !everything.includes(Buffer.from(filekey).toString('hex'))
  && !everything.includes(Buffer.from(filekey).toString('base64')))
check('uploads were ciphertext of class size only',
  b.seen.filter(s => s.method === 'PUT').every(s => s.body.length === 24 + 65536 + 16))

b.server.close()
console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
process.exit(failed === 0 ? 0 : 1)
