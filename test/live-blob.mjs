// live-blob.mjs — M2 acceptance: a large file round-trips LIVE between two
// keys — real public relays for the manifest/grant, the default Blossom
// servers (nostr.download, cdn.hzrd149.com) for the encrypted body — then
// the replace-file flow and the BUD-02 cleanup.
//
//   node test/live-blob.mjs [MB]      # default 8; acceptance run at 50

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { LiveRelay } from '../lib/liverelay.mjs'
import {
  newScopeKey, publishScope, grant, deleteScope,
  receiveGrants, latestGrants, fetchScope, localSigner,
} from '../lib/nipxx.mjs'
import { newManifest, blobFileEntry, blobKey, replaceFile, validateManifest } from '../shared/manifest.mjs'
import { DEFAULT_SERVERS, newFileKey, encryptBlob, decryptBlob, sha256hex,
         uploadBlob, fetchBlob, deleteBlob } from '../shared/blossom.mjs'

const MB = Number(process.argv[2] ?? 8)
const NET = { timeout: 600_000 }              // big uploads on real uplinks
const relay = new LiveRelay(['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'])
const settle = () => new Promise(r => setTimeout(r, 1500))

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}
const randomBytes = (n) => {                  // getRandomValues caps at 64 KiB
  const out = new Uint8Array(n)
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(i + 65536, n)))
  return out
}

const sender = generateSecretKey()
const senderSigner = localSigner(sender)      // blossom auth speaks the signer interface
const recipient = generateSecretKey()

try {
  console.log(`\nmode: LIVE — ${MB} MB file via ${DEFAULT_SERVERS.join(', ')}`)

  console.log('\n1. Sender: pad → encrypt → mirror upload')
  const plain = randomBytes(MB * 1048576)
  const plainHash = await sha256hex(plain)
  const filekey = newFileKey()
  let t0 = Date.now()
  const cipher = encryptBlob(filekey, plain)
  const desc = await uploadBlob(DEFAULT_SERVERS, senderSigner, cipher, NET)
  check('≥1 default server accepted the ciphertext', desc.servers.length >= 1,
    `${desc.servers.length}/${DEFAULT_SERVERS.length} mirrors, ${(cipher.length / 1048576).toFixed(0)} MiB padded class, ${((Date.now() - t0) / 1000).toFixed(1)}s`)

  console.log('\n2. Sender: manifest with blob entry → 30440 → grant to recipient')
  const entry = blobFileEntry({ name: 'big.bin', mime: 'application/octet-stream',
    size: plain.length, filekey, desc })
  const manifest = newManifest('Field recordings', 'raw takes — huge')
  manifest.files.push(entry)
  check('manifest validates', validateManifest(manifest).length === 0)
  const share = { scopeId: 'nv' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKey() }
  await publishScope(relay, sender, { ...share, payload: manifest })
  await grant(relay, sender, getPublicKey(recipient), { ...share, scopeName: manifest.name })
  await settle()

  console.log('\n3. Recipient (second key): grant → manifest → blob → verify')
  const g = latestGrants(await receiveGrants(relay, recipient))[0]
  const got = await fetchScope(relay, g)
  check('recipient reads the manifest', got.status === 'ok' && got.data.name === 'Field recordings')
  const rEntry = got.data.files[0]
  t0 = Date.now()
  const rCipher = await fetchBlob(rEntry.servers, rEntry.sha256_cipher, NET)
  const rPlain = decryptBlob(blobKey(rEntry), rCipher)
  check('blob fetched, hash-verified, decrypted', await sha256hex(rPlain) === plainHash,
    `${(rPlain.length / 1048576).toFixed(0)} MB in ${((Date.now() - t0) / 1000).toFixed(1)}s`)

  console.log('\n4. Replace-file flow: v2 body, `replaces` points at v1')
  const plain2 = randomBytes(1048576)
  const filekey2 = newFileKey()
  const desc2 = await uploadBlob(DEFAULT_SERVERS, senderSigner, encryptBlob(filekey2, plain2), NET)
  const entry2 = blobFileEntry({ name: 'big.bin', mime: 'application/octet-stream',
    size: plain2.length, filekey: filekey2, desc: desc2 })
  replaceFile(manifest, 'big.bin', entry2)
  check('new entry records what it supersedes', entry2.replaces === desc.sha256)
  await publishScope(relay, sender, { ...share, payload: manifest })
  await settle()
  const got2 = await fetchScope(relay, g)
  const rEntry2 = got2.data.files.find(f => f.name === 'big.bin')
  check('recipient sees v2 with no action', rEntry2?.sha256_cipher === desc2.sha256)
  const v2 = decryptBlob(blobKey(rEntry2), await fetchBlob(rEntry2.servers, rEntry2.sha256_cipher, NET))
  check('v2 body round-trips', await sha256hex(v2) === await sha256hex(plain2))

  console.log('\n5. BUD-02 cleanup (grace window elapsed → delete superseded blob)')
  const del = await deleteBlob(desc.servers, senderSigner, desc.sha256)
  check('superseded v1 blob deleted', del >= 1, `${del}/${desc.servers.length} servers confirmed`)
  await deleteBlob(desc2.servers, senderSigner, desc2.sha256)          // leave nothing behind
  await deleteScope(relay, sender, share)

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close?.()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mLive blob test aborted:\x1b[0m', err.message)
  relay.close?.()
  process.exit(1)
}
