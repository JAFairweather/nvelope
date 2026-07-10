// scrub.mjs — revoke-and-scrub (M4): the paranoid unshare. A plain rotation
// cuts the revoked party off from every future update, but the CURRENT
// ciphertext stays on the blob servers — someone who saved the old manifest
// (and with it the old filekeys) can still fetch and decrypt it until the
// servers garbage-collect. Scrubbing closes that window: every blob is
// downloaded, re-encrypted under a fresh filekey, re-uploaded, the scope key
// rotates with the new manifest, and only THEN is the old ciphertext BUD-02
// deleted — immediately, no grace window. Copied filekeys now point at
// nothing.
//
// Honest limits (see SECURITY.md): a server may ignore DELETE, and whatever
// the revoked party already downloaded is theirs forever. Scrub narrows the
// exposure window; it cannot reach into other people's disks.
//
// DOM-free on purpose: test/blossom.mjs drives this module directly.

import { rotateScope } from '../lib/nipxx.mjs'
import { newFileKey, encryptBlob, decryptBlob, uploadBlob, fetchBlob, deleteBlob } from './blossom.mjs'
import { blobFileEntry, blobKey } from './manifest.mjs'

/** Padded bytes a scrub would move — each blob is downloaded AND re-uploaded,
 *  so the wire cost is 2× this. Inline files cost nothing (they re-encrypt
 *  for free inside the rotated manifest). */
export const scrubBytes = (manifest) =>
  (manifest?.files ?? []).reduce((n, f) => n + (f.servers?.length ? f.size_padded : 0), 0)

/** Rough wall-clock estimate for the cost warning, at an assumed sustained
 *  rate (default 2 MB/s — conservative for the public mirrors). */
export const scrubSeconds = (manifest, bytesPerSec = 2 * 1048576) =>
  Math.ceil((scrubBytes(manifest) * 2) / bytesPerSec)

/**
 * Re-key every blob, rotate the scope, destroy the old ciphertext.
 * Ordering is deliberate: new ciphertext is live and survivors re-granted
 * BEFORE the old blobs are deleted, so nobody legitimate is ever cut off.
 * Returns { scopeKey, generation, manifest, scrubbed, deleted } — the caller
 * adopts the new manifest alongside the rotation result.
 */
export async function scrubShare(relay, signer, share, survivors,
  { onProgress = () => {}, fetchImpl } = {}) {
  const old = share.manifest.files.filter(f => f.servers?.length)
  const files = []
  for (const f of share.manifest.files) {
    if (!f.servers?.length) { files.push(f); continue }        // inline: nothing on any server
    onProgress(f.name, 'fetching')
    const plain = decryptBlob(blobKey(f), await fetchBlob(f.servers, f.sha256_cipher))
    onProgress(f.name, 're-encrypting')
    const filekey = newFileKey()
    const cipher = encryptBlob(filekey, plain)
    onProgress(f.name, 'uploading')
    const desc = await uploadBlob(f.servers, signer, cipher, fetchImpl ? { fetchImpl } : {})
    files.push({ ...blobFileEntry({ name: f.name, mime: f.mime, size: f.size, filekey, desc }),
      added_at: f.added_at })
  }
  const manifest = { ...share.manifest, files }
  const rotated = await rotateScope(relay, signer, {
    scopeId: share.scopeId, generation: share.generation, scopeName: share.scopeName,
    payload: manifest, survivors,
  })
  onProgress(null, 'destroying old ciphertext')
  let deleted = 0
  for (const f of old) deleted += await deleteBlob(f.servers, signer, f.sha256_cipher)
  return { ...rotated, manifest, scrubbed: old.length, deleted }
}
