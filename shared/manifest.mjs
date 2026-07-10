// manifest.mjs — the Nvelope manifest: the 30440 payload, NIP-44-encrypted
// under the scope key. File keys live INSIDE the manifest, so the scope key
// gates everything (spec §2.1). Small files ride inline as base64; bigger
// bodies live on Blossom as ciphertext (servers + sha256_cipher + filekey).
// A file entry has exactly one of `inline` | `servers`.

export const NVELOPE_VERSION = 1

export function newManifest(name, note = '') {
  return { nvelope: NVELOPE_VERSION, name, note, updated_at: 0, files: [] }
}

/** Minimal structural validation; returns a list of problems (empty = ok). */
export function validateManifest(m) {
  const problems = []
  if (m?.nvelope !== NVELOPE_VERSION) problems.push('unknown nvelope version')
  if (typeof m?.name !== 'string') problems.push('missing name')
  if (!Array.isArray(m?.files)) problems.push('files not an array')
  for (const [i, f] of (m?.files ?? []).entries()) {
    if (!f.name) problems.push(`file[${i}]: no name`)
    if (!f.inline && !f.servers?.length) problems.push(`file[${i}]: neither inline nor servers`)
    if (f.servers?.length && !(f.sha256_cipher && f.filekey)) problems.push(`file[${i}]: blob entry missing hash/key`)
  }
  return problems
}

const b64 = (bytes) => {
  let s = ''
  for (let i = 0; i < bytes.length; i += 0x8000)
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(s)
}
const unb64 = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0))

/** M1 inline entry: file bytes ride inside the encrypted manifest itself. */
export function inlineFileEntry({ name, mime, bytes }) {
  return {
    name, mime, size: bytes.length,
    inline: b64(bytes),
    added_at: Math.floor(Date.now() / 1000),
    replaces: null,
  }
}

export const inlineBytes = (entry) => unb64(entry.inline)

/**
 * M2 blob entry: the body is ciphertext on Blossom servers; the per-file
 * key rides here, inside the scope-encrypted manifest. `desc` is
 * uploadBlob's descriptor {sha256, size, servers} — the hash is of the
 * ciphertext, so verification never needs the key.
 */
export function blobFileEntry({ name, mime, size, filekey, desc }) {
  return {
    name, mime, size,
    servers: desc.servers, sha256_cipher: desc.sha256, size_padded: desc.size,
    filekey: b64(filekey),
    added_at: Math.floor(Date.now() / 1000),
    replaces: null,
  }
}

export const blobKey = (entry) => unb64(entry.filekey)

/** Replace a file in-place: new entry points at what it supersedes. */
export function replaceFile(manifest, oldName, entry) {
  const prior = manifest.files.find(f => f.name === oldName)
  entry.replaces = prior?.sha256_cipher ?? null
  manifest.files = manifest.files.filter(f => f.name !== oldName).concat(entry)
  return manifest
}
