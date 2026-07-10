// pad.mjs — bucket padding. Blob hosts (and anyone watching them) see upload
// sizes; padding to 2^n × 64 KiB classes means they learn only the class,
// never the true byte count. Same length-prefix idea as NIP-44's padding,
// scaled up for files.

const BASE = 65536                       // 64 KiB — the smallest class

/** Smallest bucket (64 KiB × 2^n) that holds `n` bytes. */
export function bucketSize(n) {
  let b = BASE
  while (b < n) b *= 2
  return b
}

/** 4-byte big-endian length prefix + bytes + zero fill to the bucket. */
export function pad(bytes) {
  const out = new Uint8Array(bucketSize(bytes.length + 4))
  new DataView(out.buffer).setUint32(0, bytes.length)
  out.set(bytes, 4)
  return out
}

/** Recover the original bytes from a padded buffer. */
export function unpad(padded) {
  const len = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0)
  if (len + 4 > padded.byteLength) throw new Error('corrupt padding')
  return padded.slice(4, 4 + len)
}
