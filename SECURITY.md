# Security — what Nvelope protects, and what it honestly cannot

Nvelope is a pure client. There is no Nvelope server: all cryptography runs
in your browser, and the only things that ever leave it are ciphertext and
routing envelopes. This document is the threat model in plain language.
Read the "NOT protected" half as carefully as the first half — tools that
overclaim get people hurt.

## What is protected

**Your files and their names.** A share is one encrypted manifest (a NIP-DA
scoped data set) on ordinary nostr relays. File contents ≤48 KB ride inside
the manifest; larger files are encrypted under their own random key
(XChaCha20-Poly1305, key inside the manifest) and stored on Blossom blob
hosts as ciphertext. Relays and blob hosts never see file contents, file
names, share names, or notes.

**Who you share with.** Grants are delivered as NIP-59 gift wraps: a relay
sees an ephemeral pubkey handing an opaque blob to a recipient. The grant
graph — who shares what with whom — never appears on the wire in readable
form. Our test suites assert this from the adversary's side: after every
flow, an "observer view" check confirms a hostile relay or blob-host
operator learned no names, no contents, no grantee keys.

**True file sizes.** Blobs are padded to power-of-two size classes (64 KiB,
128 KiB, …) before encryption, so a host learns only the class, never the
exact byte count.

**Your key at rest.** Nothing is persisted unless you opt in. With a NIP-07
extension your key never touches the page. With the "protect this key"
offer, the only thing stored is a NIP-49 ncryptsec — your key encrypted
with your passphrase (scrypt) — unlocked locally on each visit.

**Revocation, with teeth if you want them.** Unsharing rotates the scope
key and re-grants the survivors; the revoked party sees nothing new.
Revoke-and-scrub goes further: every blob is re-encrypted under fresh keys,
re-uploaded, and the old ciphertext is deleted from the hosts immediately —
a saved copy of the old manifest then dereferences to nothing.

**No hidden egress.** `npm run egress` statically asserts that the app and
shared code contain no network destinations beyond the configured relays,
the two default Blossom hosts, and esm.sh (which serves the pinned
nostr-tools / @noble modules). What that test does and does not cover is
documented in its header.

## What is NOT protected

**No DRM, no view-only.** A recipient can save, copy, screenshot, or
forward anything they can read. Encryption gates access; it cannot control
what an authorized reader does next. Nvelope will never pretend otherwise.

**Revoked parties keep prior downloads.** Revocation ends access to future
updates and (with scrub) to the stored ciphertext. It cannot reach into
someone else's disk. That is physics, and the UI says so at the moment you
revoke.

**No audit log.** There is no server, so there is no record of who opened
what, when. If you need provable access logs, this is the wrong tool.

**Deletion is a request.** BUD-02 blob deletes and NIP-01 replacements work
on honest servers; a malicious or negligent relay or host may keep old
ciphertext forever. Scrub makes old ciphertext useless on conforming hosts;
assume a hostile host still holds the (encrypted) bytes.

**Traffic metadata.** Relays see your pubkey's activity: when you publish,
how often, from what IP (use Tor/VPN if that matters). Blob hosts see
padded sizes, upload/download timing, and IPs. A global observer can
correlate who talks to which servers when. Nvelope hides content and the
grant graph, not the fact that you use it.

**Bearer invite links are bearer tokens.** Anyone holding the URL holds the
access — forwarding the link forwards the share. The secret rides only in
the URL fragment (never sent to any server), the link dies when claimed or
revoked, but until then possession is the credential. Treat links like the
files themselves.

**The code delivery path.** The app loads pinned modules from esm.sh with
no build step. You are trusting that CDN (and whoever serves you the page)
not to tamper with the code. Auditable, but not trustless — serve it
yourself if your threat model requires it.

**Draft protocol.** Nvelope is built on draft NIP-DA
([review pending](https://github.com/nostr-protocol/nips/pull/2411)); kind
numbers are placeholders and may change. Until the NIP settles, use
throwaway keys and treat shares as ephemeral.

**Your passphrase and your nsec.** NIP-49 protection is only as strong as
the passphrase; a weak one falls to offline guessing if your device is
compromised. And the nsec itself is the account — anyone holding it IS you.
Print it, write it down, keep it offline. There is no reset.

## Reporting

Found a hole? Open an issue at
<https://github.com/JAFairweather/nvelope/issues> — or, for anything
sensitive, contact the maintainer privately first.
