# Nvelope

**Simple, secure document sharing on nostr.** Live folders instead of stale
attachments; revocation instead of expiring links; one-key recovery instead
of accounts.

A *Share* is one encrypted manifest on regular nostr relays (a NIP-DA
[Scoped Data Set](https://github.com/JAFairweather/nostr-scoped-data-grants)).
Sharing hands someone the decryption key, privately. Replace a file and every
recipient sees the new version on their next fetch — nobody re-sends
anything. Unsharing rotates the key: recipients keep what they downloaded
(honesty is a feature), but see nothing new. Relays store only ciphertext and
never learn who shares what with whom.

Status: **alpha** — M1 key-to-key sharing, M2 encrypted Blossom blobs (to
250 MB, padded + mirrored), M3 bearer invite links with claim-to-own, and
M4 revoke-and-scrub, NIP-49 passphrase-protected key at rest, printable
recovery card, and a zero-egress test — all done. Built on draft NIP-DA
([review pending](https://github.com/nostr-protocol/nips/pull/2411));
kind numbers may change. Threat model — including what is deliberately NOT
promised — in [SECURITY.md](SECURITY.md).

```
npm install
npm run smoke:local   # in-memory relay, 12 assertions incl. adversarial observer view
npm run smoke         # same against live public relays
npm run blossom       # blob pipeline + revoke-and-scrub vs mock Blossom servers (30)
npm run invite        # bearer-link lifecycle (17)
npm run egress        # nothing leaves except configured relays/Blossom/esm.sh
npm run web           # http://localhost:4441/
```

Pure client: no server, no accounts, no build step. `lib/` is vendored from
the protocol repo (`npm run sync-lib`). MIT.
