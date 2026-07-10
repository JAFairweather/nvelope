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

Status: **alpha** — M1 (key-to-key sharing, inline files ≤48 KB). Blossom
blob storage, invite links, and revoke-and-scrub are next. Built on draft
NIP-DA ([review pending](https://github.com/nostr-protocol/nips/pull/2411));
kind numbers may change.

```
npm install
npm run smoke:local   # in-memory relay, 11 assertions incl. adversarial observer view
npm run smoke         # same against live public relays
npm run web           # http://localhost:4441/
```

Pure client: no server, no accounts, no build step. `lib/` is vendored from
the protocol repo (`npm run sync-lib`). MIT.
