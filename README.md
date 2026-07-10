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

Status: **v1 feature-complete alpha** — all five milestones done:

- **M1** key-to-key sharing: encrypted manifests, grants, live update,
  revocation, recovery from the nsec alone.
- **M2** encrypted Blossom blobs to 250 MB — padded to size classes,
  mirrored, hash-verified; replace-file with BUD-02 cleanup.
- **M3** bearer invite links: secret rides the URL fragment only;
  claim-to-own rotates every outstanding link dead.
- **M4** revoke-and-scrub (re-key blobs, destroy old ciphertext), NIP-49
  passphrase-protected key at rest, printable recovery card, zero-egress
  test, [SECURITY.md](SECURITY.md) threat model.
- **M5** business seams, deliberately without the business: a Settings tab
  for per-device relay and Blossom server lists (localStorage, defaults =
  public free-tier servers, honestly labeled "no persistence guarantee");
  per-server upload refusals surfaced with a fix attached (401/402/403 →
  "requires auth/payment — provision the managed server or remove it");
  storage-quota surfacing (padded ciphertext bytes per share and in total —
  the number a quota would meter); and optional share aliases stored in the
  encrypted Grant Index. **Resolving an alias to a friendly public URL
  (nvelope.example/s/q3-board) needs a naming service — DNS or a hosted
  directory. That is a paid-tier concern and out of scope here**, as are
  payments, accounts, and persistence promises: Nvelope ships the seams
  (configurable endpoints, BUD-01 auth on every request, honest errors),
  not the machinery.

Built on draft NIP-DA
([review pending](https://github.com/nostr-protocol/nips/pull/2411));
kind numbers may change — use throwaway keys, treat shares as ephemeral.

```
npm install
npm run smoke:local   # in-memory relay, 12 assertions incl. adversarial observer view
npm run smoke         # same against live public relays
npm run blossom       # blob pipeline + scrub + refusal seams vs mock Blossom servers (33)
npm run invite        # bearer-link lifecycle + index seams (19)
npm run egress        # nothing leaves except configured relays/Blossom/esm.sh (13)
npm run blob:live     # large-file acceptance against the real default servers
npm run web           # http://localhost:4441/
```

Pure client: no server, no accounts, no build step. `lib/` is vendored from
the protocol repo (`npm run sync-lib`). MIT.
