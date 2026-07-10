// invite.mjs — Nvelope M3 test: bearer invite links, in-memory relay.
// Full loop: mint link → open → claim → approve → pre-claim link dead.
//
//   node test/invite.mjs

import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { Relay } from '../lib/relay.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import {
  newScopeKey, publishScope, grant,
  receiveGrants, latestGrants, fetchScope,
  loadGrantIndex, saveGrantIndex, toIssuedEntry,
} from '../lib/nipxx.mjs'
import { newManifest, inlineFileEntry, inlineBytes } from '../shared/manifest.mjs'
import {
  buildInviteUrl, parseInviteFragment, createInvite,
  sendClaimRequest, pollClaims, approveClaim,
} from '../shared/invite.mjs'

const inner = new Relay()
const relay = new LocalRelay(inner)

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

const sender = generateSecretKey()
const alice = generateSecretKey()

try {
  console.log('\n1. The link: secret rides the fragment only, round-trips exactly')
  const tmp = generateSecretKey()
  const url = buildInviteUrl('https://nvelope.example/app/', tmp, ['wss://a.example', 'wss://b.example'])
  const u = new URL(url)
  const parsed = parseInviteFragment(u.hash)
  check('nsec round-trips through the fragment', parsed.sk.length === 32 && parsed.sk.every((b, i) => b === tmp[i]))
  check('relay hints round-trip', parsed.relays.join(',') === 'wss://a.example,wss://b.example')
  check('nothing secret outside the fragment', u.pathname + u.search === '/app/' && !u.username && !u.password)
  check('junk fragments rejected', parseInviteFragment('#received') === null
    && parseInviteFragment(`#i=${nip19.npubEncode(getPublicKey(tmp))}`) === null
    && parseInviteFragment('') === null)

  console.log('\n2. Sender: share + normal grantee + bearer invite, ledger in the index')
  const share = {
    scopeId: 'nv' + Math.random().toString(36).slice(2, 8),
    scopeName: 'Q3 board materials', generation: 1, scopeKey: newScopeKey(), grantees: [],
  }
  const manifest = newManifest('Q3 board materials')
  manifest.files.push(inlineFileEntry({ name: 'deck.txt', mime: 'text/plain', bytes: new TextEncoder().encode('slide one: numbers go up') }))
  share.manifest = manifest
  await publishScope(relay, sender, { ...share, payload: manifest })
  await grant(relay, sender, getPublicKey(alice), share)
  share.grantees.push(getPublicKey(alice))

  const inv = await createInvite(relay, sender, share, 'wss://hint.example')
  share.grantees.push(inv.pub)
  let invites = [{ pub: inv.pub, scope: share.scopeId, created_at: Math.floor(Date.now() / 1000) }]
  await saveGrantIndex(relay, sender, {
    issued: [toIssuedEntry(share, share.grantees)], received: [], nvelope_invites: invites,
  })
  const idx = await loadGrantIndex(relay, sender)
  check('bearer flag survives in the index (app-level field, no lib change)',
    idx.nvelope_invites?.length === 1 && idx.nvelope_invites[0].pub === inv.pub
    && idx.nvelope_invites[0].scope === share.scopeId)
  check('invite is a normal grantee in the issued entry', idx.issued[0].grantees.includes(inv.pub))

  console.log('\n3. Anyone with the link opens the share — no login, no other key material')
  const opened = latestGrants(await receiveGrants(relay, inv.sk))
  const got = await fetchScope(relay, opened[0])
  check('link dereferences the live manifest', got.status === 'ok' && got.data.name === 'Q3 board materials')
  check('link downloads file bytes',
    new TextDecoder().decode(inlineBytes(got.data.files[0])) === 'slide one: numbers go up')

  console.log('\n4. Claim request rides a gift wrap; forgeries are dropped')
  const rSk = generateSecretKey()
  const rPub = getPublicKey(rSk)
  await sendClaimRequest(relay, inv.sk, getPublicKey(sender), share.scopeId, rPub)
  const mallory = generateSecretKey() // never held the link
  await sendClaimRequest(relay, mallory, getPublicKey(sender), share.scopeId, getPublicKey(mallory))
  const claims = await pollClaims(relay, sender, idx.nvelope_invites)
  check('sender sees exactly the real claim', claims.length === 1
    && claims[0].rPub === rPub && claims[0].invitePub === inv.pub && claims[0].scope === share.scopeId)

  console.log('\n5. Approve: grant R, rotate every bearer key out')
  const res = await approveClaim(relay, sender, share, invites, claims[0])
  check('bearer key retired by the rotation', res.retired.length === 1 && res.retired[0] === inv.pub
    && !res.survivors.includes(inv.pub) && res.survivors.includes(rPub))
  Object.assign(share, { generation: res.generation, scopeKey: res.scopeKey, grantees: res.survivors })
  invites = [{ ...invites[0], claimed_by: rPub, claimed_at: Math.floor(Date.now() / 1000) }]
  await saveGrantIndex(relay, sender, {
    issued: [toIssuedEntry(share, share.grantees)], received: [], nvelope_invites: invites,
  })
  const rGot = await fetchScope(relay, latestGrants(await receiveGrants(relay, rSk))[0])
  check('claimed key reads the share', rGot.status === 'ok' && rGot.data.name === 'Q3 board materials')
  const aGot = await fetchScope(relay, latestGrants(await receiveGrants(relay, alice))[0])
  check('prior grantee survives the claim rotation', aGot.status === 'ok')

  console.log('\n6. The pre-claim link is dead')
  const dead = await fetchScope(relay, latestGrants(await receiveGrants(relay, inv.sk))[0])
  check('old link reads stale after claim', dead.status === 'stale')
  check('claim leaves the pending queue once the invite is marked claimed',
    (await pollClaims(relay, sender, invites)).length === 0)

  console.log('\n7. Adversarial observer view')
  const blob = JSON.stringify(inner.observerView())
  check('no share name or filenames visible', !blob.includes('board') && !blob.includes('deck'))
  check('no bearer or claimer pubkeys visible', !blob.includes(inv.pub) && !blob.includes(rPub))
  check('no claim marker visible', !blob.includes('nvelope_claim') && !blob.includes('r_pub'))

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mInvite test aborted:\x1b[0m', err)
  process.exit(1)
}
