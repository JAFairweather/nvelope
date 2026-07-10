// smoke.mjs — Nvelope M1 smoke test: key-to-key sharing over NIP-DA.
//
//   node test/smoke.mjs --local     # in-memory relay
//   node test/smoke.mjs             # live public relays
//
// Adversarial observer assertions are first-class: after the flows, we ask
// what a hostile relay operator actually learned.

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { Relay } from '../lib/relay.mjs'
import { LiveRelay, LocalRelay } from '../lib/liverelay.mjs'
import {
  newScopeKey, publishScope, grant, rotateScope,
  receiveGrants, latestGrants, fetchScope,
  loadGrantIndex, saveGrantIndex, toIssuedEntry, fromIssuedEntry, fromReceivedEntry, toReceivedEntry,
} from '../lib/nipxx.mjs'
import { newManifest, inlineFileEntry, inlineBytes, replaceFile, validateManifest } from '../shared/manifest.mjs'

const local = process.argv.includes('--local')
const inner = local ? new Relay() : null
const relay = local ? new LocalRelay(inner)
  : new LiveRelay(['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'])
console.log(local ? 'mode: LOCAL' : 'mode: LIVE')
const settle = () => local ? Promise.resolve() : new Promise(r => setTimeout(r, 1500))

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

const sender = generateSecretKey()
const alice = generateSecretKey()
const bob = generateSecretKey()

try {
  console.log('\n1. Create a share (manifest with two inline files)')
  const share = { scopeId: 'nv' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKey() }
  const manifest = newManifest('Q3 board materials', 'drafts — do not forward')
  manifest.files.push(inlineFileEntry({ name: 'deck.txt', mime: 'text/plain', bytes: new TextEncoder().encode('slide one: numbers go up') }))
  manifest.files.push(inlineFileEntry({ name: 'notes.txt', mime: 'text/plain', bytes: new TextEncoder().encode('remember to breathe') }))
  check('manifest validates', validateManifest(manifest).length === 0)
  const p = await publishScope(relay, sender, { ...share, payload: manifest })
  check('30440 accepted', (p.acks ?? 1) > 0)

  console.log('\n2. Grant to alice and bob; record docket')
  await grant(relay, sender, getPublicKey(alice), { ...share, scopeName: manifest.name })
  await grant(relay, sender, getPublicKey(bob), { ...share, scopeName: manifest.name })
  await saveGrantIndex(relay, sender, {
    issued: [toIssuedEntry({ ...share, scopeName: manifest.name }, [getPublicKey(alice), getPublicKey(bob)])],
    received: [],
  })
  await settle()

  console.log('\n3. Alice dereferences and reads a file')
  const aliceGrants = latestGrants(await receiveGrants(relay, alice))
  const got = await fetchScope(relay, aliceGrants[0])
  check('alice reads manifest', got.status === 'ok' && got.data.name === 'Q3 board materials')
  check('alice decodes file bytes',
    new TextDecoder().decode(inlineBytes(got.data.files.find(f => f.name === 'deck.txt'))) === 'slide one: numbers go up')

  console.log('\n4. Live update: sender replaces a file')
  replaceFile(manifest, 'deck.txt', inlineFileEntry({ name: 'deck.txt', mime: 'text/plain', bytes: new TextEncoder().encode('slide one: numbers go up AND to the right') }))
  manifest.updated_at = Math.floor(Date.now() / 1000)
  await publishScope(relay, sender, { ...share, payload: manifest })
  await settle()
  const got2 = await fetchScope(relay, aliceGrants[0])
  check('alice sees v2 with no action',
    new TextDecoder().decode(inlineBytes(got2.data.files.find(f => f.name === 'deck.txt'))).includes('to the right'))

  console.log('\n5. Revoke bob (rotation), alice survives')
  const rotated = await rotateScope(relay, sender, {
    scopeId: share.scopeId, generation: share.generation, scopeName: manifest.name,
    payload: manifest, survivors: [getPublicKey(alice)],
  })
  Object.assign(share, rotated)
  await settle()
  const aliceAfter = await fetchScope(relay, latestGrants(await receiveGrants(relay, alice))[0])
  const bobAfter = await fetchScope(relay, latestGrants(await receiveGrants(relay, bob))[0])
  check('alice (re-granted) still reads', aliceAfter.status === 'ok')
  check('bob reads stale after revocation', bobAfter.status === 'stale')

  console.log('\n6. Recovery: docket reconstitutes from the sender key alone')
  await saveGrantIndex(relay, sender, {
    issued: [toIssuedEntry({ ...share, scopeName: manifest.name }, [getPublicKey(alice)])],
    received: [],
  })
  await settle()
  const recovered = (await loadGrantIndex(relay, sender)).issued.map(fromIssuedEntry)
  const rShare = { ...recovered[0], publisher: getPublicKey(sender) }
  const rGot = await fetchScope(relay, rShare)
  check('share + audience recovered from nsec', rGot.status === 'ok' && recovered[0].grantees.length === 1)

  // Recipient side of the same guarantee: alice on a fresh device, holding
  // nothing but her nsec — a relay scan reconstitutes every live share,
  // current version, decryptable. No local state, no account, no backup.
  const freshGrants = latestGrants(await receiveGrants(relay, alice))
  const freshGot = await fetchScope(relay, freshGrants[0])
  check('recipient view reconstitutes from nsec alone',
    freshGot.status === 'ok' && freshGot.data.name === 'Q3 board materials'
    && new TextDecoder().decode(inlineBytes(freshGot.data.files.find(f => f.name === 'deck.txt'))).includes('to the right'))

  if (local) {
    console.log('\n7. Adversarial observer view')
    const view = inner.observerView()
    const blob = JSON.stringify(view)
    check('no filenames visible', !blob.includes('deck') && !blob.includes('notes'))
    check('no share name visible', !blob.includes('board'))
    check('no grantee pubkeys visible', !blob.includes(getPublicKey(alice)) && !blob.includes(getPublicKey(bob)))
  }

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close?.()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mSmoke aborted:\x1b[0m', err.message)
  relay.close?.()
  process.exit(1)
}
