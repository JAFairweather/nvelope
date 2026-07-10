// config.mjs — per-device endpoint configuration (M5 seam). Which relays and
// Blossom servers this browser talks to is user policy, not code: stored in
// localStorage (non-secret — endpoints, not keys), defaults = the shipped
// constants. Nothing here is a payment system; a "managed" server is just an
// endpoint the user expects to demand auth or payment (see settings UI).
//
// DOM-free on purpose: storage is injectable so Node tests exercise the
// load/save/sanitize path, and test/egress.mjs imports this module to
// cross-check the shipped defaults against its allowlist.

import { DEFAULT_SERVERS } from './blossom.mjs'

export const DEFAULT_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']
export const CONFIG_KEY = 'nvelope-config'

/** The shipped configuration: public free-tier infrastructure. */
export const defaultConfig = () => ({
  relays: [...DEFAULT_RELAYS],
  // { url, requiresAuth }: requiresAuth marks a managed endpoint — one the
  // user expects to gate uploads behind an account or payment. Nvelope signs
  // BUD-01 auth events on every upload/delete regardless; the flag is about
  // expectations (and error copy), not behavior.
  servers: DEFAULT_SERVERS.map(url => ({ url, requiresAuth: false })),
})

const validRelay = (u) => { try { return new URL(u).protocol === 'wss:' } catch { return false } }
const validServer = (u) => { try { return /^https?:$/.test(new URL(u).protocol) } catch { return false } }
const strip = (u) => u.trim().replace(/\/+$/, '')

/** Coerce anything into a usable config; empty/invalid lists fall back to
 *  the defaults — a broken config must never brick the app. */
export function sanitizeConfig(raw) {
  const cfg = defaultConfig()
  const relays = [...new Set((Array.isArray(raw?.relays) ? raw.relays : [])
    .filter(r => typeof r === 'string').map(strip).filter(validRelay))]
  if (relays.length) cfg.relays = relays
  const seen = new Set()
  const servers = (Array.isArray(raw?.servers) ? raw.servers : [])
    .map(s => typeof s === 'string' ? { url: s } : s)
    .filter(s => typeof s?.url === 'string')
    .map(s => ({ url: strip(s.url), requiresAuth: !!s.requiresAuth }))
    .filter(s => validServer(s.url) && !seen.has(s.url) && seen.add(s.url))
  if (servers.length) cfg.servers = servers
  return cfg
}

export function loadConfig(storage = globalThis.localStorage) {
  try { return sanitizeConfig(JSON.parse(storage?.getItem(CONFIG_KEY))) }
  catch { return defaultConfig() }
}

export function saveConfig(cfg, storage = globalThis.localStorage) {
  const clean = sanitizeConfig(cfg)
  storage?.setItem(CONFIG_KEY, JSON.stringify(clean))
  return clean
}

export function resetConfig(storage = globalThis.localStorage) {
  storage?.removeItem(CONFIG_KEY)
  return defaultConfig()
}
