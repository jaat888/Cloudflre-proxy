// Proxy scanner for Cloudflare Workers (free plan). Replaces the Render / Deno scanner.
//
// GET /good[?key=SCAN_KEY] -> {"updated": ts, "count": n, "good": [{"hp","ms","cc","t"}]}   (same format Render app.py reads)
// GET /scan[?key=SCAN_KEY] -> run ONE small batch now (cron does this every minute)
// GET /ping                -> ok
// GET /                    -> short status
//
// Free-plan limits this is built around: 10 ms CPU per run, 50 subrequests per run, 6 simultaneous connections.
// So every run is tiny: it reads ONE small slice of ONE proxy list, then tests ~24 proxies, 6 at a time.
//
// Settings (Worker -> Settings -> Variables and Secrets). SCAN_KEY should be added as a *Secret*.
//   SCAN_KEY      password for /good and /scan (same value as SCANNER_KEY on Render)
//   TEST_URL      https URL to test through each proxy; must NOT be behind Cloudflare (default google generate_204)
//   BATCH         new proxies tested per run (default 16)
//   RETEST        old good proxies re-tested per run (default 8)
//   KEEP          how many fastest proxies to keep (default 40)
//   MAX_MS        max ms per proxy (default 6000)
//   KEEP_AGE_MIN  drop a good proxy this old (default 360)
//
// Supports http:// (CONNECT) and socks5:// (no auth). socks4 is skipped.

import { connect } from "cloudflare:sockets";
import { DurableObject } from "cloudflare:workers";

const SOURCES = [
  { url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", cc: null },
  { url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", cc: null },
  { url: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", cc: null },
  { url: "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt", cc: null },
  { url: "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt", cc: null },
  ...["IN", "US", "DE", "GB", "SG", "NL", "FR", "BR", "ID"].map((c) => ({
    url: `https://raw.githubusercontent.com/iplocate/free-proxy-list/main/countries/${c}/proxies.txt`,
    cc: c,
  })),
];

const MAX_SLICE = 120000; // bytes read from a list per run (keeps CPU low)
const POOL_CAP = 3000; // proxies remembered (stays under the 128 KiB value limit)
const POOL_MIN = 1500; // refill the pool from a list while it is smaller than this
const CONC = 6; // Workers allow 6 simultaneous connections

const enc = new TextEncoder();
const dec = new TextDecoder();
const num = (v, d) => {
  const n = parseInt(v ?? "", 10);
  return Number.isFinite(n) ? n : d;
};

// ---------------------------------------------------------------- socket helpers
class Conn {
  constructor(sock, track) {
    this.track = track;
    track.push(this); // every connection (plain and TLS) is closed when the test ends
    this.sock = sock;
    this.w = sock.writable.getWriter();
    this.r = sock.readable.getReader();
    this.buf = new Uint8Array(0);
  }
  async write(u8) {
    await this.w.write(u8);
  }
  async fill() {
    const { value, done } = await this.r.read();
    if (done || !value) return false;
    const nb = new Uint8Array(this.buf.length + value.length);
    nb.set(this.buf);
    nb.set(value, this.buf.length);
    this.buf = nb;
    return true;
  }
  async exact(n) {
    while (this.buf.length < n) if (!(await this.fill())) throw new Error("eof");
    const out = this.buf.slice(0, n);
    this.buf = this.buf.slice(n);
    return out;
  }
  async headEnd(limit = 4096) {
    for (;;) {
      const s = dec.decode(this.buf);
      const i = s.indexOf("\r\n\r\n");
      if (i >= 0) return s.slice(0, i);
      if (this.buf.length > limit) throw new Error("big");
      if (!(await this.fill())) return s;
    }
  }
  // hand the raw socket over to TLS: locks must be released first
  startTls(hostname) {
    this.w.releaseLock();
    this.r.releaseLock();
    return new Conn(this.sock.startTls({ expectedServerHostname: hostname }), this.track);
  }
  close() {
    try {
      this.sock.close();
    } catch {
      /* already closed */
    }
  }
}

const statusOK = (head) => /^HTTP\/1\.[01] (200|204)/.test(head);
const getReq = (u) => enc.encode(`GET ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.hostname}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`);

async function runTest(hp, target, open) {
  const [sch, rest] = hp.split("://");
  const i = rest.lastIndexOf(":");
  const host = rest.slice(0, i);
  const port = parseInt(rest.slice(i + 1), 10);
  let c = open(host, port);
  const tp = parseInt(target.port || "443", 10);
  if (sch === "socks5") {
    await c.write(new Uint8Array([5, 1, 0]));
    const g = await c.exact(2);
    if (g[0] !== 5 || g[1] !== 0) return false;
    const hb = enc.encode(target.hostname);
    const req = new Uint8Array(7 + hb.length);
    req.set([5, 1, 0, 3, hb.length]);
    req.set(hb, 5);
    req[5 + hb.length] = tp >> 8;
    req[6 + hb.length] = tp & 255;
    await c.write(req);
    const h = await c.exact(4);
    if (h[0] !== 5 || h[1] !== 0) return false;
    if (h[3] === 1) await c.exact(6);
    else if (h[3] === 4) await c.exact(18);
    else if (h[3] === 3) {
      const l = (await c.exact(1))[0];
      await c.exact(l + 2);
    } else return false;
  } else {
    await c.write(enc.encode(`CONNECT ${target.hostname}:${tp} HTTP/1.1\r\nHost: ${target.hostname}:${tp}\r\nUser-Agent: Mozilla/5.0\r\n\r\n`));
    if (!/^HTTP\/1\.[01] 200/.test(await c.headEnd())) return false;
  }
  c = c.startTls(target.hostname); // certificate is verified by the runtime
  await c.write(getReq(target));
  return statusOK(await c.headEnd());
}

async function testOne(hp, target, maxMs) {
  const t0 = Date.now();
  const track = [];
  const open = (host, port) =>
    new Conn(connect({ hostname: host, port }, { secureTransport: "starttls", allowHalfOpen: false }), track);
  let timer;
  const timeout = new Promise((res) => {
    timer = setTimeout(() => res(false), maxMs);
  });
  try {
    if (!(await Promise.race([runTest(hp, target, open), timeout]))) return null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    for (const c of track) c.close();
  }
  const ms = Date.now() - t0;
  return ms <= maxMs ? { hp, ms } : null;
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]);
    }
  }));
  return out;
}

// ---------------------------------------------------------------- list slice parsing
const RE = /(?:(socks5|socks4|http):\/\/|(?<!:\/\/)(?<![\d.]))(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})(?!\d)/g;

function parseSlice(text, defScheme) {
  const out = [];
  for (const m of text.matchAll(RE)) {
    const port = parseInt(m[3], 10);
    if (port <= 0 || port >= 65536) continue;
    const sch = (m[1] || defScheme).toLowerCase();
    if (sch === "socks4") continue;
    out.push(`${sch}://${m[2]}:${m[3]}`);
  }
  return out;
}

async function fetchSlice(src) {
  const big = !src.cc;
  const off = big ? Math.floor(Math.random() * 1200000) : 0;
  const get = (range) => fetch(src.url, { headers: { "User-Agent": "Mozilla/5.0", Range: range } });
  let r = await get(`bytes=${off}-${off + MAX_SLICE - 1}`);
  let cut = off > 0;
  if (r.status === 416) {
    r = await get(`bytes=0-${MAX_SLICE - 1}`);
    cut = false;
  }
  if (!r.ok) return [];
  const buf = new Uint8Array(await r.arrayBuffer()).subarray(0, MAX_SLICE);
  let text = dec.decode(buf);
  if (r.status === 200) cut = false; // server ignored Range, we took the head
  if (cut) text = text.slice(text.indexOf("\n") + 1); // first line may be cut in half
  const def = src.url.includes("socks5") ? "socks5" : "http";
  return parseSlice(text, def).map((hp) => [hp, src.cc]);
}

// pool is stored as text lines "hp cc" (cc may be empty)
const parsePool = (s) => {
  const m = new Map();
  for (const line of s.split("\n")) {
    if (!line) continue;
    const i = line.indexOf(" ");
    m.set(line.slice(0, i), line.slice(i + 1) || null);
  }
  return m;
};
const dumpPool = (m) => [...m].map(([hp, cc]) => `${hp} ${cc ?? ""}`).join("\n");

// ---------------------------------------------------------------- Durable Object (holds the state)
export class Scanner extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.env = env;
    this.busy = false;
  }

  async scan() {
    if (this.busy) return "scan already running";
    this.busy = true;
    const t0 = Date.now();
    try {
      const env = this.env;
      const BATCH = Math.max(4, num(env.BATCH, 16));
      const RETEST = Math.max(0, num(env.RETEST, 8));
      const KEEP = Math.max(5, num(env.KEEP, 40));
      const MAX_MS = Math.max(1500, num(env.MAX_MS, 6000));
      const KEEP_AGE = num(env.KEEP_AGE_MIN, 360) * 60000;
      const target = new URL(env.TEST_URL || "https://www.google.com/generate_204");

      const st = this.ctx.storage;
      const pool = parsePool((await st.get("pool")) || "");
      let good = (await st.get("good")) || [];

      // 1. refill pool from ONE random list slice
      let added = 0;
      if (pool.size < POOL_MIN || Math.random() < 0.3) {
        try {
          const src = SOURCES[Math.floor(Math.random() * SOURCES.length)];
          for (const [hp, cc] of await fetchSlice(src)) {
            if (pool.size >= POOL_CAP) break;
            if (!pool.has(hp)) {
              pool.set(hp, cc);
              added++;
            }
          }
        } catch {
          /* list fetch failed, test what we have */
        }
      }

      // 2. pick: least-recently-tested good ones + random new ones
      const retest = [...good].sort((a, b) => (a.lt || 0) - (b.lt || 0)).slice(0, RETEST).map((g) => g.hp);
      const goodSet = new Set(good.map((g) => g.hp));
      const keys = [...pool.keys()].filter((k) => !goodSet.has(k));
      for (let i = keys.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [keys[i], keys[j]] = [keys[j], keys[i]];
      }
      const fresh = keys.slice(0, BATCH);
      const sample = [...retest, ...fresh];

      // 3. test
      const res = await mapLimit(sample, CONC, (hp) => testOne(hp, target, MAX_MS));
      const now = Date.now();
      const ccSnap = new Map(pool); // country of each pooled proxy (pool entries get deleted below)
      const by = new Map(good.map((g) => [g.hp, g]));
      const next = new Map(by);
      let passed = 0;
      sample.forEach((hp, i) => {
        const r = res[i];
        if (r) passed++;
        if (by.has(hp)) {
          if (r) next.set(hp, { ...by.get(hp), ms: r.ms, lt: now });
          else next.delete(hp); // old good one stopped working
        } else {
          pool.delete(hp); // tested once: never test it again from the pool
          if (r) next.set(hp, { hp, ms: r.ms, cc: ccSnap.get(hp) ?? null, t: now, lt: now });
        }
      });
      good = [...next.values()]
        .filter((g) => now - g.t <= KEEP_AGE)
        .sort((a, b) => a.ms - b.ms)
        .slice(0, KEEP);

      const note = `${sample.length} test, ${passed} chale, pool ${pool.size} (+${added}), list me ${good.length}` +
        (good.length ? `, sabse tez ${good[0].ms} ms` : "") + ` (${Math.round((Date.now() - t0) / 1000)} sec)`;
      await st.put("pool", dumpPool(pool));
      await st.put("good", good);
      await st.put("meta", { updated: now, note });
      return note;
    } catch (e) {
      return `scan fail: ${e && e.name}: ${String(e && e.message).slice(0, 100)}`;
    } finally {
      this.busy = false;
    }
  }

  async fetch(request) {
    const u = new URL(request.url);
    const headers = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
    if (u.pathname === "/scan") return new Response(JSON.stringify({ note: await this.scan() }), { headers });
    const good = (await this.ctx.storage.get("good")) || [];
    const meta = (await this.ctx.storage.get("meta")) || { updated: null, note: "abhi scan nahi hua" };
    if (u.pathname === "/good") {
      return new Response(JSON.stringify({
        updated: meta.updated ? meta.updated / 1000 : null,
        count: good.length,
        good: good.map((g) => ({ hp: g.hp, ms: g.ms, cc: g.cc ?? null, t: g.t / 1000 })),
      }), { headers });
    }
    const ago = meta.updated ? `${Math.round((Date.now() - meta.updated) / 1000)} sec pehle` : "-";
    return new Response(`proxy scanner (cloudflare)\nlist me: ${good.length}\nlast scan: ${ago}\n${meta.note}\n`, {
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
}

// ---------------------------------------------------------------- Worker entry
const stubOf = (env) => env.SCANNER.get(env.SCANNER.idFromName("main"));

export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname === "/ping") return new Response("ok", { headers: { "content-type": "text/plain" } });
    const KEY = (env.SCAN_KEY || "").trim();
    if ((u.pathname === "/good" || u.pathname === "/scan") && KEY && u.searchParams.get("key") !== KEY) {
      return new Response('{"error":"key galat"}', { status: 403, headers: { "content-type": "application/json" } });
    }
    return stubOf(env).fetch(`https://scanner${u.pathname}`);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(stubOf(env).fetch("https://scanner/scan"));
  },
};
