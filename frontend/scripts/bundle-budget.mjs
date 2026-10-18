// SPDX-License-Identifier: Apache-2.0
// Bundle budget (gzip): what the first page load fetches, read from the built dist/index.html (the entry script, its
// module preloads and stylesheets), and the largest lazily loaded page. Run after `npm run build`; exits 1 when over.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const BUDGET = { initialJs: 180, css: 35, pageChunk: 60 }; // KB, gzip
const dist = new URL("../dist/", import.meta.url).pathname;
const html = readFileSync(join(dist, "index.html"), "utf8");
const gz = (file) => gzipSync(readFileSync(join(dist, file)), { level: 9 }).length / 1024;
const refs = (re) => [...html.matchAll(re)].map((m) => m[1].replace(/^\//, ""));

const initial = [...refs(/<script[^>]+src="([^"]+\.js)"/g), ...refs(/rel="modulepreload"[^>]+href="([^"]+)"/g)].filter((f) => f.startsWith("assets/"));
const styles = refs(/rel="stylesheet"[^>]+href="([^"]+)"/g);
const lazy = readdirSync(join(dist, "assets")).filter((f) => f.endsWith(".js") && !initial.includes(`assets/${f}`));
const largest = lazy.map((f) => [f, gz(`assets/${f}`)]).sort((a, b) => b[1] - a[1])[0] ?? ["none", 0];

const rows = [
  ["Initial JavaScript", initial.reduce((n, f) => n + gz(f), 0), BUDGET.initialJs, initial.length + " file(s)"],
  ["CSS", styles.reduce((n, f) => n + gz(f), 0), BUDGET.css, styles.length + " file(s)"],
  ["Largest page chunk", largest[1], BUDGET.pageChunk, largest[0]],
];
let over = false;
for (const [name, kb, max, note] of rows) {
  const ok = kb <= max;
  over ||= !ok;
  console.log(`${ok ? "ok  " : "OVER"} ${name.padEnd(20)} ${kb.toFixed(1).padStart(6)} KB of ${max} KB  (${note})`);
}
process.exit(over ? 1 : 0);
