#!/usr/bin/env node
/**
 * dvmobile (TypeScript/Node port) — mirrors the primary CLI surface of the
 * Python tool: list challenges, look up a CVE/GHSA in the bundled offline OSV
 * DB, and show the real-world CVE context for each MASVS challenge.
 *
 * Offline only. Reads the same data the Python package ships:
 *   - ../challenges.json                 (shared challenge catalog)
 *   - ../../dvmobile/cognis_vulndb.jsonl.gz   (262k real OSV records)
 *
 *   node dvmobile.js challenges [--cves]
 *   node dvmobile.js cve CVE-2021-44228
 *   node dvmobile.js enrich [challenge-id]
 */
import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";

interface Challenge {
  id: string;
  title: string;
  category: string;
  difficulty: string;
  masvs: string;
  cwe: string;
  hint: string;
  real_world_cves: string[];
}

interface VulnRecord {
  id: string;
  aliases?: string[];
  ecosystem?: string;
  summary?: string;
  severity?: string;
  packages?: string[];
}

/** Walk up from a start dir until a relative path exists (handles running from
 *  source dir or a compiled dist/ subdir). */
function findUp(rel: string, start: string = __dirname): string {
  let dir = start;
  for (let i = 0; i < 6; i++) {
    const cand = path.join(dir, rel);
    if (fs.existsSync(cand)) return cand;
    dir = path.dirname(dir);
  }
  return path.join(start, rel);
}

const CATALOG = findUp(path.join("ports", "challenges.json"));
const DB = findUp(path.join("dvmobile", "cognis_vulndb.jsonl.gz"));

export function loadChallenges(file: string = CATALOG): Challenge[] {
  return JSON.parse(fs.readFileSync(file, "utf-8"));
}

/** Stream the gz line-by-line and return every record matching a CVE/GHSA id. */
export function byCve(cve: string, dbPath: string = DB): VulnRecord[] {
  const want = (cve || "").toUpperCase();
  if (!want || !fs.existsSync(dbPath)) return [];
  const raw = zlib.gunzipSync(fs.readFileSync(dbPath)).toString("utf-8");
  const out: VulnRecord[] = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    const r: VulnRecord = JSON.parse(t);
    const ids = [r.id, ...(r.aliases || [])].map((x) => (x || "").toUpperCase());
    if (ids.includes(want)) out.push(r);
  }
  return out;
}

export function enrichChallenge(c: Challenge, dbPath: string = DB) {
  const matches: VulnRecord[] = [];
  const resolved: string[] = [];
  const unresolved: string[] = [];
  for (const cve of c.real_world_cves) {
    const hits = byCve(cve, dbPath);
    if (hits.length) {
      resolved.push(cve);
      matches.push(hits[0]);
    } else {
      unresolved.push(cve);
    }
  }
  return { id: c.id, masvs: c.masvs, cwe: c.cwe, resolved, unresolved, matches };
}

function pad(s: string, n: number): string {
  return (s + " ".repeat(n)).slice(0, n);
}

function main(argv: string[]): number {
  const [cmd, ...rest] = argv;
  if (cmd === "challenges") {
    const showCves = rest.includes("--cves");
    for (const c of loadChallenges()) {
      console.log(`${pad(c.id, 16)} [${pad(c.difficulty, 6)}] ${pad(c.masvs, 14)} ${c.title}`);
      if (showCves && c.real_world_cves.length) {
        console.log(`                 ${c.cwe}  real-world: ${c.real_world_cves.join(", ")}`);
      }
    }
    return 0;
  }
  if (cmd === "cve") {
    const hits = byCve(rest[0] || "");
    if (!hits.length) {
      console.log(`no match for ${rest[0]} in the bundled offline DB`);
      return 1;
    }
    for (const r of hits) {
      console.log(`${r.id}  [${r.ecosystem || ""}]  ${(r.aliases || []).join(", ")}`);
      console.log(`  ${r.summary || ""}`);
    }
    return 0;
  }
  if (cmd === "enrich") {
    const cs = loadChallenges();
    const sel = rest[0] ? cs.filter((c) => c.id === rest[0]) : cs;
    if (rest[0] && !sel.length) {
      console.log(`unknown challenge: ${rest[0]}`);
      return 2;
    }
    for (const c of sel) {
      const e = enrichChallenge(c);
      console.log(`${e.id}  ${e.masvs}  ${e.cwe}  (${e.resolved.length} CVEs resolved offline)`);
      for (const m of e.matches) {
        const cve = (m.aliases || []).find((a) => a.startsWith("CVE")) || m.id;
        console.log(`  ${pad(cve, 18)} ${(m.summary || "").slice(0, 70)}`);
      }
    }
    return 0;
  }
  console.log("usage: dvmobile (challenges [--cves] | cve <id> | enrich [id])");
  return 1;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}
