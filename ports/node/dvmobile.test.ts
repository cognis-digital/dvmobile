/** Smoke test for the Node/TS port. Pure stdlib (node:assert + node:test).
 *  Proves real offline lookups against the bundled OSV DB. */
import * as assert from "node:assert";
import { test } from "node:test";
import { loadChallenges, byCve, enrichChallenge } from "./dvmobile";

test("catalog has the four MASVS challenges", () => {
  const cs = loadChallenges();
  assert.strictEqual(cs.length, 4);
  assert.ok(cs.some((c) => c.id === "jwt-none"));
});

test("log4j (CVE-2021-44228) resolves in the bundled DB", () => {
  const hits = byCve("CVE-2021-44228");
  assert.ok(hits.length >= 1);
  assert.match(hits[0].summary || "", /Log4j/i);
});

test("ghsa alias resolves the same record", () => {
  const hits = byCve("GHSA-jfh8-c2jp-5v3q");
  assert.ok(hits.length >= 1);
});

test("unknown id returns empty", () => {
  assert.strictEqual(byCve("CVE-0000-00000").length, 0);
});

test("every challenge's real-world CVEs resolve offline", () => {
  for (const c of loadChallenges()) {
    const e = enrichChallenge(c);
    assert.strictEqual(e.unresolved.length, 0, `${c.id} has unresolved: ${e.unresolved}`);
    assert.ok(e.resolved.length >= 1);
  }
});
