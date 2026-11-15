#!/usr/bin/env node
// Rebuild every in-scope page from the templates, the span raws and the
// committed catalog, then diff that against the committed pages.
// A missing message or argument throws. A render that does not match the
// recorded page text throws. This file is not part of `make deploy`.

import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { render } = await import(pathToFileURL(join(root, "i18n/generated/esm/solpbc-org/api.mjs")).href);

const TOKEN = /%%([^%]+)%%/g;
const spans = JSON.parse(readFileSync(join(root, "i18n/spans.json"), "utf8"));
const failures = [];

function fail(msg) {
  failures.push(msg);
}

function expand(rel) {
  const template = readFileSync(join(root, "i18n/templates", rel), "utf8");
  const list = spans.files[rel];
  if (!list) throw new Error(`no spans for ${rel}`);
  let i = 0;
  const out = template.replace(TOKEN, (_m, body) => {
    const rec = list[i++];
    if (!rec) throw new Error(`${rel}: extra token ${body}`);
    const rendered = render("en-US", rec.id, rec.args, { useIsolating: false });
    const [start, end] = rec.slice;
    const piece = rendered.slice(start, end);
    if (piece !== rec.decoded) {
      throw new Error(
        `${rel}: ${rec.id} slice ${start}:${end} rendered ${JSON.stringify(piece)} but the page text is ${JSON.stringify(rec.decoded)}`
      );
    }
    const whole = rec.id;
    const partial = `${rec.id}|${start}:${end}`;
    if (body !== whole && body !== partial) {
      throw new Error(`${rel}: token ${body} does not match span ${partial}`);
    }
    if (body === whole && !(start === 0 && end === rendered.length)) {
      throw new Error(`${rel}: ${rec.id} is marked whole but covers ${start}:${end} of ${rendered.length}`);
    }
    return rec.raw;
  });
  if (i !== list.length) throw new Error(`${rel}: used ${i} of ${list.length} spans`);
  if (out.includes("%%")) throw new Error(`${rel}: a %% token survived expansion`);
  return out;
}

const builtPages = new Map();
for (const rel of Object.keys(spans.files).sort()) {
  try {
    builtPages.set(rel, expand(rel));
  } catch (err) {
    fail(String(err && err.message ? err.message : err));
  }
}
const writing = process.argv.includes("--write") && failures.length === 0;
for (const [rel, built] of builtPages) {
  const page = join(root, rel);
  if (writing) writeFileSync(page, built);
  const committed = readFileSync(page, "utf8");
  if (built !== committed) {
    let at = 0;
    const n = Math.min(built.length, committed.length);
    while (at < n && built[at] === committed[at]) at += 1;
    fail(`${rel}: rebuilt page differs at ${at} (rebuilt ${built.length} bytes, committed ${committed.length})`);
  }
}

// Plain authoring lines (no "{") must match render(). A source edit that
// does not regenerate the committed ESM fails here, even when the pages
// still match the old render.
const ftl = readFileSync(join(root, "i18n/catalog/source/en-US.ftl"), "utf8");
const seen = new Set();
for (const line of ftl.split("\n")) {
  const m = /^(solpbc\.[A-Za-z0-9.]+) = (.*)$/.exec(line);
  if (!m) continue;
  seen.add(m[1]);
  if (m[2].includes("{")) continue;
  let rendered;
  try {
    rendered = render("en-US", m[1], [], { useIsolating: false });
  } catch (err) {
    fail(`${m[1]}: ${err.message}`);
    continue;
  }
  if (rendered !== m[2]) {
    fail(`${m[1]}: catalog source ${JSON.stringify(m[2])} but render() returned ${JSON.stringify(rendered)}`);
  }
}
const sidecars = readdirSync(join(root, "i18n/catalog/meta")).filter((name) => name.endsWith(".json"));
if (seen.size !== sidecars.length) {
  fail(`catalog id lines ${seen.size} do not match meta sidecars ${sidecars.length}`);
}

const compiler = process.env.I18N_CATALOG;
if (compiler) {
  const dir = mkdtempSync(join(tmpdir(), "solpbc-i18n-"));
  const run = spawnSync(compiler, [
    "targets",
    join(root, "i18n/catalog"),
    "--channel", "production",
    "--locale", "en-US",
    "--target", "esm",
    "--out", dir,
  ], { encoding: "utf8" });
  if (run.status !== 0) {
    fail(`i18n-catalog targets exited ${run.status}: ${(run.stderr || run.stdout || "").slice(0, 400)}`);
  } else {
    const freshRoot = join(dir, "esm");
    const committedRoot = join(root, "i18n/generated/esm");
    const names = new Set();
    const walk = (base, rel = "") => {
      for (const ent of readdirSync(join(base, rel), { withFileTypes: true })) {
        const next = rel ? `${rel}/${ent.name}` : ent.name;
        if (ent.isDirectory()) walk(base, next);
        else names.add(next);
      }
    };
    walk(freshRoot);
    walk(committedRoot);
    for (const name of [...names].sort()) {
      const freshPath = join(freshRoot, name);
      const committedPath = join(committedRoot, name);
      let fresh, committed;
      try { fresh = readFileSync(freshPath); } catch { fail(`regenerated esm missing ${name}`); continue; }
      try { committed = readFileSync(committedPath); } catch { fail(`committed esm missing ${name}`); continue; }
      if (!fresh.equals(committed)) fail(`regenerated esm differs: ${name}`);
    }
  }
  rmSync(dir, { recursive: true, force: true });
}

if (failures.length) {
  for (const msg of failures) console.error(msg);
  process.exit(1);
}
console.log(`ok ${Object.keys(spans.files).length} pages, ${seen.size} messages`);
