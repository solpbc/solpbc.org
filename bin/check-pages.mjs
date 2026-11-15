#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, mkdtempSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildPages } from './render-pages.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const write = process.argv.includes('--write');
const compiler = process.env.I18N_CATALOG;
if (write && !compiler) throw new Error('--write requires I18N_CATALOG pointing to the pinned compiler');
const generated = join(root, 'i18n/generated');
function files(base, rel = '') {
  return readdirSync(join(base, rel), {withFileTypes:true}).flatMap(e => e.isDirectory() ? files(base, join(rel,e.name)) : [join(rel,e.name)]).sort();
}
function inputs() {
  return Object.fromEntries(['i18n/compiler.json', ...files(join(root,'i18n/catalog')).map(n=>'i18n/catalog/'+n), ...files(join(generated,'esm')).map(n=>'i18n/generated/esm/'+n)].map(n=>[n,createHash('sha256').update(readFileSync(join(root,n))).digest('hex')]));
}
if (compiler) {
  const temp = mkdtempSync(join(tmpdir(), 'solpbc-i18n-'));
  try {
    const out = join(temp,'targets');
    const result = spawnSync(compiler, ['targets',join(root,'i18n/catalog'),'--channel','production','--locale','en-US','--target','esm','--out',out], {encoding:'utf8'});
    if (result.status !== 0) throw new Error(`Catalog compiler failed: ${result.error || result.stderr || result.stdout}`);
    if (write) {
      rmSync(join(generated,'esm'), {recursive:true,force:true});
      cpSync(join(out,'esm'),join(generated,'esm'),{recursive:true});
      writeFileSync(join(generated,'inputs.json'),JSON.stringify(inputs(),null,2)+'\n');
    } else {
      const fresh = join(out,'esm'), committed = join(generated,'esm');
      if (JSON.stringify(files(fresh)) !== JSON.stringify(files(committed))) throw new Error('Generated ESM file set differs');
      for (const n of files(fresh)) if (!readFileSync(join(fresh,n)).equals(readFileSync(join(committed,n)))) throw new Error(`Generated ESM differs: ${n}`);
    }
  } finally { rmSync(temp,{recursive:true,force:true}); }
}
const recorded = JSON.parse(readFileSync(join(generated,'inputs.json'),'utf8'));
if (JSON.stringify(inputs()) !== JSON.stringify(recorded)) throw new Error('Catalog inputs changed; regenerate with the pinned compiler and --write');
const {render} = await import(pathToFileURL(join(generated,'esm/solpbc-org/api.mjs')).href);
const pages = buildPages(root,render);
for (const [name,built] of pages) {
  const dest = join(root,name);
  if (write) writeFileSync(dest,built);
  if (readFileSync(dest,'utf8') !== built) throw new Error(`${name}: committed output differs; regenerate with --write`);
}
console.log(`ok ${pages.size} generated pages and scripts`);
