import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export function escapeHTML(text) {
  return text.replace(/[&<>"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[ch]));
}

export function cssString(text) {
  return '"' + text.replace(/["\\\x00-\x1f\x7f<]/g, ch => `\\${ch.codePointAt(0).toString(16)} `) + '"';
}

// Catalog text can move a numbered pair, but can supply no tag or attribute.
// Only template-owned a/span/strong elements enter the output as HTML.
export function inlineHTML(text, slots = [], markup = true) {
  for (const slot of slots) {
    const tag = /^<(a|span|strong)(?:\s[^<>]*)?>$/.exec(slot.open);
    if (!tag || slot.close !== `</${tag[1]}>`) throw new Error('Invalid inline template element');
  }
  const stack = [], used = new Set();
  let last = 0, out = '';
  for (const m of text.matchAll(/\[(\/?)(\d+)\]/g)) {
    out += escapeHTML(text.substring(last, m.index));
    const n = Number(m[2]), slot = slots[n - 1];
    if (!slot) throw new Error(`Unknown inline marker ${m[0]}`);
    if (m[1]) {
      if (stack.pop() !== n) throw new Error(`Unbalanced inline marker ${m[0]}`);
      if (markup) out += slot.close;
    } else {
      if (used.has(n)) throw new Error(`Repeated inline marker ${m[0]}`);
      used.add(n); stack.push(n); if (markup) out += slot.open;
    }
    last = m.index + m[0].length;
  }
  if (stack.length || used.size !== slots.length) throw new Error('Missing inline marker');
  return out + escapeHTML(text.substring(last));
}

export function buildPages(root, render, locale = 'en-US') {
  const base = join(root, 'i18n/templates');
  const inline = JSON.parse(readFileSync(join(base, 'inline.json'), 'utf8'));
  const pages = new Map();
  function walk(rel = '') {
    for (const ent of readdirSync(join(base, rel), { withFileTypes: true })) {
      const name = join(rel, ent.name);
      if (ent.isDirectory()) { walk(name); continue; }
      if (!/\.(html|js)$/.test(name)) continue;
      let source = readFileSync(join(base, name), 'utf8');
      source = source.replace(/%%([^%]+)%%/g, (_, token) => {
        const match = /^(html|rich|attr|js|css):(solpbc\.[a-zA-Z0-9.]+)(?: (\{.*\}))?$/.exec(token);
        if (!match) throw new Error(`${name}: invalid token ${token}`);
        const [, mode, id, rawArgs] = match;
        const args = Object.entries(rawArgs ? JSON.parse(rawArgs) : {});
        const value = render(locale, id, args, { useIsolating: false });
        if (mode === 'js') return JSON.stringify(value).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
        if (mode === 'css') return cssString(value);
        if (mode === 'attr') {
          if (inline[id]) throw new Error(`${id}: inline message used as an attribute`);
          return escapeHTML(value);
        }
        return inlineHTML(value, inline[id], mode === 'rich');
      });
      if (source.includes('%%')) throw new Error(`${name}: unresolved token`);
      if (locale !== 'en-US' && name.endsWith('.html')) {
        source = source.replace(/<html lang="en"/, `<html lang="${escapeHTML(locale)}"`);
      }
      pages.set(name, source);
    }
  }
  walk();
  return pages;
}
