import test from 'node:test';
import assert from 'node:assert/strict';
import { buildPages, inlineHTML, escapeHTML, cssString } from './render-pages.mjs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { render } from '../i18n/generated/esm/solpbc-org/api.mjs';

test('a translation can move links and all surrounding words', () => {
  const slots = [{open:'<a href="/one">',close:'</a>'},{open:'<strong>',close:'</strong>'}];
  assert.equal(inlineHTML('[2]last[/2], then [1]first[/1] & more',slots), '<strong>last</strong>, then <a href="/one">first</a> &amp; more');
});
test('catalog characters never become markup or attributes', () => {
  assert.equal(inlineHTML('<script>alert("x")</script>'), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
  assert.equal(escapeHTML('" onload="x <&'), '&quot; onload=&quot;x &lt;&amp;');
  assert.equal(inlineHTML('[1]<img src=x onerror=x>[/1]',[{open:'<a href="/">',close:'</a>'}]),'<a href="/">&lt;img src=x onerror=x&gt;</a>');
});
test('CSS strings escape quotes, controls and style terminators', () => {
  assert.equal(cssString('"\\\n</style>'), '"\\22 \\5c \\a \\3c /style>"');
});
test('missing, repeated, unknown and crossed inline markers refuse', () => {
  const slots=[{open:'<a href="/">',close:'</a>'},{open:'<strong>',close:'</strong>'}];
  for(const text of ['[1]x[/1]','[1]x[/1][1]y[/1][2]z[/2]','[3]x[/3]','[1][2]x[/1][/2]']) assert.throws(()=>inlineHTML(text,slots));
  assert.throws(()=>inlineHTML('[1]x[/1]',[{open:'<script>',close:'</script>'}]));
});
test('missing message and missing typed argument refuse the build', () => {
  const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
  assert.throws(()=>buildPages(root,(_locale,id)=>render('en-US',id,[],{useIsolating:false})),/Missing argument/);
  assert.throws(()=>render('en-US','solpbc.site.noSuchMessage',[]),/Unknown message/);
});
test('script strings serialize quotes, newlines and closing script tags', () => {
  const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
  const injected='\'"\\\n</script>\u2028';
  const pages=buildPages(root,(locale,id,args,options)=>id==='solpbc.site.brands.copyfailed'?injected:render(locale,id,args,options));
  assert.ok(pages.get('public/brands/brand.js').includes(JSON.stringify(injected).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028')));
});
