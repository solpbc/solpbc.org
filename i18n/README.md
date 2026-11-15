# solpbc.org string catalog

Visitor-page English is the catalog in this directory. The site ships `en-US` only. There is no `translations/` directory.

`catalog/` is the source: `source/en-US.ftl`, one sidecar per message in `meta/`, plus `history.json` and `source-lock.json`. `compiler.json` names the catalog compiler revision in the solstone-journal repository.

`templates/` holds the pages and scripts the catalog fills. `spans.json` records each replacement: the message id, the slice of the rendered sentence, the page bytes to write, and any arguments. `generated/esm/` is the compiler output, committed so a page check does not need a Rust toolchain. The Worker does not load it, and nothing under `i18n/` is served.

## Check

From the repository root:

```sh
node bin/check-pages.mjs
```

`make check` runs that command. The check rebuilds each in-scope page from the templates, the span bytes, and `generated/esm/`, then diffs the result against the committed file. A missing message, a missing argument, or a render that does not match the recorded page text fails the check. `make deploy` does not run it.

A catalog line that is a single line and contains no `{` must match `render()` of the committed ESM. Editing `catalog/source/en-US.ftl` without regenerating `generated/esm/` fails that comparison.

Set `I18N_CATALOG` to an `i18n-catalog` binary built from the pinned revision and the check also regenerates the ESM and diffs it against `generated/esm/`.

## Change a string

1. Edit the message in `catalog/source/en-US.ftl` and its sidecar in `catalog/meta/`. Keep the id. A new sentence gets a new id.
2. Regenerate the ESM with the compiler at the revision in `compiler.json`, and replace `generated/esm/`:

```sh
i18n-catalog targets i18n/catalog \
  --channel production --locale en-US --target esm \
  --out /tmp/solpbc-targets
```

The output directory must be absent, or a directory this command wrote before. Copy `/tmp/solpbc-targets/esm/` over `i18n/generated/esm/`.

3. Update the matching `spans.json` entry so `raw` and `decoded` are the new page text. `raw` is what the page file contains. Where the page keeps an HTML entity, `raw` keeps the entity and `decoded` is the character `render()` returns.
4. If the markup around the string changed, edit the template and keep its token. A token is `%%id%%` when the whole message is one span, or `%%id|start:end%%` when one message is split across tags.
5. Rewrite the committed pages, then check:

```sh
node bin/check-pages.mjs --write
node bin/check-pages.mjs
```

`--write` still fails when a render does not match its span. It does not fill a missing message with a blank.

Calls that rebuild pages pass `{ useIsolating: false }`, so this English stays free of extra direction marks. The generated API defaults to isolation on. Adding a language means a registry change, a reviewed catalog, and an explicit decision to turn isolation on for that language. The visitor's browser language does not select an unshipped language.

## Arguments

Five messages take `state`: `solpbc.site.brands.copy`, `solpbc.site.brands.copyconstant`, `solpbc.site.brands.copysvg`, `solpbc.site.brands.copyvitmark`, and `solpbc.site.contact.send`. The idle spans pass `idle`. `solpbc.site.brands.copyhex` takes `hex`, the color as written on the page. Omitting either argument throws.

## Left out

`public/blog/` is written by the blog publisher. `articles.html`, `bylaws.html`, and `privacy.html` are hand-maintained. Talks, PDFs, the sitemap, and `robots.txt` are not catalog messages.

The contact form's hidden field labeled `company` stays a literal in the template.
