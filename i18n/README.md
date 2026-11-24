# solpbc.org string catalog

The site ships English only. `catalog/source/en-US.ftl` supplies visitor text. Each message has translator context in `catalog/meta/`. `compiler.json` pins the solstone-journal catalog compiler and its registry digest. Nothing under `i18n/` is served to visitors.

## editing and regenerating

1. Edit the English message and its sidecar. Keep its id for a prose edit. A changed argument contract or protected-slot contract requires a new id; retire the old id with `retire --id OLD --replacement NEW`. Register new identities with `history`.
2. Run the pinned compiler's `lock i18n/catalog`. Copy each changed message's `source` hash from `source-lock.json` into its sidecar's `source_revision`. The compiler supplies this hash; do not calculate it from FTL text.
3. From the repository root, regenerate the committed ESM and pages together:

```sh
I18N_CATALOG=/path/to/pinned/i18n-catalog node bin/check-pages.mjs --write
make check
```

Build that binary from the revision in `compiler.json`, using `tools/i18n/README.md` in the compiler repository. `--write` requires the compiler. It validates the catalog, replaces `generated/esm/`, records hashes of all catalog inputs, then renders the pages. Commit the catalog, generated resources and rendered files together.

Without the compiler, `make check` verifies those input hashes and compares every generated page and script to the committed output. With `I18N_CATALOG` set it also recompiles and compares the complete ESM file set. Missing messages, missing arguments, stale inputs and changed committed pages fail. `make deploy` keeps using the committed files; it does not invoke this build or require Rust.

## templates and inline elements

A template token names its output context:

- `%%html:MESSAGE%%`: escaped text, with any inline markers removed after validation.
- `%%rich:MESSAGE%%`: escaped text with numbered markers expanded to template-owned inline elements.
- `%%attr:MESSAGE%%`: escaped text inside a double-quoted attribute.
- `%%css:MESSAGE%%`: a complete CSS string, with quotes, controls and style terminators escaped.
- `%%js:MESSAGE%%`: a complete JSON-serialized JavaScript string literal. Do not put quotes around the token.

Append a JSON argument object after the id, for example `%%html:solpbc.site.contact.send {"state":"idle"}%%`. Argument values are passed to the generated typed API.

A linked sentence stays one message, such as `words [1]link text[/1] more words`. `templates/inline.json` maps its numbered pairs to exact opening and closing tags. Only `a`, `span` and `strong` elements are admitted. Tags, URLs and attributes live there; the catalog supplies their translated text. Each pair must occur once, with balanced nesting. Translators may move pairs and words together. The plain `html` form renders the same whole message without decoration where another page needs it.

Text is escaped before template elements are inserted. Attribute tokens escape ampersands, angle brackets and double quotes. Script tokens use JSON serialization and escape less-than signs and JavaScript line separators. Rendering uses `useIsolating: false` for the shipped English. No browser language selects an unshipped locale.

## scope

Home, contact, thanks, 404, brands and the contact-handler sentences are generated. Blog, legal pages, talks, PDFs, governance documents, the sitemap and downloadable brand assets stay outside the build. The hidden contact-field label `company` remains a literal.

## Draft locales

`es-419` is registered in the pinned locale registry as a draft locale (`development` released, `production` withheld). Draft translations live in `catalog/translations/es-419.ftl` (or sharded files under `catalog/translations/es-419/`), and production builds exclude them. Unapproved legal and statutory messages stay absent from draft translation files and fall back to English in development builds. When editing English prose, run `i18n-catalog lock` to refresh `source-lock.json`, copy each changed `source` hash into its sidecar `source_revision`, and do not pass `--acknowledge es-419`: leaving the prior acknowledgment untouched marks edited draft entries stale until a translator updates them.
