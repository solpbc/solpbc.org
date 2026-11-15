# contributor instructions

solpbc.org is a static site served by a Cloudflare Worker.

## visitor text

English lives in `i18n/catalog/source/en-US.ftl`, with translator context in `i18n/catalog/meta/`. Change text there, never in generated HTML or JavaScript. Keep the message id when its meaning and argument contract stay the same. Follow `i18n/README.md` for history changes and regeneration.

`i18n/templates/` owns page structure, inline elements, links and attributes. A linked sentence is one message: numbered markers let its words move around the link. Add or move markup in the templates, including `inline.json`. Do not split a sentence into word fragments.

Generated files are committed: `public/index.html`, `public/404.html`, `public/contact/index.html`, `public/contact/thanks/index.html`, `public/contact/contact.js`, `public/brands/index.html`, `public/brands/brand.js`, and `worker.js`. Edit their templates. The brands page's inline SVG is in its template.

Run `make check` before committing. It checks catalog freshness, regenerates the page strings in memory, compares committed output, and tests escaping and inline markers. `make deploy` does not rebuild pages and needs no catalog compiler. It refreshes brand downloads and the sitemap, then deploys.

## excluded files

The blog publisher owns `public/blog/`. Legal pages (`articles.html`, `bylaws.html`, `privacy.html`, and `privacy/`) stay hand-maintained. Leave them outside this build, along with talks, PDFs, governance documents, the sitemap and downloadable brand assets.

The hidden contact field labeled `company` is a deliberate literal. Do not submit the production contact form to test a change; drive responses locally.
