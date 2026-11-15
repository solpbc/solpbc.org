# Contributor instructions

solpbc.org is a static site. A Cloudflare Worker serves `public/` and handles the contact form in `worker.js`.

## Page text

English for the visitor pages lives in `i18n/catalog/`. The page structure lives in `i18n/templates/`. These committed files are generated from that pair:

- `public/index.html`
- `public/404.html`
- `public/contact/index.html`, `public/contact/thanks/index.html`, `public/contact/contact.js`
- `public/brands/index.html`, `public/brands/brand.js`
- `worker.js` (the contact-handler sentences; the rest of the handler is in the template too)

Edit the template and the catalog. Do not hand-edit the generated files. The inline drawings on the brands page are part of `i18n/templates/public/brands/index.html`. `i18n/README.md` says how to change a string and regenerate.

`make check` rebuilds those files from the committed catalog and fails if they disagree. `make deploy` does not rebuild them. It still refreshes the sitemap, refreshes downloadable brand files when their source has changed, and deploys.

## Left out on purpose

`public/blog/` is written by the blog publisher. Leave it out of the catalog and the templates.

`articles.html`, `bylaws.html`, and `privacy.html` (and a `privacy/` directory, if one is added) are hand-maintained legal pages. Leave them out.

`public/talks/`, PDFs, the sitemap, and `robots.txt` stay as they are.

The hidden contact-form field labeled `company` stays a literal in the contact template. It is not a catalog message.

## One shipped wording change

`public/brands/brand.js` tells a screen reader `copy failed. select and copy.` when a copy does not land. That sentence is the catalog message `solpbc.site.brands.copyfailed`.
