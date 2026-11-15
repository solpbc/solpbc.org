.PHONY: install deploy dev sitemap brands check

install:
	@command -v wrangler >/dev/null || { echo "wrangler required (npm i -g wrangler)"; exit 1; }
	@echo "ok — static worker, no build deps"

sitemap:
	./bin/gen-sitemap.sh

brands:
	./bin/gen-brand-assets.sh

deploy: brands sitemap
	wrangler deploy

dev:
	wrangler dev

check:
	node bin/check-pages.mjs
