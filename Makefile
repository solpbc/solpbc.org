.PHONY: install deploy dev dev-pages sitemap brands check

LOCALE ?= es-419
OUT ?= .dev-pages

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
	node --test bin/render-pages.test.mjs

dev-pages:
	node bin/check-pages.mjs --dev --locale $(LOCALE) --out $(OUT)
