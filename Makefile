.PHONY: deploy dev sitemap brands

sitemap:
	./bin/gen-sitemap.sh

brands:
	./bin/gen-brand-assets.sh

deploy: brands sitemap
	wrangler deploy

dev:
	wrangler dev
