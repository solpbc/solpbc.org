.PHONY: deploy dev sitemap

sitemap:
	./bin/gen-sitemap.sh

deploy: sitemap
	wrangler deploy

dev:
	wrangler dev
