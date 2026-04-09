# solpbc.org

Company site for [sol pbc](https://solpbc.org), served via Cloudflare Workers.

## Deploy

```bash
make deploy
```

## Develop

```bash
make dev
```

## Structure

```
public/          static assets served by CF Workers
├── index.html   landing page
├── contact/     contact form (Turnstile-protected)
├── blog/        blog posts and feed
├── static/      logo and favicon assets
├── articles.html, bylaws.html, privacy.html
└── _headers     security headers for asset responses
worker.js        static assets + contact form handler + security headers
wrangler.toml    CF Workers deployment config
```
