// solpbc.org — company site Worker
// Serves static assets, handles POST /contact, applies security headers.
// Replaces: GitHub Pages hosting + headers-solpbc proxy + contact.solpbc.org Worker.

const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};

const CONTACT_CSP =
  "default-src 'none'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self'; " +
  "script-src 'self' https://challenges.cloudflare.com; " +
  'frame-src https://challenges.cloudflare.com; ' +
  "connect-src 'self' https://challenges.cloudflare.com; " +
  "frame-ancestors 'none'";

// Scoped relaxed CSP for /demo/* — stage-tool walkthroughs that need same-origin
// scripts and inline styles. Not a public surface.
const DEMO_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
  "base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

// Scoped CSP for /brands/ — the brand media portal needs same-origin clipboard
// JS (the base CSP has no script-src, so page JS is otherwise blocked). Base
// CSP + script-src 'self' only: no connect-src (the Clipboard API is not a
// network fetch), no external origins. The page makes zero third-party
// requests by design — that is the brand. (build spec §5.6)
const BRANDS_CSP =
  "default-src 'none'; style-src 'self' 'unsafe-inline'; font-src 'self'; " +
  "img-src 'self'; script-src 'self'; frame-ancestors 'none'";

// Scoped CSP for /talks/* — recorded talk pages embed Cloudflare Stream.
// Allows stream embed scripts, video frames, and HLS connections. frame-src and
// frame-ancestors include 'self' so a talk page can iframe a same-origin sibling
// (e.g. the extro-viz "Buzz" standalone in the NYTW deck) and be framed by one;
// same-origin only — no cross-origin framing.
const TALKS_CSP =
  "default-src 'self'; " +
  "script-src 'self' 'unsafe-inline' https://embed.cloudflarestream.com; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: https://customer-eyrmf7nulbdv9pd7.cloudflarestream.com; " +
  "font-src 'self'; " +
  "connect-src 'self' https://customer-eyrmf7nulbdv9pd7.cloudflarestream.com; " +
  "media-src 'self' https://customer-eyrmf7nulbdv9pd7.cloudflarestream.com; " +
  "frame-src 'self' https://customer-eyrmf7nulbdv9pd7.cloudflarestream.com https://embed.cloudflarestream.com; " +
  "base-uri 'self'; form-action 'self'; frame-ancestors 'self'";

// --- helpers ---

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function redirect(url, status = 301) {
  return new Response(null, { status, headers: { Location: url } });
}

function methodNotAllowed(allow) {
  return new Response(null, { status: 405, headers: { Allow: allow } });
}

function assetRequest(url, request) {
  return new Request(url, {
    method: request.method,
    headers: request.headers,
  });
}

function clampText(value, maxLength) {
  return String(value ?? '').trim().slice(0, maxLength);
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value || '');
}

function applySecurityHeaders(response, pathname) {
  const newResponse = new Response(response.body, response);
  const isContactPage = pathname === '/contact' || pathname.startsWith('/contact/');
  const isDemoPage = pathname.startsWith('/demo/');
  const isTalksPage = pathname === '/talks' || pathname.startsWith('/talks/');
  const isBrandsPage =
    pathname === '/brands' || pathname === '/brands.html' || pathname.startsWith('/brands/');

  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    if (key === 'Content-Security-Policy' && isContactPage) {
      newResponse.headers.set(key, CONTACT_CSP);
    } else if (key === 'Content-Security-Policy' && isDemoPage) {
      newResponse.headers.set(key, DEMO_CSP);
    } else if (key === 'Content-Security-Policy' && isTalksPage) {
      newResponse.headers.set(key, TALKS_CSP);
    } else if (key === 'Content-Security-Policy' && isBrandsPage) {
      newResponse.headers.set(key, BRANDS_CSP);
    } else if (key === 'X-Frame-Options' && isTalksPage) {
      // /talks/* may iframe a same-origin sibling (the extro-viz "Buzz" standalone
      // in the NYTW deck). X-Frame-Options: DENY is absolute and would block that
      // even with TALKS_CSP frame-ancestors 'self'; SAMEORIGIN is the legacy-header
      // equivalent — same-origin framing only, no cross-origin surface opened.
      newResponse.headers.set(key, 'SAMEORIGIN');
    } else {
      newResponse.headers.set(key, value);
    }
  }

  return newResponse;
}

// --- turnstile ---

async function validateTurnstile(env, token, remoteIp) {
  if (!token) return false;
  if (!env.TURNSTILE_SECRET) return false;

  const response = await fetch(TURNSTILE_VERIFY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: env.TURNSTILE_SECRET,
      response: token,
      remoteip: remoteIp || undefined,
    }),
  });

  if (!response.ok) return false;
  const payload = await response.json();
  return payload.success === true;
}

// --- contact form handler ---

async function handleContact(request, env, ctx) {
  const contentType = request.headers.get('Content-Type') || '';
  const isJson = contentType.includes('application/json');

  function respond(data, status) {
    if (isJson) return jsonResponse(data, status);
    if (data.ok) return redirect('/contact/thanks', 303);
    return redirect('/contact?error=1', 303);
  }

  // Rate limiting
  if (env.CONTACT_LIMITER) {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    try {
      const { success } = await env.CONTACT_LIMITER.limit({ key: ip });
      if (!success) return respond({ ok: false, error: 'too many requests' }, 429);
    } catch {
      // Rate limiter unavailable — proceed without limiting.
    }
  }

  try {
    let body;
    try {
      if (isJson) {
        body = await request.json();
      } else {
        body = await request.formData();
      }
    } catch {
      return respond({ ok: false, error: 'invalid request body' }, 400);
    }

    if (isJson && (body === null || Array.isArray(body) || typeof body !== 'object')) {
      return respond({ ok: false, error: 'invalid request body' }, 400);
    }

    const field = (key) => (body instanceof FormData ? body.get(key) : body[key]);

    // Honeypot
    const honeypot = field('company');
    if (honeypot && String(honeypot).trim() !== '') {
      return respond({ ok: false, error: 'submission rejected' }, 400);
    }

    // Turnstile
    const turnstileToken = field('cf-turnstile-response');
    const ip = request.headers.get('CF-Connecting-IP') || '';
    const turnstileOk = await validateTurnstile(env, turnstileToken, ip);
    if (!turnstileOk) {
      return respond({ ok: false, error: 'verification failed' }, 400);
    }

    // Validate fields
    const name = clampText(field('name'), 200);
    const email = clampText(field('email'), 320);
    const message = clampText(field('message'), 5000);

    if (!isValidEmail(email)) {
      return respond({ ok: false, error: 'valid email is required' }, 400);
    }
    if (!message) {
      return respond({ ok: false, error: 'message is required' }, 400);
    }

    // Build flat payload matching hub webhook contract
    const submissionId = crypto.randomUUID();
    const submission = {
      type: 'contact.submitted',
      submission_id: submissionId,
      name,
      email,
      message,
      ip: request.headers.get('CF-Connecting-IP') || '',
      timestamp: new Date().toISOString(),
    };

    // Cache in KV before firing webhook — survives hub downtime
    if (env.CONTACT_SUBMISSIONS) {
      await env.CONTACT_SUBMISSIONS.put(submissionId, JSON.stringify(submission), {
        expirationTtl: 86400, // 24 hours
      });
    }

    // Fire webhook, delete from KV on success
    if (env.HUB_WEBHOOK_URL) {
      ctx.waitUntil(
        fetch(env.HUB_WEBHOOK_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Hub-Secret': env.HUB_WEBHOOK_SECRET || '',
          },
          body: JSON.stringify(submission),
        })
          .then((res) => {
            if (res.ok && env.CONTACT_SUBMISSIONS) {
              return env.CONTACT_SUBMISSIONS.delete(submissionId);
            }
          })
          .catch((err) => console.error('webhook failed:', err))
      );
    }

    return respond({ ok: true }, 200);
  } catch (err) {
    console.error('contact submission error:', err);
    return respond({ ok: false, error: 'internal error' }, 500);
  }
}

// --- sweep endpoints for hub recovery ---

// Sweep-endpoint auth uses a DISTINCT secret from the outbound-push
// HUB_WEBHOOK_SECRET (non-coupling: webhook-ingest and contact-sweep are two
// trust paths and must not share one credential). The hub presents this value
// as X-Hub-Secret on its GET/DELETE /api/contact/pending calls.
function verifySweepSecret(request, env) {
  const secret = env.CONTACT_SWEEP_SECRET;
  if (!secret) return false;
  return request.headers.get('X-Hub-Secret') === secret;
}

async function handleSweepList(request, env) {
  if (!verifySweepSecret(request, env)) {
    return jsonResponse({ error: 'unauthorized' }, 401);
  }
  if (!env.CONTACT_SUBMISSIONS) {
    return jsonResponse({ submissions: [] });
  }
  const list = await env.CONTACT_SUBMISSIONS.list();
  const submissions = [];
  for (const key of list.keys) {
    const value = await env.CONTACT_SUBMISSIONS.get(key.name);
    if (value) {
      try {
        submissions.push(JSON.parse(value));
      } catch {
        // Skip malformed entries
      }
    }
  }
  return jsonResponse({ submissions });
}

async function handleSweepAck(request, env, submissionId) {
  if (!verifySweepSecret(request, env)) {
    return jsonResponse({ error: 'unauthorized' }, 401);
  }
  if (!env.CONTACT_SUBMISSIONS) {
    return jsonResponse({ error: 'not found' }, 404);
  }
  const existing = await env.CONTACT_SUBMISSIONS.get(submissionId);
  if (!existing) {
    return jsonResponse({ error: 'not found' }, 404);
  }
  await env.CONTACT_SUBMISSIONS.delete(submissionId);
  return jsonResponse({ ok: true });
}

// --- main ---

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // www → apex redirect
    if (url.hostname === 'www.solpbc.org') {
      url.hostname = 'solpbc.org';
      return redirect(url.toString(), 301);
    }

    // Demo-day talk short aliases → canonical /talks/2026-05-05-demo-day
    if (
      url.pathname === '/demo' ||
      url.pathname === '/demo/' ||
      url.pathname === '/demo-day' ||
      url.pathname === '/demo-day/' ||
      url.pathname === '/demo/2026-05-05' ||
      url.pathname === '/demo/2026-05-05/'
    ) {
      return redirect('/talks/2026-05-05-demo-day', 302);
    }

    // /brands and /brands.html → canonical /brands/ (the clean-URL handler
    // only tries .html and would not dir-index /brands). 301 — build spec §5.6.
    if (url.pathname === '/brands' || url.pathname === '/brands.html') {
      return redirect('/brands/', 301);
    }

    // POST /api/contact → form handler
    if (url.pathname === '/api/contact') {
      if (request.method !== 'POST') {
        return applySecurityHeaders(methodNotAllowed('POST'), url.pathname);
      }
      const response = await handleContact(request, env, ctx);
      return applySecurityHeaders(response, url.pathname);
    }

    // GET /api/contact/pending → list cached submissions for hub sweep
    if (url.pathname === '/api/contact/pending') {
      if (request.method !== 'GET') {
        return applySecurityHeaders(methodNotAllowed('GET'), url.pathname);
      }
      return handleSweepList(request, env);
    }

    // DELETE /api/contact/pending/:id → acknowledge a submission
    if (url.pathname.startsWith('/api/contact/pending/')) {
      if (request.method !== 'DELETE') {
        return applySecurityHeaders(methodNotAllowed('DELETE'), url.pathname);
      }
      const id = url.pathname.slice('/api/contact/pending/'.length);
      return handleSweepAck(request, env, id);
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return applySecurityHeaders(methodNotAllowed('GET, HEAD'), url.pathname);
    }

    // Serve static assets
    let response = await env.ASSETS.fetch(request);

    // Clean URLs: try .html extension for paths without dots
    if (response.status === 404 && !url.pathname.endsWith('/') && !url.pathname.includes('.')) {
      const htmlUrl = new URL(request.url);
      htmlUrl.pathname = url.pathname + '.html';
      const htmlResponse = await env.ASSETS.fetch(assetRequest(htmlUrl, request));
      if (htmlResponse.status !== 404) {
        response = htmlResponse;
      }
    }

    // Custom 404 — serve the branded HTML page with strict security headers.
    if (response.status === 404) {
      const notFoundUrl = new URL(request.url);
      notFoundUrl.pathname = '/404';
      const notFoundResponse = await env.ASSETS.fetch(assetRequest(notFoundUrl, request));
      const headers = new Headers(notFoundResponse.headers);
      headers.set('Content-Type', 'text/html; charset=utf-8');
      return applySecurityHeaders(
        new Response(notFoundResponse.body, { status: 404, headers }),
        url.pathname
      );
    }

    return applySecurityHeaders(response, url.pathname);
  },
};
