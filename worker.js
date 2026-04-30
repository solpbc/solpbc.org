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

  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    if (key === 'Content-Security-Policy' && isContactPage) {
      newResponse.headers.set(key, CONTACT_CSP);
    } else if (key === 'Content-Security-Policy' && isDemoPage) {
      newResponse.headers.set(key, DEMO_CSP);
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
    if (isJson) {
      body = await request.json();
    } else {
      body = await request.formData();
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

function verifyHubSecret(request, env) {
  const secret = env.HUB_WEBHOOK_SECRET;
  if (!secret) return false;
  return request.headers.get('X-Hub-Secret') === secret;
}

async function handleSweepList(request, env) {
  if (!verifyHubSecret(request, env)) {
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
  if (!verifyHubSecret(request, env)) {
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

    // POST /api/contact → form handler
    if (url.pathname === '/api/contact' && request.method === 'POST') {
      const response = await handleContact(request, env, ctx);
      return applySecurityHeaders(response, url.pathname);
    }

    // GET /api/contact/pending → list cached submissions for hub sweep
    if (url.pathname === '/api/contact/pending' && request.method === 'GET') {
      return handleSweepList(request, env);
    }

    // DELETE /api/contact/pending/:id → acknowledge a submission
    if (url.pathname.startsWith('/api/contact/pending/') && request.method === 'DELETE') {
      const id = url.pathname.slice('/api/contact/pending/'.length);
      return handleSweepAck(request, env, id);
    }

    // Serve static assets
    let response = await env.ASSETS.fetch(request);

    // Clean URLs: try .html extension for paths without dots
    if (response.status === 404 && !url.pathname.endsWith('/') && !url.pathname.includes('.')) {
      const htmlUrl = new URL(request.url);
      htmlUrl.pathname = url.pathname + '.html';
      const htmlResponse = await env.ASSETS.fetch(new Request(htmlUrl, request));
      if (htmlResponse.status !== 404) {
        response = htmlResponse;
      }
    }

    // Custom 404
    if (response.status === 404) {
      return applySecurityHeaders(
        new Response('not found', { status: 404, headers: { 'Content-Type': 'text/plain' } }),
        url.pathname
      );
    }

    return applySecurityHeaders(response, url.pathname);
  },
};
