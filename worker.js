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

  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    if (key === 'Content-Security-Policy' && isContactPage) {
      newResponse.headers.set(key, CONTACT_CSP);
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

function fireWebhook(env, ctx, eventType, data) {
  if (!env.HUB_WEBHOOK_URL) return;
  const body = JSON.stringify({
    event: eventType,
    data,
    timestamp: new Date().toISOString(),
  });
  ctx.waitUntil(
    fetch(env.HUB_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Hub-Secret': env.HUB_WEBHOOK_SECRET || '',
      },
      body,
    }).catch((err) => console.error('webhook failed:', err))
  );
}

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

    // Fire webhook
    fireWebhook(env, ctx, 'contact.submitted', {
      name,
      email,
      message,
      ip: request.headers.get('CF-Connecting-IP') || '',
      timestamp: new Date().toISOString(),
    });

    return respond({ ok: true }, 200);
  } catch (err) {
    console.error('contact submission error:', err);
    return respond({ ok: false, error: 'internal error' }, 500);
  }
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
