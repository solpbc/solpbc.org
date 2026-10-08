// solpbc.org/contact: submits the form as JSON so the page can show its own
// success and error states. The worker also accepts a plain form POST
// (redirects to /contact/thanks or /contact?error=1), e.g. if the form is sent
// before this script loads; Turnstile needs JS, so there is no working no-JS path.
//
// Same-origin file, not an inline <script>: CONTACT_CSP allows script-src 'self'
// (no 'unsafe-inline', no hash), so the copy below can change without touching
// the CSP. Every string here is owner-visible; voice-check (owner-copy) any edit.
(function () {
    var MESSAGES = {
        generic: "that didn't send. please try again, or email jer at solpbc dot org.",
        verification: "the check that you're human didn't go through. please finish it above, then send again.",
        rateLimited: 'a lot of messages came from here just now. please wait a minute, then send again.',
        sending: 'sending…',
        send: 'send message'
    };

    // Raw worker error codes (worker.js handleContact) are never shown as-is.
    function messageFor(error) {
        if (error === 'verification failed') return MESSAGES.verification;
        if (error === 'too many requests') return MESSAGES.rateLimited;
        return MESSAGES.generic;
    }

    var form = document.getElementById('contact-form');
    var errorEl = document.getElementById('error-message');
    var successEl = document.getElementById('success-state');
    var btn = form.querySelector('.submit-btn');

    function showError(text) {
        errorEl.textContent = text;
        errorEl.hidden = false;
        btn.disabled = false;
        btn.textContent = MESSAGES.send;
        if (window.turnstile) { window.turnstile.reset(); }
    }

    // Non-JS fallback redirect lands here on failure.
    if (new URLSearchParams(window.location.search).has('error')) {
        errorEl.textContent = MESSAGES.generic;
        errorEl.hidden = false;
    }

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        errorEl.hidden = true;
        btn.disabled = true;
        btn.textContent = MESSAGES.sending;

        var turnstileInput = form.querySelector('[name="cf-turnstile-response"]');
        var data = {
            name: document.getElementById('name').value,
            email: document.getElementById('email').value,
            message: document.getElementById('message').value,
            company: document.getElementById('company').value,
            'cf-turnstile-response': turnstileInput ? turnstileInput.value : ''
        };

        fetch('/api/contact', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        })
            .then(function (res) { return res.json(); })
            .then(function (result) {
                if (result.ok) {
                    form.hidden = true;
                    successEl.hidden = false;
                } else {
                    showError(messageFor(result.error));
                }
            })
            .catch(function () {
                showError(MESSAGES.generic);
            });
    });
})();
