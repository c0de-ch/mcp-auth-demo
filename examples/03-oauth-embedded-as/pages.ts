/**
 * 03 — pages.ts: the authorization server's OWN login and consent pages.
 *
 * These are the two screens a browser sees between GET /authorize and the redirect back to the
 * client. They are deliberately shaped like Keycloak's pages — form ids #username / #password,
 * submit #kc-login, consent buttons input[name=accept] / input[name=cancel] — so the headless
 * driver (scripts/browser-login.py) works unchanged against Keycloak AND this embedded AS.
 *
 * Rules the pages follow:
 *   - all state lives server-side in the provider's pending transaction (?txn=…); the forms only
 *     carry the transaction id and its per-transaction `csrf` secret
 *   - EVERYTHING that came from a client registration (client_name, redirect_uri) is HTML-escaped
 *     before rendering — DCR is open, so client metadata is attacker-controlled input
 *   - the consent page shows who is asking (client), as whom (user), what for (scopes) and where
 *     the browser will be sent afterwards (redirect host) — the human is the phishing defence
 *   - error/expiry pages never reflect request parameters
 */
import '../../src/shared/env.ts';
import { Router, urlencoded } from 'express';
import type { Request, Response } from 'express';
import type { ConsentView, DemoAuthorizationServer } from './provider.ts';

const CSS = `
  body { font-family: system-ui, sans-serif; background: #f3f4f6; margin: 0; color: #111; }
  main { max-width: 26rem; margin: 8vh auto; background: #fff; border-radius: 8px; padding: 2rem; box-shadow: 0 1px 8px rgba(0,0,0,.12); }
  h1 { font-size: 1.25rem; margin-top: 0; }
  label { display: block; margin: .75rem 0 .25rem; font-size: .9rem; }
  input[type=text], input[type=password] { width: 100%; box-sizing: border-box; padding: .5rem; border: 1px solid #cbd5e1; border-radius: 4px; }
  input[type=submit] { margin-top: 1rem; padding: .5rem 1.25rem; border: 0; border-radius: 4px; background: #1d4ed8; color: #fff; cursor: pointer; }
  input[type=submit].secondary { background: #6b7280; margin-left: .5rem; }
  .alert-error { background: #fef2f2; border: 1px solid #dc2626; color: #991b1b; padding: .5rem .75rem; border-radius: 4px; margin-bottom: .75rem; }
  .hint, .meta { color: #555; font-size: .85rem; }
  ul.scopes { padding-left: 1.25rem; }
  ul.scopes li { margin: .3rem 0; }
  ul.scopes .denied { color: #9ca3af; }
  code { background: #eef2ff; padding: 0 .25rem; border-radius: 3px; word-break: break-all; }
`.replace(/\n\s*/g, ' ');

const escapeHtml = (value: string): string =>
  value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

const page = (title: string, body: string): string =>
  `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title} — 03-oauth-embedded-as</title><style>${CSS}</style></head><body><main>${body}</main></body></html>`;

const hidden = (txn: string, csrf: string): string =>
  `<input type="hidden" name="txn" value="${escapeHtml(txn)}"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}">`;

/** 400 for a missing/expired/spent transaction — nothing from the request is reflected. */
const expiredPage = (res: Response): void => {
  res.status(400).send(page('Request expired', '<h1>Sign-in request expired</h1><p class="hint">This sign-in link is no longer valid (it may have expired or already been used). Return to your client and start again.</p>'));
};

const loginPage = (txn: string, csrf: string, error?: string): string =>
  page(
    'Sign in',
    `<h1>Sign in</h1>
     <p class="hint">Demo accounts (DEMO): <strong>alice</strong> / password (tools), <strong>bob</strong> / password (tools + admin).</p>
     ${error ? `<div class="alert-error" id="input-error">${escapeHtml(error)}</div>` : ''}
     <form method="post" action="/login">
       ${hidden(txn, csrf)}
       <label for="username">Username</label>
       <input type="text" id="username" name="username" autocomplete="username" autofocus>
       <label for="password">Password</label>
       <input type="password" id="password" name="password" autocomplete="current-password">
       <input type="submit" id="kc-login" name="login" value="Sign in">
     </form>`,
  );

const consentPage = (txn: string, view: ConsentView): string => {
  const scopes = view.scopes
    .map((s) =>
      s.granted
        ? `<li><code>${escapeHtml(s.scope)}</code> — ${escapeHtml(s.description)}</li>`
        : `<li class="denied"><code>${escapeHtml(s.scope)}</code> — not available for this account (will not be granted)</li>`,
    )
    .join('');
  return page(
    'Grant access',
    `<h1>Grant access?</h1>
     <p><strong>${escapeHtml(view.clientName.slice(0, 80))}</strong> <span class="meta">(client_id <code>${escapeHtml(view.clientId)}</code>)</span> asks to act as <strong>${escapeHtml(view.sub)}</strong> with:</p>
     <ul class="scopes">${scopes}</ul>
     ${view.resource ? `<p class="meta">For the resource <code>${escapeHtml(view.resource)}</code>.</p>` : ''}
     <p class="meta">After your decision the browser is sent to <code>${escapeHtml(view.redirectUri)}</code> — if you do not recognise that address, deny.</p>
     <form method="post" action="/consent">
       ${hidden(txn, view.csrf)}
       <input type="submit" id="kc-login" name="accept" value="Allow">
       <input type="submit" id="kc-cancel" name="cancel" value="Deny" class="secondary">
     </form>`,
  );
};

const str = (value: unknown): string => (typeof value === 'string' ? value : '');

/** GET/POST /login and /consent, driven entirely by the provider's pending-transaction store. */
export function authPagesRouter(provider: DemoAuthorizationServer): Router {
  const router = Router();
  const forms = urlencoded({ extended: false });

  router.get('/login', (req: Request, res: Response) => {
    const txn = str(req.query.txn);
    const pending = txn ? provider.pending(txn) : undefined;
    if (!pending) return expiredPage(res);
    res.status(200).send(loginPage(txn, pending.csrf));
  });

  router.post('/login', forms, (req: Request, res: Response) => {
    const { txn, csrf, username, password } = { txn: str(req.body.txn), csrf: str(req.body.csrf), username: str(req.body.username), password: str(req.body.password) };
    const outcome = provider.authenticate(txn, csrf, username, password);
    if (outcome === 'expired') return expiredPage(res);
    if (outcome === 'csrf') return void res.status(400).send(page('Invalid request', '<h1>Invalid request</h1><p class="hint">The form was missing its anti-forgery token. Start again from your client.</p>'));
    if (outcome === 'credentials') return void res.status(401).send(loginPage(txn, csrf, 'Invalid username or password.'));
    res.redirect(303, `/consent?txn=${txn}`);
  });

  router.get('/consent', (req: Request, res: Response) => {
    const txn = str(req.query.txn);
    const view = txn ? provider.consentView(txn) : 'expired';
    if (view === 'expired') return expiredPage(res);
    if (view === 'unauthenticated') return res.redirect(303, `/login?txn=${txn}`); // not signed in yet
    res.status(200).send(consentPage(txn, view));
  });

  router.post('/consent', forms, (req: Request, res: Response) => {
    const txn = str(req.body.txn);
    const accept = req.body.accept !== undefined && req.body.cancel === undefined;
    const outcome = provider.decide(txn, str(req.body.csrf), accept);
    if (outcome === 'expired') return expiredPage(res);
    if (outcome === 'csrf' || outcome === 'unauthenticated') {
      return void res.status(400).send(page('Invalid request', '<h1>Invalid request</h1><p class="hint">This consent form is not valid for the current sign-in. Start again from your client.</p>'));
    }
    res.redirect(302, outcome.redirectTo); // back to the client: ?code=…&state=… or ?error=…
  });

  return router;
}
