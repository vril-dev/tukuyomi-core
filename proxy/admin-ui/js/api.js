// The calls to the admin API. The CSRF token of the session is kept here, in memory only, and goes with every call
// but GET and HEAD. A call gives the parsed JSON, or throws an `ApiError` whose `kind` says how to go on:
//   session      the session is gone (401): the page goes back to the sign-in (see `onSessionLost`)
//   forbidden    refused (403): the role does not allow it, or a state of the session does
//   conflict     the state moved under the call (409): read the lists again and say why
//   limited      too many tries (429): wait
//   unavailable  the admin state cannot be read or written (503): the change was refused
//   unknown      no answer, or the proxy of the way in gave up (502, 504): the result of a change is not known, so
//                read the status and the history again
//   refused      another 4xx: the request was not valid
//   failed       any other answer that is not a success
// A call has no time limit of its own: an import, a switch and a rollback may take as long as the server lets them.
// Nothing runs when the module is loaded.

const SAFE = new Set(['GET', 'HEAD']);

export function kindOf(status) {
  if (status === 401) return 'session';
  if (status === 403) return 'forbidden';
  if (status === 409) return 'conflict';
  if (status === 429) return 'limited';
  if (status === 503) return 'unavailable';
  if (status === 502 || status === 504) return 'unknown';
  if (status >= 400 && status < 500) return 'refused';
  return 'failed';
}

export class ApiError extends Error {
  constructor(kind, status, sentence, body = null) {
    super(sentence || kind);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = status;
    this.sentence = sentence;
    this.body = body;
  }
}

/** The `error` sentence of an answer's body; empty when there is none. */
export function sentenceOf(body) {
  return body !== null && typeof body === 'object' && typeof body.error === 'string' ? body.error : '';
}

/**
 * Where a user stands, from the answer of a sign-in (`mfa`: off, verify or setup; `must_change`) or of the session
 * (`state`: active, must_change or mfa_setup):
 *   login     no session, or an answer that is not understood (nothing is opened on a doubt)
 *   mfa       the code of the second factor is asked for
 *   password  the password must be changed first; nothing else is shown
 *   setup     the second factor must be set up first; nothing else is shown
 *   open      the screens may be used
 */
export function gateOf(answer) {
  if (answer === null || typeof answer !== 'object') return 'login';
  if (answer.mfa === 'verify') return 'mfa';
  if (answer.must_change === true || answer.state === 'must_change') return 'password';
  if (answer.mfa === 'setup' || answer.state === 'mfa_setup') return 'setup';
  if (answer.state === 'active' || answer.mfa === 'off') return 'open';
  return 'login';
}

export class Api {
  #fetch;

  constructor(fetchFunction) {
    this.#fetch = fetchFunction ?? ((...args) => globalThis.fetch(...args));
    /** The CSRF token of the session; null when there is none. */
    this.csrf = null;
    /** Called when a call finds the session gone, before the call throws. */
    this.onSessionLost = () => {};
  }

  /** One request: the status and the parsed JSON body (null when the answer has none). Throws `unknown` on no answer. */
  async send(method, path, body) {
    const headers = { Accept: 'application/json' };
    // No `mode` and no `referrerPolicy`: the Fetch standard has a browser send `Origin: null` with a change (neither
    // GET nor HEAD) when the mode is not `cors` and the referrer policy is `no-referrer`, and the server refuses that
    // origin. The policy of the page (`same-origin`) applies, and the CSP (`connect-src 'self'`) keeps the call here.
    const init = {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
    };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    if (!SAFE.has(method) && this.csrf !== null) headers['X-CSRF-Token'] = this.csrf;
    let response;
    try {
      response = await this.#fetch(path, init);
    } catch {
      throw new ApiError('unknown', 0, '');
    }
    const type = response.headers.get('content-type') ?? '';
    let parsed = null;
    if (type.startsWith('application/json')) {
      try {
        parsed = await response.json();
      } catch {
        parsed = null;
      }
    }
    return { status: response.status, body: parsed };
  }

  /**
   * The JSON answer of a call. With `auth` (the default) a 401 means the session is gone; the sign-in calls pass
   * `auth: false`, where a 401 is a wrong password or code. A change that a 403 refused is tried once more when the
   * session has a new CSRF token (it was renewed elsewhere, for example by a password change in another window).
   */
  async call(method, path, body, { auth = true } = {}) {
    let reply = await this.send(method, path, body);
    if (auth && reply.status === 403 && !SAFE.has(method) && (await this.renew())) {
      reply = await this.send(method, path, body);
    }
    return this.settle(reply, auth);
  }

  /** Reads the session again; true when it has a new CSRF token, which is kept. Throws `session` when it is gone. */
  async renew() {
    let probe;
    try {
      probe = await this.send('GET', '/api/session');
    } catch {
      return false;
    }
    if (probe.status === 401) this.lose();
    const token = probe.body?.csrf;
    if (probe.status === 200 && typeof token === 'string' && token !== this.csrf) {
      this.csrf = token;
      return true;
    }
    return false;
  }

  settle({ status, body }, auth) {
    if (status >= 200 && status < 300) {
      if (body !== null && typeof body === 'object' && 'csrf' in body) {
        this.csrf = typeof body.csrf === 'string' ? body.csrf : null;
      }
      return body ?? {};
    }
    if (status === 401 && auth) this.lose();
    throw new ApiError(kindOf(status), status, sentenceOf(body), body);
  }

  lose() {
    this.csrf = null;
    this.onSessionLost();
    throw new ApiError('session', 401, 'unauthorized');
  }

  /**
   * Ends the session. It gives only when the server said so, and then the CSRF token is dropped. Any other end throws
   * and keeps the session as it was: a 401 means that the session was gone already (see `onSessionLost`), and a call
   * that failed or got no answer leaves it unknown whether the session is still there.
   */
  async logout() {
    await this.call('POST', '/api/logout');
    this.csrf = null;
  }
}
