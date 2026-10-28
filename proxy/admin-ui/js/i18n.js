// The words of the page, in Japanese and in English. A key is a short name (`status.title`). The sentences that the
// API gives for a refusal are keys too, so that the page can show them in the chosen language; a sentence that is not
// here is shown as the API gave it. Nothing runs when the module is loaded.

export const LANGUAGES = ['ja', 'en'];

const ja = {
  'app.name': 'tukuyomi-core',
  'app.loading': '読み込み中…',
  'app.failed': '管理画面を開始できませんでした。',
  'app.retry': '再試行',
  'app.skip': '本文へ移動',

  'login.title': 'ログイン',
  'login.name': 'ユーザー名',
  'login.password': 'パスワード',
  'login.submit': 'ログイン',
  'login.ended': 'ログインの有効期間が切れました。もう一度ログインしてください。',
  'login.step_lost': 'コードの入力の途中で画面が読み込み直されました。もう一度ログインしてください。',
  'login.step_expired': 'コードの入力に使える時間（5 分）を過ぎました。もう一度ログインしてください。',
  'login.changed': 'パスワードを変更しました。その後のログインの状態を読み込めなかったので、新しいパスワードでもう一度ログインしてください。',

  'mfa.title': '確認コードの入力',
  'mfa.intro': '認証アプリに表示されている 6 桁のコードを入力してください。',
  'mfa.intro_recovery': '設定のときに保存した回復コードを 1 つ入力してください。使った回復コードは、もう使えません。',
  'mfa.code': '6 桁のコード',
  'mfa.recovery': '回復コード',
  'mfa.use_recovery': '回復コードを使う',
  'mfa.use_code': '認証アプリのコードを使う',
  'mfa.submit': '確認する',
  'mfa.invalid': 'コードが違います。',
  'mfa.back': 'ログインからやり直す',

  'password.title': 'パスワードの変更',
  'password.intro': '続けるには、パスワードを変更してください。',
  'password.current': '今のパスワード',
  'password.new': '新しいパスワード',
  'password.confirm': '新しいパスワード（確認）',
  'password.hint': '12〜128 バイトで入力してください（日本語の文字は 1 文字が 3 バイトです）。',
  'password.mismatch': '新しいパスワードが一致しません。',
  'password.same': '新しいパスワードが今のパスワードと同じです。',
  'password.length': '新しいパスワードは 12〜128 バイトにしてください。',
  'password.submit': '変更する',

  'setup.title': '二要素認証の設定',
  'setup.body': '続けるには、二要素認証（MFA）を設定する必要があります。設定の画面はまだ使えません。',

  'nav.menu': 'メニュー',
  'nav.status': '状態',
  'bar.logout': 'ログアウト',
  'bar.language': '言語',
  'bar.warning': '選ばれた世代と実行中の世代が違います',
  'logout.failed': 'ログアウトを確認できませんでした。この画面はログインしたままです。もう一度試してください。',
  'theme.label': '表示',
  'theme.auto': '自動',
  'theme.light': '明るい',
  'theme.dark': '暗い',

  'status.title': '状態',
  'status.reload': '読み直す',
  'status.loading': '状態を読み込んでいます…',
  'status.read_at': '取得: {time}',
  'status.failed': '状態を読み込めませんでした。',
  'status.proxy': 'プロキシ',
  'status.state': '状態',
  'status.mode': '動作',
  'status.switching': '世代の切り替え',
  'status.switching_on': '切り替え中',
  'status.switching_off': 'なし',
  'status.unreachable': 'プロキシに接続できません。起動しているか確かめてください。',
  'status.busy': 'プロキシは今、状態の問い合わせに答える余裕がありません。少し待って読み直してください。',
  'status.generations': 'ルールの世代',
  'status.chosen': '選ばれた世代',
  'status.serving': '実行中の世代',
  'status.none': 'なし',
  'status.unknown': '不明',
  'status.same': '選ばれた世代と実行中の世代は一致しています。',
  'status.differ': '選ばれた世代と実行中の世代が違います。切り替えの途中か、切り替えに失敗した可能性があります。',
  'status.differ_switching': '切り替えの途中なので、2 つの世代が一時的に違います。',
  'status.rollback': '戻しの先',
  'status.rollback_none': '戻せる世代はありません。',
  'status.rollback_note': '戻しを実行すると、この世代が選ばれます。',
  'phase.starting': '起動中',
  'phase.ready': '稼働中',
  'phase.stopping': '停止の処理中',
  'phase.stopped': '停止',
  'phase.failed': '失敗',
  'mode.block': '遮断',
  'mode.detect': '検知のみ',

  'error.unknown_result': '結果が分かりません。接続が切れたか、応答が間に合わなかった可能性があります。状態を読み直して確かめてください。',
  'error.network': '管理のプロセスに接続できません。',
  'error.generic': '処理に失敗しました。',

  'invalid credentials': 'ユーザー名かパスワードが違います。',
  'too many tries': '試行が多すぎます。しばらく待ってからやり直してください。',
  'unavailable': '管理の状態を読み書きできないため、処理を断りました。変更は行われていません。',
  'unauthorized': 'ログインしていないか、有効期間が切れました。',
  'forbidden': 'この操作をする権限がありません。',
  'second factor required': '確認コードの入力が必要です。',
  'password change required': 'パスワードの変更が必要です。',
  'second factor setup required': '二要素認証の設定が必要です。',
  'the current password is wrong': '今のパスワードが違います。',
  'the new password is not 12 to 128 bytes': '新しいパスワードは 12〜128 バイトにしてください。',
  'conflict': '他の操作と重なりました。読み直してからやり直してください。',
  'not found': '見つかりません。',
  'bad request': '要求の内容が正しくありません。',
  'method not allowed': 'この方法では使えません。',
  'unsupported media type': '送る形式に対応していません。',
  'payload too large': '送る内容が大きすぎます。',
  'request timeout': '要求の受け取りが間に合いませんでした。',
  'internal error': '管理のプロセスの内部で誤りが起きました。',
};

const en = {
  'app.name': 'tukuyomi-core',
  'app.loading': 'Loading…',
  'app.failed': 'The admin page could not start.',
  'app.retry': 'Try again',
  'app.skip': 'Skip to the content',

  'login.title': 'Sign in',
  'login.name': 'User name',
  'login.password': 'Password',
  'login.submit': 'Sign in',
  'login.ended': 'Your session has ended. Sign in again.',
  'login.step_lost': 'The page was reloaded in the middle of the code step. Sign in again.',
  'login.step_expired': 'The time for entering the code (5 minutes) is over. Sign in again.',
  'login.changed': 'The password was changed, but the state of the session could not be read afterwards. Sign in again with the new password.',

  'mfa.title': 'Verification code',
  'mfa.intro': 'Enter the 6-digit code that your authenticator app shows.',
  'mfa.intro_recovery': 'Enter one of the recovery codes that you saved at the setup. A recovery code works once.',
  'mfa.code': '6-digit code',
  'mfa.recovery': 'Recovery code',
  'mfa.use_recovery': 'Use a recovery code',
  'mfa.use_code': 'Use the code of the app',
  'mfa.submit': 'Verify',
  'mfa.invalid': 'The code is wrong.',
  'mfa.back': 'Start again from the sign-in',

  'password.title': 'Change password',
  'password.intro': 'You must change your password to continue.',
  'password.current': 'Current password',
  'password.new': 'New password',
  'password.confirm': 'New password (again)',
  'password.hint': 'Use 12 to 128 bytes (a character may take more than one byte).',
  'password.mismatch': 'The new passwords do not match.',
  'password.same': 'The new password is the same as the current one.',
  'password.length': 'The new password must be 12 to 128 bytes.',
  'password.submit': 'Change password',

  'setup.title': 'Set up two-factor authentication',
  'setup.body': 'You must set up two-factor authentication (MFA) to continue. The setup screen is not available yet.',

  'nav.menu': 'Menu',
  'nav.status': 'Status',
  'bar.logout': 'Sign out',
  'bar.language': 'Language',
  'bar.warning': 'The chosen and serving generations differ',
  'logout.failed': 'The sign-out could not be confirmed. This page is still signed in. Try again.',
  'theme.label': 'Theme',
  'theme.auto': 'Auto',
  'theme.light': 'Light',
  'theme.dark': 'Dark',

  'status.title': 'Status',
  'status.reload': 'Reload',
  'status.loading': 'Reading the status…',
  'status.read_at': 'Read at {time}',
  'status.failed': 'The status could not be read.',
  'status.proxy': 'Proxy',
  'status.state': 'State',
  'status.mode': 'Mode',
  'status.switching': 'Switch of the generation',
  'status.switching_on': 'Under way',
  'status.switching_off': 'None',
  'status.unreachable': 'The proxy cannot be reached. Check that it is running.',
  'status.busy': 'The proxy has no room to answer a question just now. Wait a moment and reload.',
  'status.generations': 'Rule generations',
  'status.chosen': 'Chosen generation',
  'status.serving': 'Serving generation',
  'status.none': 'None',
  'status.unknown': 'Unknown',
  'status.same': 'The chosen generation is the one that serves.',
  'status.differ': 'The chosen generation is not the one that serves. A switch may be under way, or it may have failed.',
  'status.differ_switching': 'A switch is under way, so the two generations differ for now.',
  'status.rollback': 'Rollback target',
  'status.rollback_none': 'There is no generation to go back to.',
  'status.rollback_note': 'A rollback would choose this generation.',
  'phase.starting': 'Starting',
  'phase.ready': 'Running',
  'phase.stopping': 'Stopping',
  'phase.stopped': 'Stopped',
  'phase.failed': 'Failed',
  'mode.block': 'Block',
  'mode.detect': 'Detect only',

  'error.unknown_result': 'The result is not known. The connection may have dropped, or the answer came too late. Reload the status to check.',
  'error.network': 'The admin process cannot be reached.',
  'error.generic': 'The request failed.',

  'invalid credentials': 'The user name or the password is wrong.',
  'too many tries': 'Too many tries. Wait a while and try again.',
  'unavailable': 'The admin state cannot be read or written, so the request was refused. Nothing was changed.',
  'unauthorized': 'You are not signed in, or the session has ended.',
  'forbidden': 'You are not allowed to do this.',
  'second factor required': 'A verification code is required.',
  'password change required': 'The password must be changed.',
  'second factor setup required': 'Two-factor authentication must be set up.',
  'the current password is wrong': 'The current password is wrong.',
  'the new password is not 12 to 128 bytes': 'The new password must be 12 to 128 bytes.',
  'conflict': 'It clashed with another change. Reload and try again.',
  'not found': 'Not found.',
  'bad request': 'The request is not valid.',
  'method not allowed': 'This method is not allowed.',
  'unsupported media type': 'The format of the request is not supported.',
  'payload too large': 'The request is too large.',
  'request timeout': 'The request did not arrive in time.',
  'internal error': 'The admin process had an internal error.',
};

export const dictionaries = { ja, en };

let current = 'en';

/** The language to start with: the saved one if it is ours, else the first of `preferred` that is Japanese or English. */
export function pickLanguage(saved, preferred) {
  if (LANGUAGES.includes(saved)) return saved;
  for (const tag of Array.isArray(preferred) ? preferred : [preferred]) {
    const lower = typeof tag === 'string' ? tag.toLowerCase() : '';
    if (lower.startsWith('ja')) return 'ja';
    if (lower.startsWith('en')) return 'en';
  }
  return 'en';
}

export function setLanguage(language) {
  if (LANGUAGES.includes(language)) current = language;
  return current;
}

export function language() {
  return current;
}

/** The words for `key` in the chosen language, with `{name}` taken from `params`; the key itself if there are none. */
export function t(key, params = {}) {
  const words = dictionaries[current];
  if (!Object.hasOwn(words, key)) return key;
  return words[key].replace(/\{(\w+)\}/g, (whole, name) => (Object.hasOwn(params, name) ? String(params[name]) : whole));
}

/** The words for a sentence of the API: ours if we have them, else the sentence as the API gave it. */
export function sentence(text) {
  const words = dictionaries[current];
  return Object.hasOwn(words, text) ? words[text] : text;
}
