// The words of the page, in Japanese and in English. A key is a short name (`status.title`). The sentences that the
// API gives for a refusal are keys too, so that the page can show them in the chosen language; a sentence that is not
// in the dictionaries is shown as the API gave it. Here are the words of the frame of the page and of its shared parts,
// and the sentences that the frame or more than one folder of screens can show; a folder of screens keeps the words
// that only it uses in its `words.js`, and `dictionaries` is all of them together. Nothing runs when the module is
// loaded.

import { en as accountEnglish, ja as accountJapanese } from './account/words.js';
import { en as editEnglish, ja as editJapanese } from './managed/edit/words.js';
import { en as managedEnglish, ja as managedJapanese } from './managed/words.js';
import { en as wafEnglish, ja as wafJapanese } from './waf/words.js';

export const LANGUAGES = ['ja', 'en'];

const ja = {
  'app.name': 'tukuyomi-core',
  'app.loading': '読み込み中…',
  'app.failed': '管理画面を開始できませんでした。',
  'app.retry': 'もう一度試す',
  'app.skip': '本文へ移動',

  'login.title': 'ログイン',
  'login.name': 'ユーザー名',
  'login.password': 'パスワード',
  'login.submit': 'ログイン',
  'login.ended': 'ログインの有効期間が切れました。もう一度ログインしてください。',
  'login.step_lost': 'コードの入力の途中で画面が読み込み直されました。もう一度ログインしてください。',
  'login.step_expired': 'コードの入力に使える時間（5 分）を過ぎました。もう一度ログインしてください。',
  'login.changed': 'パスワードを変更しました。その後のログインの状態を読み込めなかったので、新しいパスワードでもう一度ログインしてください。',
  'login.draft_dropped': '保存していない下書きを捨てました。',

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

  'setup.title': '二要素認証の設定',
  'setup.body': '続けるには、二要素認証（MFA）を設定する必要があります。',

  'nav.menu': 'メニュー',
  'bar.logout': 'ログアウト',
  'bar.language': '言語',
  'bar.warning': '世代が一致していません',
  'logout.failed': 'ログアウトを確認できませんでした。この画面はログインしたままです。もう一度試してください。',
  'theme.label': '表示',
  'theme.auto': '自動',
  'theme.light': '明るい',
  'theme.dark': '暗い',

  'status.chosen': '選ばれた世代',
  'status.serving': '実行中の世代',
  'status.none': 'なし',
  'status.unknown': '不明',
  'mode.block': '遮断',
  'mode.detect': '検知のみ',
  'engine.coraza': 'Coraza',
  'engine.modsecurity': 'ModSecurity',

  'error.unknown_result': '結果が分かりません。接続が切れたか、応答が間に合わなかった可能性があります。状態を読み直して確かめてください。',
  'error.network': '管理のプロセスに接続できません。',
  'error.generic': '処理に失敗しました。',
  'error.request': '要求の番号は {id} です。管理者は、要求の記録の画面でこの番号を探せます。',

  'invalid credentials': 'ユーザー名かパスワードが違います。',
  'too many tries': '試行が多すぎます。しばらく待ってからやり直してください。',
  'unavailable': '管理の状態を読み書きできないため、処理を断りました。変更は行われていません。',
  'unauthorized': 'ログインしていないか、有効期間が切れました。',
  'forbidden': 'この操作をする権限がありません。',
  'second factor required': '確認コードの入力が必要です。',
  'password change required': 'パスワードの変更が必要です。',
  'second factor setup required': '二要素認証の設定が必要です。',
  'conflict': '他の操作と重なりました。読み直してからやり直してください。',
  'not found': '見つかりません。',
  'bad request': '要求の内容が正しくありません。',
  'method not allowed': 'この方法では使えません。',
  'unsupported media type': '送る形式に対応していません。',
  'payload too large': '送る内容が大きすぎます。',
  'request timeout': '要求の受け取りが間に合いませんでした。',
  'internal error': '管理のプロセスの内部で誤りが起きました。',

  'screen.reload': '読み直す',
  'confirm.cancel': '取り消す',

  'col.state': '状態',
  'col.actions': '操作',

  'working.activate': '世代を切り替えています。プロキシの答えを待っています…',
  'working.rollback': '前の世代に戻しています。プロキシの答えを待っています…',
  'working.remove': '世代を削除しています…',
  'working.import': 'ルールを取り込んでいます。試しの実行に時間がかかります…',
  'working.managed_activate': '画面の設定の版を反映しています…',
  'working.managed_rollback': '画面の設定を前の版に戻しています…',
  'working.managed_apply': '下書きを保存して反映しています…',

  'word.switched': '切り替え済み',
  'word.unchanged': '変更なし',
  'word.refused': 'プロキシが拒否',
  'word.failed': '失敗',
  'word.unreachable': '接続できない',
  'word.unconfirmed': '結果を確認できない',
  'word.busy': 'プロキシが処理中',
  'word.lost': '結果が分からない',
  'word.conflict': '他の操作と重なった',
  'word.unavailable': '受け付けられない',
  'word.forbidden': '権限がない',
  'word.limited': '待ってください',
  'word.other': 'エラー',
  'out.switched': 'プロキシは世代 {to} に切り替わりました。',
  'out.unchanged': 'プロキシはすでに世代 {to} を使っていたので、何も変わっていません。',
  'out.refused': 'プロキシが世代 {to} への切り替えを断りました。保管場所は {to} を選んだままですが、プロキシは前の世代を使い続けています。',
  'out.failed': 'プロキシは世代 {to} に切り替えられませんでした。保管場所は {to} を選んだままで、プロキシを起動し直すとその世代で始まります。',
  'out.unreachable': 'プロキシに接続できません。保管場所は変えていません。',
  'out.unconfirmed': '保管場所は世代 {to} を選びましたが、プロキシが切り替えの結果を答えませんでした。',
  'out.busy': 'プロキシは別の切り替えの途中で、今は受け付けられません。何も変えていません。',
  'out.lost': '答えが届きませんでした。接続が切れたか、答えが間に合わなかったため、結果が分かりません。',
  'out.unwritten': '履歴に、この操作の行を書けませんでした。',
  'next.refused': '概要の画面で確かめてください。元に戻すには、世代 {from} をもう一度選んでください。',
  'next.failed': '概要の画面で確かめてください。世代 {to} を使わないなら、世代 {from} をもう一度選んでください。',
  'next.unreachable': 'プロキシが起動しているか確かめてから、もう一度試してください。',
  'next.unconfirmed': '概要の画面で、プロキシが世代 {to} を使っているか確かめてください。使っていなければ、世代 {from} をもう一度選んでください。',
  'next.busy': '少し待ってから、もう一度試してください。',
  'next.lost': '状態と履歴を読み直しました。下の内容で確かめてください。',
  'next.conflict': '一覧を読み直しました。内容を確かめてから、もう一度試してください。',
  'found.title': '読み直した結果',
  'found.failed': '状態か履歴を読み込めませんでした。',
  'found.newest': '履歴の最新の行',

  'history.empty': '履歴はありません。',

  'the proxy is busy': 'プロキシは今、受け付けられません。少し待ってから、もう一度試してください。',
  'the proxy cannot be reached': 'プロキシに接続できません。',
  'the directory cannot be read': 'ディレクトリを読めません。',
  'the directory is not a real directory': '実際のディレクトリではありません（リンクは数えません）。',
  'the directory has group or other permission bits': 'ディレクトリに、持ち主以外が使える権限が付いています。',
  'the directory is not owned by this user': 'ディレクトリの持ち主が、管理のプロセスを動かしている利用者ではありません。',
  'cannot read the process status': 'プロセスの状態を読めません。',
  'the user ids are missing or malformed': 'プロセスの利用者の番号を読めません。',

  'login.mfa_changed': 'MFA を設定しましたが、そのあとのログインの状態を読み込めませんでした。もう一度ログインしてください。',

  // The tables, the dialogs and the forms.
  'field.required': '必須',
  'field.empty': 'この項目を入力してください。',
  'copy.button': 'コピー',
  'copy.done': 'コピーしました。',
  'copy.failed': 'コピーできませんでした。文字を選んで、手でコピーしてください。',
  'dialog.close': '閉じる',
  'table.filter': '表の中を絞り込む',
  'table.count': '{n} 件',
  'table.count_of': '{total} 件のうち {shown} 件',
  'table.range': '{from}–{to} 件目（全 {total} 件）',
  'table.prev': '前へ',
  'table.next': '次へ',
  'table.loading': '読み込んでいます…',
  'table.no_match': '条件に合う行はありません。',
  'table.clear': '絞り込みを消す',
  'nav.group.waf': 'WAF',
  'nav.group.records': '記録',
  'nav.group.forward': '転送',
  'nav.group.policy': '方針',
  'nav.upstreams': '上流の組',
  'nav.policy': 'アクセスと流量',
  'nav.group.managed': '設定',
  'nav.group.admin': '管理',
  'time.label': '時刻',
  'time.local': '手元',
  'time.utc': 'UTC',
  'time.change': '時刻の書き方を切り替える（今: {now}）',
  'theme.change': '表示を切り替える（今: {now}、次: {next}）',
  'route.dropped': 'アドレスの正しくない部分を取り除きました。',
  'login.busy': 'ログインしています',
  'mfa.busy': '確認しています',
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
  'login.draft_dropped': 'A draft that was not saved has been discarded.',

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

  'setup.title': 'Set up two-factor authentication',
  'setup.body': 'You must set up two-factor authentication (MFA) to continue.',

  'nav.menu': 'Menu',
  'bar.logout': 'Sign out',
  'bar.language': 'Language',
  'bar.warning': 'The generations differ',
  'logout.failed': 'The sign-out could not be confirmed. This page is still signed in. Try again.',
  'theme.label': 'Theme',
  'theme.auto': 'Auto',
  'theme.light': 'Light',
  'theme.dark': 'Dark',

  'status.chosen': 'Chosen generation',
  'status.serving': 'Serving generation',
  'status.none': 'None',
  'status.unknown': 'Unknown',
  'mode.block': 'Block',
  'mode.detect': 'Detect only',
  'engine.coraza': 'Coraza',
  'engine.modsecurity': 'ModSecurity',

  'error.unknown_result': 'The result is not known. The connection may have dropped, or the answer came too late. Reload the status to check.',
  'error.network': 'The admin process cannot be reached.',
  'error.generic': 'The request failed.',
  'error.request': 'The request ID is {id}. An administrator can search for it on the Requests screen.',

  'invalid credentials': 'The user name or the password is wrong.',
  'too many tries': 'Too many tries. Wait a while and try again.',
  'unavailable': 'The admin state cannot be read or written, so the request was refused. Nothing was changed.',
  'unauthorized': 'You are not signed in, or the session has ended.',
  'forbidden': 'You are not allowed to do this.',
  'second factor required': 'A verification code is required.',
  'password change required': 'The password must be changed.',
  'second factor setup required': 'Two-factor authentication must be set up.',
  'conflict': 'It clashed with another change. Reload and try again.',
  'not found': 'Not found.',
  'bad request': 'The request is not valid.',
  'method not allowed': 'This method is not allowed.',
  'unsupported media type': 'The format of the request is not supported.',
  'payload too large': 'The request is too large.',
  'request timeout': 'The request did not arrive in time.',
  'internal error': 'The admin process had an internal error.',

  'screen.reload': 'Reload',
  'confirm.cancel': 'Cancel',

  'col.state': 'State',
  'col.actions': 'Actions',

  'working.activate': 'Switching the generation. Waiting for the proxy to answer…',
  'working.rollback': 'Rolling back. Waiting for the proxy to answer…',
  'working.remove': 'Removing the generation…',
  'working.import': 'Importing the rules. The trial takes a while…',
  'working.managed_activate': 'Applying the version of the managed configuration…',
  'working.managed_rollback': 'Rolling back the managed configuration…',
  'working.managed_apply': 'Saving and applying the draft…',

  'word.switched': 'Switched',
  'word.unchanged': 'Unchanged',
  'word.refused': 'Refused by the proxy',
  'word.failed': 'Failed',
  'word.unreachable': 'Unreachable',
  'word.unconfirmed': 'Unconfirmed',
  'word.busy': 'Proxy busy',
  'word.lost': 'Result unknown',
  'word.conflict': 'Clashed with another change',
  'word.unavailable': 'Not accepted',
  'word.forbidden': 'Not allowed',
  'word.limited': 'Wait',
  'word.other': 'Error',
  'out.switched': 'The proxy now serves generation {to}.',
  'out.unchanged': 'The proxy served generation {to} already, so nothing changed.',
  'out.refused': 'The proxy refused to switch to generation {to}. The rules store still chooses {to}, but the proxy keeps serving its earlier generation.',
  'out.failed': 'The proxy did not switch to generation {to}. The rules store still chooses {to}, and a proxy that is started again starts with it.',
  'out.unreachable': 'The proxy cannot be reached. The rules store was not changed.',
  'out.unconfirmed': 'The rules store now chooses generation {to}, but the proxy did not say how the switch ended.',
  'out.busy': 'The proxy is in the middle of another switch and cannot take this one now. Nothing was changed.',
  'out.lost': 'No answer came. The connection dropped or the answer was too late, so the result is not known.',
  'out.unwritten': 'The history has no line for this request.',
  'next.refused': 'Check the Overview screen. To undo it, choose generation {from} again.',
  'next.failed': 'Check the Overview screen. If you do not want generation {to}, choose generation {from} again.',
  'next.unreachable': 'Check that the proxy is running, then try again.',
  'next.unconfirmed': 'Check on the Overview screen whether the proxy serves generation {to}. If it does not, choose generation {from} again.',
  'next.busy': 'Wait a moment and try again.',
  'next.lost': 'The status and the history were read again. Check them below.',
  'next.conflict': 'The lists were read again. Check them, then try again.',
  'found.title': 'What was found on reading again',
  'found.failed': 'The status or the history could not be read.',
  'found.newest': 'Newest line of the history',

  'history.empty': 'There is no history.',

  'the proxy is busy': 'The proxy cannot take this just now. Wait a moment and try again.',
  'the proxy cannot be reached': 'The proxy cannot be reached.',
  'the directory cannot be read': 'The directory cannot be read.',
  'the directory is not a real directory': 'It is not a real directory (a link does not count).',
  'the directory has group or other permission bits': 'The directory gives permissions to its group or to others.',
  'the directory is not owned by this user': 'The directory is not owned by the user that runs the admin process.',
  'cannot read the process status': 'The state of the process cannot be read.',
  'the user ids are missing or malformed': 'The user ids of the process cannot be read.',

  'login.mfa_changed': 'Two-factor authentication was set up, but the state of the session could not be read afterwards. Sign in again.',

  // The tables, the dialogs and the forms.
  'field.required': 'required',
  'field.empty': 'Fill in this field.',
  'copy.button': 'Copy',
  'copy.done': 'Copied.',
  'copy.failed': 'Could not copy. Select the text and copy it by hand.',
  'dialog.close': 'Close',
  'table.filter': 'Filter this table',
  'table.count': '{n} rows',
  'table.count_of': '{shown} of {total} rows',
  'table.range': 'Rows {from}–{to} of {total}',
  'table.prev': 'Previous',
  'table.next': 'Next',
  'table.loading': 'Loading…',
  'table.no_match': 'No row matches.',
  'table.clear': 'Clear the filter',
  'nav.group.waf': 'WAF',
  'nav.group.records': 'Records',
  'nav.group.forward': 'Forwarding',
  'nav.group.policy': 'Policy',
  'nav.upstreams': 'Upstream groups',
  'nav.policy': 'Access and rate',
  'nav.group.managed': 'Configuration',
  'nav.group.admin': 'Admin',
  'time.label': 'Time',
  'time.local': 'Local',
  'time.utc': 'UTC',
  'time.change': 'Change how times are written (now: {now})',
  'theme.change': 'Change the theme (now: {now}, next: {next})',
  'route.dropped': 'Removed what was not valid in the address.',
  'login.busy': 'Signing in',
  'mfa.busy': 'Verifying',
};

export const dictionaries = {
  ja: { ...ja, ...wafJapanese, ...accountJapanese, ...managedJapanese, ...editJapanese },
  en: { ...en, ...wafEnglish, ...accountEnglish, ...managedEnglish, ...editEnglish },
};

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

/**
 * Words that are worked out when they are shown, and again when the language changes (see `retranslate` in `dom.js`):
 * a screen is not drawn again for the language, so a text that it gives to an element is one of these, not a string.
 */
export class Words {
  #make;

  constructor(make) {
    this.#make = make;
  }

  text() {
    return String(this.#make());
  }

  toString() {
    return this.text();
  }
}

/** The words for `key` as `Words`; `params` are read each time the words are worked out. */
export function w(key, params = {}) {
  return new Words(() => t(key, params));
}

/** Words that `make` gives, for a text that is put together from more than one key or from the state of the page. */
export function lazy(make) {
  return new Words(make);
}

/** A number with the digits in groups, as the chosen language writes it. */
export function formatNumber(value) {
  return new Intl.NumberFormat(current === 'ja' ? 'ja-JP' : 'en-US').format(value);
}
