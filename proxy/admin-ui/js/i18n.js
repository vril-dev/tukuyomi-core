// The words of the page, in Japanese and in English. A key is a short name (`status.title`). The sentences that the
// API gives for a refusal are keys too, so that the page can show them in the chosen language; a sentence that is not
// in the dictionaries is shown as the API gave it. Here are the words of the frame of the page and of its shared parts,
// and the sentences that the frame or more than one folder of screens can show; a folder of screens keeps the words
// that only it uses in its `words.js` (and the words of the path of a route in `route-words.js`), and `dictionaries` is
// all of them together. Nothing runs when the module is loaded.

import { en as accountEnglish, ja as accountJapanese } from './account/words.js';
import { en as routeEnglish, ja as routeJapanese } from './managed/edit/route-words.js';
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
  'login.step_lost': 'コードの入力中に画面が再読み込みされました。もう一度ログインしてください。',
  'login.step_expired': 'コードの入力に使える時間（5 分）を過ぎました。もう一度ログインしてください。',
  'login.changed': 'パスワードを変更しましたが、その後のセッションの状態を読み込めませんでした。新しいパスワードでもう一度ログインしてください。',
  'login.draft_dropped': '保存していない下書きを破棄しました。',

  'mfa.title': '認証コードの入力',
  'mfa.intro': '認証アプリに表示されている 6 桁のコードを入力してください。',
  'mfa.intro_recovery': '設定時に保存したリカバリーコードを 1 つ入力してください。使用済みのリカバリーコードは使えません。',
  'mfa.code': '6 桁のコード',
  'mfa.recovery': 'リカバリーコード',
  'mfa.use_recovery': 'リカバリーコードを使う',
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
  'bar.warning': 'ルールの世代が一致していません',
  'logout.failed': 'ログアウトを確認できませんでした。この画面はログインしたままです。もう一度試してください。',
  'theme.label': 'テーマ',
  'theme.auto': '自動',
  'theme.light': 'ライト',
  'theme.dark': 'ダーク',

  'status.chosen': '選択中の世代',
  'status.serving': '稼働中の世代',
  'status.none': 'なし',
  'status.unknown': '不明',
  'mode.block': '遮断',
  'mode.detect': '検知のみ',
  'engine.coraza': 'Coraza',
  'engine.modsecurity': 'ModSecurity',
  'engine.default': 'デフォルト',
  'engine.default_name': 'デフォルトのエンジン',
  'engine.defaults_differ': '管理プロセスとプロキシで、デフォルトのエンジンが違います。両方を再起動してそろえてください。',

  'error.unknown_result': '結果は不明です。接続が切れたか、応答が間に合わなかった可能性があります。ステータスを再読み込みして確認してください。',
  'error.network': '管理プロセスに接続できません。',
  'error.generic': '処理に失敗しました。',
  'error.request': 'リクエスト ID は {id} です。管理者は、アクセスログの画面でこの ID を検索できます。',

  'invalid credentials': 'ユーザー名かパスワードが違います。',
  'too many tries': '試行が多すぎます。しばらく待ってからやり直してください。',
  'unavailable': '管理データを読み書きできないため、処理を受け付けませんでした。何も変更していません。',
  'unauthorized': 'ログインしていないか、有効期間が切れました。',
  'forbidden': 'この操作をする権限がありません。',
  'second factor required': '認証コードの入力が必要です。',
  'password change required': 'パスワードの変更が必要です。',
  'second factor setup required': '二要素認証の設定が必要です。',
  'conflict': '別の操作と競合しました。再読み込みしてから、もう一度試してください。',
  'not found': '見つかりません。',
  'bad request': 'リクエストの内容が正しくありません。',
  'method not allowed': 'このメソッドは使えません。',
  'unsupported media type': 'リクエストの形式に対応していません。',
  'payload too large': 'リクエストが大きすぎます。',
  'request timeout': 'リクエストの受信がタイムアウトしました。',
  'internal error': '管理プロセスで内部エラーが発生しました。',

  'screen.reload': '再読み込み',
  'confirm.cancel': 'キャンセル',

  'col.state': '状態',
  'col.engine': 'エンジン',
  'col.actions': '操作',
  'badge.unstarted': '未起動',

  'working.activate': '世代を切り替えています。プロキシの応答を待っています…',
  'working.rollback': '前の世代にロールバックしています。プロキシの応答を待っています…',
  'working.remove': '世代を削除しています…',
  'working.import': 'ルールをインポートしています。事前検証に時間がかかります…',
  'working.managed_activate': 'managed 設定のバージョンを反映しています…',
  'working.managed_rollback': 'managed 設定を前のバージョンにロールバックしています…',
  'working.managed_apply': '下書きを保存して反映しています…',

  'word.switched': '切り替え済み',
  'word.unchanged': '変更なし',
  'word.refused': 'プロキシが拒否',
  'word.failed': '失敗',
  'word.unreachable': '接続不可',
  'word.unconfirmed': '未確認',
  'word.busy': 'プロキシが処理中',
  'word.lost': '結果不明',
  'word.conflict': '競合',
  'word.unavailable': '受付不可',
  'word.forbidden': '権限なし',
  'word.limited': '回数制限中',
  'word.other': 'エラー',
  'out.switched': 'プロキシの {engine} は、世代 {to} で稼働しています。',
  'out.unchanged': 'プロキシの {engine} はすでに世代 {to} で稼働していたため、変更はありません。',
  'out.refused': 'プロキシが {engine} の世代 {to} への切り替えを拒否しました。ルールストアでは世代 {to} が選択されたままで、プロキシの {engine} は前の世代で稼働しています。',
  'out.refused_any': 'プロキシが {engine} の世代 {to} への切り替えを拒否しました。ルールストアでは世代 {to} が選択されたままです。',
  'out.refused_new': 'プロキシが {engine} の世代 {to} での起動を拒否しました。ルールストアでは世代 {to} が選択されたままで、プロキシでは {engine} が稼働していません。',
  'out.failed': 'プロキシは {engine} を世代 {to} に切り替えられませんでした。ルールストアでは世代 {to} が選択されたままなので、プロキシを再起動すると {engine} はその世代で起動します。',
  'out.unreachable': 'プロキシに接続できません。ルールストアは変更していません。',
  'out.unconfirmed': 'ルールストアで {engine} の世代 {to} を選択しましたが、プロキシから切り替えの結果が返りませんでした。',
  'out.busy': 'プロキシの制御ソケットが同時接続数の上限に達していたため、状態の問い合わせに応答がありませんでした。何も変更していません。',
  'out.lost': '応答がありませんでした。接続が切れたか、応答が間に合わなかったため、結果は不明です。',
  'out.unwritten': '履歴に、この操作の行を書き込めませんでした。',
  'next.check': '概要の画面で状態を確認してください。',
  'next.refused': '概要の画面で確認してください。元に戻すには、世代 {from} をもう一度選択してください。',
  'next.failed': '概要の画面で確認してください。世代 {to} を使わない場合は、世代 {from} をもう一度選択してください。',
  'next.unreachable': 'プロキシが起動しているか確認してから、もう一度試してください。',
  'next.unconfirmed': '概要の画面で、プロキシが世代 {to} で稼働しているか確認してください。稼働していなければ、世代 {from} をもう一度選択してください。',
  'next.busy': '少し待ってから、もう一度試してください。',
  'next.lost': 'ステータスと履歴を再読み込みしました。下の内容で確認してください。',
  'next.conflict': '一覧を再読み込みしました。内容を確認してから、もう一度試してください。',
  'found.title': '再読み込みの結果',
  'found.failed': 'ステータスか履歴を読み込めませんでした。',
  'found.newest': '履歴の最新の行',

  'history.empty': '履歴はありません。',

  'the proxy is busy': 'プロキシは今、受け付けられません。少し待ってから、もう一度試してください。',
  'the proxy cannot be reached': 'プロキシに接続できません。',
  'the directory cannot be read': 'ディレクトリを読めません。',
  'the directory is not a real directory': 'ディレクトリではありません（シンボリックリンクは使えません）。',
  'the directory has group or other permission bits': 'ディレクトリに、所有者以外が使える権限が付いています。',
  'the directory is not owned by this user': 'ディレクトリの所有者が、管理プロセスを実行しているユーザーではありません。',
  'cannot read the process status': 'プロセスの状態を読めません。',
  'the user ids are missing or malformed': 'プロセスのユーザー ID を読めません。',

  'login.mfa_changed': 'MFA を設定しましたが、その後のセッションの状態を読み込めませんでした。もう一度ログインしてください。',

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
  'table.clear': '絞り込みをクリア',
  'nav.group.waf': 'WAF',
  'nav.group.records': 'ログ',
  'nav.group.forward': 'プロキシ',
  'nav.group.policy': 'ポリシー',
  'nav.sites': 'サイト',
  'nav.upstreams': 'アップストリーム',
  'nav.routes': 'ルート',
  'nav.policy': 'アクセス制御とレート制限',
  'nav.group.managed': '設定',
  'nav.group.admin': '管理',
  'time.label': '時刻',
  'time.local': 'ローカル',
  'time.utc': 'UTC',
  'time.change': '時刻の表示を切り替える（現在: {now}）',
  'theme.change': 'テーマを切り替える（現在: {now}、次: {next}）',
  'route.dropped': 'アドレスの正しくない部分を取り除きました。',
  'login.busy': 'ログインしています',
  'mfa.busy': '確認しています',
};

const en = {
  'app.name': 'tukuyomi-core',
  'app.loading': 'Loading…',
  'app.failed': 'The admin screens could not start.',
  'app.retry': 'Try again',
  'app.skip': 'Skip to main content',

  'login.title': 'Log in',
  'login.name': 'User name',
  'login.password': 'Password',
  'login.submit': 'Log in',
  'login.ended': 'Your session has ended. Log in again.',
  'login.step_lost': 'The page was reloaded while you were entering the code. Log in again.',
  'login.step_expired': 'The time allowed for entering the code (5 minutes) has passed. Log in again.',
  'login.changed': 'Your password was changed, but the session state could not be loaded afterwards. Log in again with the new password.',
  'login.draft_dropped': 'An unsaved draft was discarded.',

  'mfa.title': 'Verification code',
  'mfa.intro': 'Enter the 6-digit code shown in your authenticator app.',
  'mfa.intro_recovery': 'Enter one of the recovery codes you saved during setup. Each recovery code can be used once.',
  'mfa.code': '6-digit code',
  'mfa.recovery': 'Recovery code',
  'mfa.use_recovery': 'Use a recovery code',
  'mfa.use_code': 'Use your authenticator app',
  'mfa.submit': 'Verify',
  'mfa.invalid': 'The code is wrong.',
  'mfa.back': 'Back to login',

  'password.title': 'Change password',
  'password.intro': 'You must change your password to continue.',

  'setup.title': 'Set up two-factor authentication',
  'setup.body': 'You must set up two-factor authentication (MFA) to continue.',

  'nav.menu': 'Menu',
  'bar.logout': 'Log out',
  'bar.language': 'Language',
  'bar.warning': 'Rule generations differ',
  'logout.failed': 'The logout could not be confirmed. You are still logged in on this page. Try again.',
  'theme.label': 'Theme',
  'theme.auto': 'Auto',
  'theme.light': 'Light',
  'theme.dark': 'Dark',

  'status.chosen': 'Chosen generation',
  'status.serving': 'Running generation',
  'status.none': 'None',
  'status.unknown': 'Unknown',
  'mode.block': 'Block',
  'mode.detect': 'Detect only',
  'engine.coraza': 'Coraza',
  'engine.modsecurity': 'ModSecurity',
  'engine.default': 'Default',
  'engine.default_name': 'Default engine',
  'engine.defaults_differ': 'The admin process and the proxy have different default engines. Restart both to make them the same.',

  'error.unknown_result': 'The result is unknown. The connection may have dropped, or the response may have arrived too late. Reload the status to check.',
  'error.network': 'The admin process cannot be reached.',
  'error.generic': 'The request failed.',
  'error.request': 'The request ID is {id}. An administrator can search for it on the Access log screen.',

  'invalid credentials': 'The user name or password is wrong.',
  'too many tries': 'Too many attempts. Wait a while and try again.',
  'unavailable': 'The admin data cannot be read or written, so the request was refused. Nothing was changed.',
  'unauthorized': 'You are not logged in, or your session has ended.',
  'forbidden': 'You are not allowed to do this.',
  'second factor required': 'A verification code is required.',
  'password change required': 'The password must be changed.',
  'second factor setup required': 'Two-factor authentication must be set up.',
  'conflict': 'The request conflicted with another change. Reload and try again.',
  'not found': 'Not found.',
  'bad request': 'The request is not valid.',
  'method not allowed': 'This method is not allowed.',
  'unsupported media type': 'The request format is not supported.',
  'payload too large': 'The request is too large.',
  'request timeout': 'The request did not arrive in time.',
  'internal error': 'The admin process had an internal error.',

  'screen.reload': 'Reload',
  'confirm.cancel': 'Cancel',

  'col.state': 'State',
  'col.engine': 'Engine',
  'col.actions': 'Actions',
  'badge.unstarted': 'Not running',

  'working.activate': 'Switching the generation. Waiting for the proxy to respond…',
  'working.rollback': 'Rolling back to the previous generation. Waiting for the proxy to respond…',
  'working.remove': 'Deleting the generation…',
  'working.import': 'Importing the rules. The trial takes a while…',
  'working.managed_activate': 'Applying the managed configuration version…',
  'working.managed_rollback': 'Rolling back the managed configuration to the previous version…',
  'working.managed_apply': 'Saving and applying the draft…',

  'word.switched': 'Switched',
  'word.unchanged': 'Unchanged',
  'word.refused': 'Refused by the proxy',
  'word.failed': 'Failed',
  'word.unreachable': 'Unreachable',
  'word.unconfirmed': 'Unconfirmed',
  'word.busy': 'Proxy busy',
  'word.lost': 'Result unknown',
  'word.conflict': 'Conflict',
  'word.unavailable': 'Not accepted',
  'word.forbidden': 'Not allowed',
  'word.limited': 'Rate limited',
  'word.other': 'Error',
  'out.switched': 'The proxy is now running generation {to} for {engine}.',
  'out.unchanged': 'The proxy was already running generation {to} for {engine}, so nothing changed.',
  'out.refused': 'The proxy refused to switch {engine} to generation {to}. Generation {to} is still chosen in the rules store, but for {engine}, the proxy keeps running the generation it was running before.',
  'out.refused_any': 'The proxy refused to switch {engine} to generation {to}. Generation {to} is still chosen in the rules store.',
  'out.refused_new': 'The proxy refused to start {engine} with generation {to}. Generation {to} is still chosen in the rules store, and {engine} is not running in the proxy.',
  'out.failed': 'The proxy did not switch {engine} to generation {to}. Generation {to} is still chosen in the rules store, so when the proxy is restarted, {engine} starts with that generation.',
  'out.unreachable': 'The proxy cannot be reached. The rules store was not changed.',
  'out.unconfirmed': 'Generation {to} is now chosen for {engine} in the rules store, but the proxy did not report the result of the switch.',
  'out.busy': 'The proxy did not respond to the state query because its control socket was at its limit of concurrent connections. Nothing was changed.',
  'out.lost': 'No response was received. The connection dropped or the response came too late, so the result is unknown.',
  'out.unwritten': 'The line for this operation could not be written to the history.',
  'next.check': 'Check the state on the Overview screen.',
  'next.refused': 'Check the Overview screen. To undo it, choose generation {from} again.',
  'next.failed': 'Check the Overview screen. If you do not want generation {to}, choose generation {from} again.',
  'next.unreachable': 'Check that the proxy is running, then try again.',
  'next.unconfirmed': 'On the Overview screen, check whether the proxy is running generation {to}. If it is not, choose generation {from} again.',
  'next.busy': 'Wait a moment and try again.',
  'next.lost': 'The status and the history have been reloaded. Check them below.',
  'next.conflict': 'The lists have been reloaded. Check them, then try again.',
  'found.title': 'State after reload',
  'found.failed': 'The status or the history could not be read.',
  'found.newest': 'Newest history line',

  'history.empty': 'There is no history.',

  'the proxy is busy': 'The proxy cannot accept this right now. Wait a moment and try again.',
  'the proxy cannot be reached': 'The proxy cannot be reached.',
  'the directory cannot be read': 'The directory cannot be read.',
  'the directory is not a real directory': 'The directory is not a real directory (symbolic links are not allowed).',
  'the directory has group or other permission bits': 'The directory has permissions for the group or other users.',
  'the directory is not owned by this user': 'The directory is not owned by the OS user that runs the admin process.',
  'cannot read the process status': 'The process status cannot be read.',
  'the user ids are missing or malformed': 'The process\'s user IDs cannot be read.',

  'login.mfa_changed': 'Two-factor authentication was set up, but the session state could not be loaded afterwards. Log in again.',

  // The tables, the dialogs and the forms.
  'field.required': 'required',
  'field.empty': 'Fill in this field.',
  'copy.button': 'Copy',
  'copy.done': 'Copied.',
  'copy.failed': 'Could not copy. Select the text and copy it by hand.',
  'dialog.close': 'Close',
  'table.filter': 'Filter this table',
  'table.count': 'Rows: {n}',
  'table.count_of': 'Rows: {shown} of {total}',
  'table.range': 'Rows {from}–{to} of {total}',
  'table.prev': 'Previous',
  'table.next': 'Next',
  'table.loading': 'Loading…',
  'table.no_match': 'No rows match.',
  'table.clear': 'Clear the filter',
  'nav.group.waf': 'WAF',
  'nav.group.records': 'Logs',
  'nav.group.forward': 'Proxy',
  'nav.group.policy': 'Policy',
  'nav.sites': 'Sites',
  'nav.upstreams': 'Upstreams',
  'nav.routes': 'Routes',
  'nav.policy': 'Access control and rate limits',
  'nav.group.managed': 'Configuration',
  'nav.group.admin': 'Admin',
  'time.label': 'Time',
  'time.local': 'Local',
  'time.utc': 'UTC',
  'time.change': 'Change how times are shown (now: {now})',
  'theme.change': 'Change the theme (now: {now}, next: {next})',
  'route.dropped': 'Removed the invalid parts of the address.',
  'login.busy': 'Logging in',
  'mfa.busy': 'Verifying',
};

export const dictionaries = {
  ja: { ...ja, ...wafJapanese, ...accountJapanese, ...managedJapanese, ...editJapanese, ...routeJapanese },
  en: { ...en, ...wafEnglish, ...accountEnglish, ...managedEnglish, ...editEnglish, ...routeEnglish },
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
