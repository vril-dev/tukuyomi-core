// The words of the path of a route as a regular expression, and of its priority, in Japanese and in English, with the
// sentences of the API that a check and a saving can give about them. `i18n.js` puts them in the dictionaries. This
// file imports nothing.

export const ja = {
  'edit.col.regex': '正規表現',
  'edit.col.priority': '優先度 {n}',
  'edit.route.path_regex': 'パスを正規表現として扱う',
  'edit.route.path_regex_hint': '任意です。空欄のときは、すべてのパスに一致します。プロキシが受け取ったままのパス（URL デコードなし）の一部に一致すれば、このルートに一致します。パス全体に一致させるときは、^ と $ を書いてください。正規表現のルートには、アクセス制御と書き換え後のパスを設定できません。',
  'edit.route.priority': '優先度',
  'edit.route.priority_hint': '任意です。-1000〜1000 の整数を入力してください。空欄のときは 0 です。数が小さいルートが先に選ばれますが、比べるのは、ホストの一致の仕方が同じルートの間だけです。ホストを書いたルートは、数にかかわらず、ホストを書いていないルートより先に選ばれます。',

  'a route has both a path and a path regex': 'ルートに、パスとパスの正規表現を同時に指定することはできません。',
  'a route path regex is not 1 to 255 bytes': 'パスの正規表現は 1〜255 バイトの範囲で入力してください。',
  'a route path regex has a character that is not allowed': 'パスの正規表現に使えない文字があります。使えるのは、0x21〜0x7e の範囲の ASCII の文字だけです（空白は使えません）。',
  'a route path regex is not a valid regular expression': 'パスの正規表現の構文が正しくありません。書き方を確認してください。',
  'a route path regex is too large': 'パスの正規表現が大きすぎます。繰り返しを減らすなど、式を単純にしてください。',
  'routes has more than 32 entries with a path regex': 'パスが正規表現のルートは 32 件までです。',
  'a route with a path regex has an access list': 'パスが正規表現のルートには、アクセス制御を設定できません。このルートのアクセス制御を使わないか、パスを正規表現にしないでください。',
  'a rewrite path is set on a route with a path regex': 'パスが正規表現のルートには、書き換え後のパスを設定できません。書き換え後のパスを空にするか、パスを正規表現にしないでください。',
  'a route priority is not -1000 to 1000': '優先度は -1000〜1000 の整数で入力してください。',
};

export const en = {
  'edit.col.regex': 'Regex',
  'edit.col.priority': 'Priority {n}',
  'edit.route.path_regex': 'Treat the path as a regular expression',
  'edit.route.path_regex_hint': 'Optional. If empty, the route matches any path. The route matches when the expression matches any part of the path as the proxy received it, without URL decoding. To match the whole path, write ^ and $. A route with a regular expression cannot have access control or a path to rewrite to.',
  'edit.route.priority': 'Priority',
  'edit.route.priority_hint': 'Optional. An integer from -1000 to 1000; if empty, 0. A route with a smaller number is chosen first, but only among routes whose host matches the request in the same way. A route that has a host always comes before one that has none.',

  'a route has both a path and a path regex': 'A route cannot have both a path and a regular expression for the path.',
  'a route path regex is not 1 to 255 bytes': 'The regular expression for the path must be 1 to 255 bytes.',
  'a route path regex has a character that is not allowed': 'The regular expression for the path contains a character that is not allowed. Use only ASCII characters in the range 0x21 to 0x7e (a space is not allowed).',
  'a route path regex is not a valid regular expression': 'The regular expression for the path is not valid. Check its syntax.',
  'a route path regex is too large': 'The regular expression for the path is too large. Simplify it, for example with fewer repetitions.',
  'routes has more than 32 entries with a path regex': 'At most 32 routes can have a regular expression for the path.',
  'a route with a path regex has an access list': 'A route whose path is a regular expression cannot have access control. Turn off the route\'s access control, or use a path that is not a regular expression.',
  'a rewrite path is set on a route with a path regex': 'A route whose path is a regular expression cannot have a path to rewrite to. Clear the path to rewrite to, or use a path that is not a regular expression.',
  'a route priority is not -1000 to 1000': 'Priority must be an integer from -1000 to 1000.',
};
