# Python 向け実装例 (Django, FastAPI, Flask等)

## データベース
```python
# NG: 文字列フォーマットでSQLiに脆弱
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# OK: プレースホルダ (DB-API標準)
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))

# OK: Django ORM（常にパラメータ化される）
User.objects.filter(email=email)

# OK: SQLAlchemy Core/ORM
select(User).where(User.email == email)

# 動的にORDER BYを組み立てる場合は allowlist で変換
SORTABLE_COLUMNS = {"created_at", "name"}
sort_by = sort_by if sort_by in SORTABLE_COLUMNS else "created_at"
```
接続情報は環境変数（`os.environ`）や `django-environ` 等から読み込み、`settings.py` に直書きしない。
本番DBはTLSで接続し、証明書を検証する（`sslmode=verify-full`）。

## 入力値検証
- Django: `forms.Form` / `ModelForm` / DRFの `Serializer` でバリデーションする。
- FastAPI: Pydanticモデルで型・制約を宣言し、自動検証させる。
- テンプレート（Django Template, Jinja2）はデフォルトで自動エスケープされる。`|safe` フィルタや
  `mark_safe()` の使用は必要最小限にし、外部入力に対しては使わない。

## 認証・パスワード
```python
from django.contrib.auth.hashers import make_password, check_password
hashed = make_password(raw_password)  # PBKDF2/Argon2等
check_password(raw_password, hashed)
```
Djangoを使わない場合は `passlib` や `bcrypt` パッケージでハッシュ化する。

## セッション
- Django: `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`
- `SESSION_EXPIRE_AT_BROWSER_CLOSE` やタイムアウト設定を用途に応じて有効化する。

## CSRF / セキュリティ設定
- Django: `CsrfViewMiddleware` はデフォルト有効。フォームには `{% csrf_token %}` を必ず入れる。
- `DEBUG = False` を本番設定で徹底し、`ALLOWED_HOSTS` を適切に設定する。
- `django-csp` 等でCSPヘッダを設定する。

## 秘密情報管理
- `SECRET_KEY` やDB認証情報を `settings.py` にハードコードせず、環境変数か `python-decouple`/`django-environ` 経由。
- 環境変数が未設定の場合、既知の固定文字列へ静かにフォールバックしない（fail-fast）。`os.environ['SECRET_KEY']`
  のように添字アクセスを使えば未設定時に`KeyError`で即座に止まる。`os.environ.get('SECRET_KEY')`は
  デフォルト値を与えなくても例外を送出せず`None`を静かに返してしまうため、この用途では使わない
  （使う場合は戻り値が`None`かを自分でチェックして例外を送出する）。詳細な考え方は
  `references/lang/nodejs-typescript.md`の「秘密情報管理」節を参照。

## 依存関係
```bash
pip install pip-audit
pip-audit
```

## エラー処理
- 本番では `DEBUG=False` にし、詳細なトレースバックをユーザーに見せない。カスタム500ページを用意する。
- ログには詳細を残しつつ、パスワードやトークンをログ出力しない（DjangoならログフィルタでSensitive情報をマスク）。
