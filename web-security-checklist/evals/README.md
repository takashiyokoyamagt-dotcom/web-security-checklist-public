# 評価用フィクスチャ（evals/）

`web-security-checklist` SKILLの動作確認・回帰確認に使う入力と、その実行環境の作り方・基準値をまとめる。
このディレクトリはSKILLの規則ではない（実行時に読む必要はない）。

## 構成

| パス                                                                       | 内容                                                                                                       |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `mini-vulnerable-app/`                                                     | 極小の脆弱アプリ（`server.js` 1本、約40行）。lockfileを持たない                                            |
| `sample-vulnerable-app/`                                                   | 本格評価用の脆弱アプリ（9ファイル・約290行、Express＋SQLite）。`package-lock.json`で依存の版を固定している |
| `mini-vulnerable-app-answer-key.md`, `sample-vulnerable-app-answer-key.md` | 採点用の答え合わせ                                                                                         |
| `sample-diff-delete-account.diff`                                          | モード2の評価に使う差分（`sample-vulnerable-app`へのPRとして扱う）                                         |
| `gen-target-app/`                                                          | モード1の評価に使う雛形                                                                                    |
| `evals.json`                                                               | 評価項目（依頼文・対象ファイル・期待する結果）                                                             |
| `setup-evals.sh`                                                           | `sample-vulnerable-app`の実行環境（`node_modules/`と種データ入りの`data/app.db`）を作る                    |
| `sample-vulnerable-app-seed.js`                                            | `setup-evals.sh`が使う種データの投入（アプリの外に置く）                                                   |
| `baselines/`                                                               | 過去の実行に対する検査結果・SCAの期待値（見方は`baselines/README.md`）                                     |

## 2つのサンプルアプリの使い分け

- `mini-vulnerable-app`: SKILL・リント設定を変えた後に、モード3が一通り動くかを短時間で確かめる。lockfileが無いので、`scripts/run_sca_scan.sh`の「lockfile無し」の経路（一時ディレクトリでlockfileを生成して監査する）の確認にも使う。
- `sample-vulnerable-app`: 規模を大きくしたときの回帰確認に使う（`docs/HISTORY.md`の40節のrun4）。lockfileで版が固定されているので、SCAの件数を基準値と比べられる（下記）。
- どちらも意図的に脆弱なコードであり、実運用に使わない。コード・`package.json`・`package-lock.json`は評価の入力そのもの（過去の報告書が`file:line`で参照している）なので、lintの指摘や依存の更新に合わせて書き換えない。
- `sample-vulnerable-app-seed.js`は種データを入れるための補助で、仕込んだ脆弱性には含めない（答え合わせにも無い）。監査の対象に入らないよう、アプリのディレクトリの外に置いている。

## 監査エージェントに読ませないもの

次は採点・準備のためのファイルで、どこにどの脆弱性があるかのヒントを含む。監査を行うエージェント（Red/Blue Team・Arbiter・文章化担当等）には読ませない。監査の対象はアプリのコピーだけにし、これらはコピーに含めない（手順は下記）。

- `evals/*answer-key*`（答え合わせ。`evals.json`の評価項目にも、Blue Teamが`evals/*answer-key*`を読んでいないことを含めている）
- `evals/README.md`（このファイル）と`evals/baselines/`
- `evals/setup-evals.sh`と`evals/sample-vulnerable-app-seed.js`

## セットアップ

`sample-vulnerable-app`を起動して挙動を再現する（例: `GET /users`が平文のパスワードを返す）には、`node_modules/`と種データ入りの`data/app.db`が要る。どちらも`.gitignore`で除外しているので、`evals/`の外のコピー先で作る。以下のコマンドはスキルのディレクトリ（`web-security-checklist/`）で実行する。

```bash
mkdir -p <コピー先>
rsync -a --exclude node_modules --exclude data --exclude .env evals/sample-vulnerable-app/ <コピー先>/
bash evals/setup-evals.sh <コピー先>
cd <コピー先> && node server.js
```

- `setup-evals.sh`は、`npm ci`（`package-lock.json`の版）と、`sample-vulnerable-app-seed.js`による`data/app.db`の作成を行う。既存の`data/app.db`は上書きしない（作り直すときは`--force`）。アプリのコードは変更しない。
- 書き込み先の指定は必須である。引数なし・空の引数では何もせずにrc2で終わる。元の`evals/sample-vulnerable-app`に作るのは`--in-place`を明示したときだけで、元の`evals/`に`node_modules/`と`data/`ができるので、通常は使わない。
- 書き込むのは、コピー先の`node_modules/`と`data/app.db`、npmのキャッシュ（`~/.npm`）、ビルドに落ちたときはnode-gypのキャッシュ（`~/.cache/node-gyp`、macOSでは`~/Library/Caches/node-gyp`）である。
- ネットワーク接続が要る（npmレジストリと、sqlite3のプリビルドの取得先のGitHub）。sqlite3のネイティブモジュールを用意するため`--ignore-scripts`は付けない。プリビルドの取得に失敗するとnode-gypでのビルドになり、python3とC++コンパイラが要る（実測: super-linterのイメージ（Alpine、C++コンパイラ無し）で、1回目はプリビルドの取得に失敗してビルドに回り失敗した。再実行するとプリビルドを取得して通った（同日の別の実行では1回目で通った））。
- 種データは`users`の1行（`bob@example.com`、パスワード`pw123`、一般ユーザー）だけで、`comments`は空である。表の定義はアプリの`db.js`のもの。作られる`data/app.db`は、これまで使ってきたDBとバイト単位で一致する（2026-10-10に確認）。
- `mini-vulnerable-app`の監査には`npm install`は不要である（静的に読むだけで監査できる）。起動して確かめるときは、コピー先で`npm install`をしてから`server.js`だけを起動する（`node server.js`。DBは起動時にカレントディレクトリへ`app.db`として作られ、種データは無い）。lockfileが無いので、`sqlite3`等の版はその時点で解決される。

## モード3の検証手順（要点）

1. 監査の対象として、gitで追跡しているファイルだけを`evals/`の外へコピーする（コマンドはスキルのディレクトリで実行する）。元の`evals/`は変更しない（監査中の再現・修正案の試験がファイルを作るため）。

   ```bash
   mkdir -p <コピー先>
   # コミット済みの内容（追跡しているファイルだけ）
   git archive HEAD evals/sample-vulnerable-app | tar -x -C <コピー先> --strip-components=2
   # 作業ツリーの内容を使う場合（追跡していない node_modules/・data/・.env を除く）
   rsync -a --exclude node_modules --exclude data --exclude .env evals/sample-vulnerable-app/ <コピー先>/
   ```

2. コピー先に、上記の読ませないものが入っていないことを確かめる。`README.md`はアプリ自身のもの（元の仕様どおり含める）であることを比べる。

   ```bash
   find <コピー先> \( -name '*answer-key*' -o -name baselines -o -name setup-evals.sh -o -name '*-seed.js' \) -print  # 何も出ないこと
   diff <コピー先>/README.md evals/sample-vulnerable-app/README.md  # 差が無いこと
   ls -a <コピー先>  # package-lock.json があること
   ```

3. コピー先で依存と種データを入れる: `bash evals/setup-evals.sh <コピー先>`（`package-lock.json`の版で`npm ci`する。SCAはlockfileだけで行えるが、Arbiterの実機再現には`node_modules/`と`data/app.db`が要る）。
4. コピー先を対象に、`evals.json`の依頼文でモード3を実行する。依頼文のパス（`evals/sample-vulnerable-app`）はコピー先のパスに読み替える。厳格度とCVSS環境メトリクス（指定が無ければ想定値であること）を記録する。
5. 成果物を検査する。`check_cvss_decisions.py --final --strict --report`と`check_5b_clique.py --report`の結果を、`baselines/checker-results.expected.txt`の過去の実行の結果と比べる（コマンドは`baselines/README.md`）。
6. 採点は監査の完了後に、答え合わせファイルと照合して行う。

## SCAの期待値

`sample-vulnerable-app`は、`npm audit`で17件（low 2・moderate 3・high 10・critical 2）になる。lockfileで版を固定しているためで、件数の変化はSCAの手順の退行か、npmの脆弱性データベースの更新（新しい勧告の追加・取り下げ）を意味する。パッケージ名と深刻度の一覧は`baselines/sca-sample-vulnerable-app.expected.txt`にある。`mini-vulnerable-app`はlockfileが無く、解決される版が実行時点で変わるので、件数の期待値を置かない。

## 脆弱な依存の固定について

`sample-vulnerable-app/package-lock.json`は、意図的に脆弱な版（`jsonwebtoken` 8.5.1、`multer` 1.4.4等）を固定している。GitHubのDependabot等が警告を出すのは想定内であり、更新のPRを取り込まない（取り込むと評価の入力が変わる）。
