# 依存関係の脆弱性チェック (SCA: Software Composition Analysis)

依存パッケージに既知の脆弱性(CVE)がないかを確認する手順です。`scripts/run_sca_scan.sh` が
スタックを検出して該当コマンドを実行します。手動で行う場合は以下を使用してください。

## 言語別コマンド

| スタック | 検出ファイル | コマンド |
| --- | --- | --- |
| Node.js | `package.json` / `package-lock.json` | `npm audit --audit-level=high` (yarnなら `yarn audit`, pnpmなら `pnpm audit`) |
| Python | `requirements.txt` / `pyproject.toml` | `pip-audit` （未インストールなら `pip install pip-audit`） |
| Java | `pom.xml` / `build.gradle` | `mvn org.owasp:dependency-check-maven:check` または OWASP Dependency-Check CLI |
| 汎用（複数言語対応） | - | [OSV-Scanner](https://github.com/google/osv-scanner) `osv-scanner -r .` |

## 実行できない/ツールが無い場合
- Node.jsでlockfileが無い場合、`scripts/run_sca_scan.sh`は対象を変更せず一時ディレクトリで`package.json`からlockfileを生成して監査する（版が実際の導入版と異なりうるため、報告に「lockfile無し・一時生成lockfileで監査」と明記する）。手動なら`npm install --package-lock-only`を一時ディレクトリで実行する。
- ネットワークアクセスやツールのインストールができない環境では、`package-lock.json`/`requirements.txt`等の
  バージョンを目視し、既知の大きな脆弱性が報告されているメジャーバージョンでないか（利用者の記憶やCHANGELOG等）を確認する。
- 実行できなかった場合は監査結果として「SCAスキャン未実施（理由: ○○）」と正直に報告し、
  ユーザーに手動実行を促す。存在しない結果を作り上げない。

## 評価基準
- SCA由来の指摘も他のカテゴリの指摘と同様、重大度はArbiterが自己判断せず、`references/cvss/cvss-scoring.md`「CVSSスコアの
  算定」節（判定基準・スコアの算出）に従って`scripts/calculate_cvss.py`で算定したCVSS v3.1の定量的区分を正とする（v4.0も
  併記する）。スキャンツールが報告するCVE自体のCritical/High等のseverityは、CVSSベクター判定時の
  参考情報（既に公表されているCVSSベクターがあればその値を出発点にしてよい）として扱い、
  そのまま指摘の重大度として転記しない。
- 直接依存だけでなく間接依存（transitive dependency）で検出された場合も報告するが、
  「直接 or 間接」を明記し、アップデート方法（直接依存側のバージョンアップで解決するか等）を添える。
- 既に世の中でexploitが公開されている脆弱性は最優先で扱う。

## EPSS・KEV（補助情報）

- 取得は`scripts/run_sca_scan.sh`が自動で行う。スキャン後に出力の脆弱性IDを`scripts/fetch_epss_kev.py`へ渡し、末尾の「== EPSS/KEV ==」節に要約・取得状況の1行・結果JSONの場所を出す（`SCA_EPSS_KEV=0`で省略。`SCA_EPSS_KEV_OUT`で保存先を指定でき、絶対パスを推奨。対象ディレクトリの中は不可）。
- 送るのはID（CVE・GHSA等）だけで、対象のコードは送らない。接続先は api.osv.dev（GHSA等→CVE）・api.first.org（EPSS）・www.cisa.gov（KEVカタログ）である。オフライン環境や、監査対象の情報を外部に問い合わせたくない場合は`SCA_EPSS_KEV=0`とする。
- 対象はCVEを持つ勧告だけである。CVEが無いもの（JSONの`entries[].status`が`no_cve`）は「CVEなし（対象外）」と書く。
- 「スキャン出力に脆弱性IDなし」は、標準出力にIDが無かったという事実だけを表す。スキャンが失敗した、またはツールが脆弱性IDを標準出力に出さない（Dependency-Check等）ときは「未取得（理由）」とし、IDを確認できれば`python3 -I scripts/fetch_epss_kev.py --id <ID> --out <JSON>`で取得する（出力先は対象ディレクトリの外にする）。
- CVSSの重大度は変えない補助情報である。優先度の判断には使ってよい（KEV掲載は優先対応）が、重大度の帯は変えない。
- 値は必ず取得日時（`retrieved_at`）・EPSSの基準日（`epss_date`／`sources.epss.score_date`）・KEVカタログ版（`sources.kev.catalog_version`）・参照URL（`urls`）とセットで書く（EPSSは日々変わる）。
- 取得できなかったとき（「EPSS/KEV: 未取得（理由: …）」、`entries[].status`が`error`（OSVの失敗でCVE不明。`no_cve`とは別）、`epss_status`が`error`、`sources.kev.error`あり、時間切れ・接続失敗による打ち切り、`sources.id_limit`の件数上限による除外）とSCA未実施のときは「未取得（理由）」と書き、推測で埋めない。「一部未取得」なら取得できた値だけを書き、残りを未取得とする。理由が「CA証明書」なら、PythonのCA証明書を設定して再実行する（macOSのpython.org版は`Install Certificates.command`を実行する）。
- 1指摘に複数の勧告があるときは、指摘側には「最大EPSS」と「KEV掲載数」を書き、勧告ごとの一覧は報告書の8節に置く。8節にはEPSSの出典表記`EPSS data from FIRST`を付ける。
- 結果JSONは報告書と同じ保存先へ複製する。

## 到達可能性（採点を下げる条件）

脆弱性が「この使い方では悪用条件を満たさない」（到達しない・再現しない）として採点を下げる（AC:H・v4はAT:P、A:L、影響N等）ときは、次を満たす。

- 到達の根拠: 脆弱な関数・機能をアプリが呼ぶ経路を`file:line`で示す。呼ばれないと言うなら、grepの式と0件に加え、フレームワークによる暗黙の呼出しや動的読込も確認した旨を書く。
- 非再現を根拠にするときは、`references/core/agent-roles.md`「非再現を根拠にした評価の引き下げ」の3条件（アプリが実際に読む入力へ送る／陽性対照かコード根拠で到達を確認する／再現記録を残す）を全て満たす。パーサ系の脆弱性は、フレームワークが全リクエストで入力を解析する場合（Express 4のクエリ文字列等）はどのルートでも到達しうる。ただし到達（どのルートでも解析される）と影響の観測は別で、観測できる経路で確認していない非再現は検証に当たらない。陽性対照（同じ経路で入力の内容・大きさを変えると応答や処理時間が変わること）を取り、アプリが値を読み処理するルートでも試す。
- 満たさない場合は「未検証」とし、勧告のベクターを維持する（`references/cvss/cvss-scoring.md`基準表「脆弱な依存パッケージ」）。

<!--split:add-->
## 根本原因ごとの指摘の単位
同じマニフェスト（`package.json`等）を指す依存関係の指摘は、根本原因ごとに1指摘とする。根本原因は (i) 個別の既知脆弱性（勧告・CVEのある版。同じパッケージの複数の勧告は1指摘にまとめてよい）、(ii) 古い・保守終了の依存（勧告の無い古さ・EOL・未使用の依存）、(iii) 供給網（可変参照〔git・URL・`latest`・広い範囲指定〕、lockfile・integrityの欠如、未宣言の依存の自動導入）の3つで、同じ根本原因を複数の指摘に分けず、同じパッケージの同じ問題を2つの指摘で数えない（勧告のある版は(i)で扱い、(ii)には勧告の無い古さだけを残す）。この単位は、依存関係のカテゴリのRed Teamが指摘を出す時点で揃える（Red Teamへの指示に含める）。手順4・5の統合は従来どおり5b・5cの機械判定だけで行い、この規則で指摘を手で統合しない。共有CWEがあれば5bで判定し（5b補足・5b補足2に従う）、観点が違って統合されないまま同じ行を指すもの（例: 同じ`package.json`の行を(i)と(iii)が指す）は、`references/pipeline/finding-arbiter.md`5b補足4の「同一箇所」の相互参照にする（参考表に記し、双方の「修正内容の解説」に相手の最終番号と、この指摘に固有の欠陥を1文で書く）。CVSSの前提条件（開発依存のみ・lockfile等の既存の防御）は`references/cvss/cvss-scoring.md`「前提条件の確認」で確かめる。
<!--split:end-->

## サプライチェーン攻撃対策
- lockfile（`package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`、`poetry.lock`、`Pipfile.lock`等）を
  必ずリポジトリにコミットし、意図しないバージョン変更・改ざんをレビュー・CIで検知できるようにする。
- 新規依存追加時、パッケージ名が有名パッケージに酷似したtyposquatting（例: `reqeusts`,
  `python3-dateutil`もどき等）でないか、公開元・ダウンロード数・GitHubリポジトリの実在を確認する。
- 可能であればビルド成果物のSBOM (Software Bill of Materials、CycloneDXやSPDX形式)を生成し、
  依存関係の全体像を追跡可能にする。

## 除外・受容の扱い
- 修正版が存在しない、または業務影響が大きく即時対応できない脆弱性がある場合、
  「受容リスクとして記録し、監視を継続する」という選択肢があることをレポートに明記してよい。
  ただし黙って除外せず、必ずレポートに記載すること。
