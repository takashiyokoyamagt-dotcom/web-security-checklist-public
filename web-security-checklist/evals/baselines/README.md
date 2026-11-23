# 基準値（evals/baselines/）

SKILLのスクリプトや規則を変えたときに、結果が意図せず変わっていないかを比べるための基準値を置く。
どれも実測の記録であり、規則ではない。監査を行うエージェントには読ませない（`../README.md`の「監査エージェントに読ませないもの」）。

| ファイル                                 | 内容                                                                                                                                          |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `checker-results.expected.txt`           | 各スクリプトの`--self-test`と、過去のモード3の成果物（mini-smoke-3・run4）に対する`check_cvss_decisions.py`・`check_5b_clique.py`・`check_refs.py`の結果の要約 |
| `sca-sample-vulnerable-app.expected.txt` | `sample-vulnerable-app`の`npm audit`の要約行と、パッケージ名・深刻度の一覧                                                                    |

## checker-results.expected.txt の見方

- `## <検査名>`の行で区切り、その下に各検査の要約の行（`RESULT:`・`NG`・`WARN`の行、自己テストの最終行、`check_5b_clique.py`の終了コード`rc=`）を置く。先頭6行の、`#`と空白で始まる行は説明である（照合から除く）。
- 成果物は、リポジトリの`web-security-checklist-workspace/{mini-smoke-3,run4}/outputs/`にある（`docs/HISTORY.md`の35節・40節）。スキルのディレクトリには入れていない（報告書が大きく、lintの対象が増えるため）。スキルのディレクトリだけを別の場所へ移したときは、この2つの`outputs/`も持っていかないと照合できない。
- 記録したWARN（確定行のrev、文単位の流用、A-5、文体）は、成果物を作った時点の規則で残ったもので、`RESULT: OK`のまま出る。照合では、行が増えた・消えた・`RESULT`が変わった、のどれも差として扱い、意図した変更によるものかを確かめる。
- 自己テストの行（破壊ケースの件数など）は、スクリプトに検査を足すと変わる。意図した差なら、このファイルを更新する。

次をbashで、リポジトリの直下から実行した出力が、先頭6行の、`#`と空白で始まる説明行と、それに続く空行1行を除いた本文と一致する。

```bash
cd web-security-checklist
echo "## docs integrity"
python3 scripts/check_docs_integrity.py 2>&1 | grep -E "^RESULT|^NG|^WARN" | head -5
for s in check_cvss_decisions check_5b_clique check_docs_integrity calculate_cvss fetch_epss_kev make_idmap locate_snippet check_sources check_refs; do
  echo "## $s --self-test"
  python3 scripts/$s.py --self-test 2>&1 | tail -1
done
for r in mini-smoke-3 run4; do
  O=../web-security-checklist-workspace/$r/outputs
  IDMAP=()
  [ "$r" = run4 ] && IDMAP=(--idmap "$O/idmap.json")
  echo "## $r check_cvss_decisions --final --strict --report"
  python3 scripts/check_cvss_decisions.py --final --strict --decisions "$O/cvss-decisions.jsonl" \
    --raw "$O/cvss-raw-output.jsonl" --report "$O/security-audit-report.md" ${IDMAP[@]+"${IDMAP[@]}"} \
    --mapping "$O/temp-id-final-number-mapping.tsv" 2>&1 | grep -E "^RESULT|^NG|WARN" | head -8
  echo "## $r check_5b_clique --report"
  python3 scripts/check_5b_clique.py "$O/5b-pair-table.md" "$O/temp-id-final-number-mapping.tsv" \
    --report "$O/security-audit-report.md" 2>&1 | grep -vE "^WARN: .*対応表に一時IDが無い" | tail -6
  echo "rc=${PIPESTATUS[0]}"
  T=evals/mini-vulnerable-app
  [ "$r" = run4 ] && T=evals/sample-vulnerable-app
  echo "## $r check_refs"
  python3 scripts/check_refs.py --report "$O/security-audit-report.md" --repo "$T" 2>&1 | grep -E "^RESULT|^NG|^参照"
done
```

mini-smoke-3の記録には`idmap.json`が無いので`--idmap`を付けない。`check_refs.py`の対象は、mini-smoke-3が`evals/mini-vulnerable-app`、run4が`evals/sample-vulnerable-app`（どちらも依存を導入していない元のディレクトリ）である。run4の報告書は依存の内部（`verify.js`等）を参照するため、「未解決」のWARNがパスごとに出る（件数は「参照」の行の「未解決」に出るので、WARNの行は照合から除いている）。`check_5b_clique.py`の「対応表に一時IDが無い」のWARNは、run4で執筆できなかった作業項目（未執筆項目U1。最終番号を持たない）の一時IDを含むペアごとに出る行（42行）で、件数が多いため除いている。

## sca-sample-vulnerable-app.expected.txt の見方

- `bash evals/setup-evals.sh <コピー先>`で`npm ci`したコピーで`npm audit`（`--json`の`vulnerabilities`）を実行した結果である。冒頭に実測の日付とnpm・Node.jsの版を書いた。
- lockfileで版を固定しているので、件数が変わるのは、SCAの手順の退行か、npmの脆弱性データベースの更新（勧告の追加・取り下げ・深刻度の変更）のどちらかである。後者のときは、日付を改めてこのファイルを更新する。
- `scripts/run_sca_scan.sh`が実行する`npm audit --audit-level=high`は、同じ要約行を出す（`--audit-level`は終了コードだけを変える）。
