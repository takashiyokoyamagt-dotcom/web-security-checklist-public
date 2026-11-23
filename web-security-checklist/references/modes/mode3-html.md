<!--split:add-->
# モード3 手順6（HTML Artifact）
本ファイルはSKILL.mdから移設した部分。本文中の「モード2手順N」「5a〜5f」「モード3手順N」「〜節」等の参照先のファイルは、SKILL.mdのモード2・モード3の必読一覧とゲート一覧（ファイルごとの担当）で引く。
GATE-TOKEN:G6-a54483
本ファイルはゲートG6で`Read`するファイル。ゲートを通らず手順6を進めていた場合は停止し、読み直して既存成果物を点検する（この停止文のみモード3に適用。本文規則はモード2でも有効）
記入補足: 2節の項目には委任実績（`delegation-log.jsonl`から役割別に転記。agent-roles.md）も含める。
<!--split:end-->
6. 同じ内容でHTML Artifactも作成する。モード3は`scripts/render_html.py`（`references/core/handoff-files.md`5節。シェル`assets/templates/report_shell.html`が以下を実装済み）で作り、手で書かない。**Artifactツールで公開する前に、必ず `artifact-design` スキルを
   読み込み、その作法（テーマ対応・favicon等）に従うこと**。`report_template.md`をそのままHTML化する
   のではなく、重大度別サマリー・カテゴリ別ダッシュボード・指摘一覧・リスク分析が見やすい形に
   再構成する。**重大度別サマリーの件数は、Markdownレポートと同じ数値を手書きで転記するのではなく、
   埋め込んだ指摘データ配列（`FINDINGS`等）から`.filter(f=>f.cvssV3Severity==='Critical').length`
   のように実行時に動的算出する**（Markdown側で数え直した後の修正が、転記漏れでHTML側にだけ反映され
   ないという事態を防ぐため。重大度はCVSS v3.1の区分が正のため、各指摘オブジェクトの重大度
   フィールドは`cvssV3Severity`のような名前にし、`severity`という汎用名で別の意味の値
   （Red/Blue Teamの暫定判定等）と混同しないようにする）。

   **見た目の方針（日本の大手企業間の取引でも提出できる、厳格な監査報告書であること）**: SaaS
   ダッシュボード的な華美な装飾（紫・藍系の強いアクセントカラー、カードの`box-shadow`による
   浮き上がり演出、大きな角丸、絵文字）は使わない。代わりに以下を徹底する:
   - **配色**: ブランド/見出し用のアクセントカラー（`--accent`）はネイビー1系統のみとする。
     重大度・判定を示す状態色（Critical/High/Medium/Low/PLAUSIBLE/CONFIRMED）は可読性のため
     慣例的な色分け（赤系・橙系・黄土系・紺系・灰系・緑系）を許容するが、**紫・藍系の強い色は
     状態色にも一切使わない**（PLAUSIBLE等の判定色を無彩色寄りのグレーにするのはこのため）。
     値の例は`assets/templates/report_shell.html`の`:root`（ライト/ダーク両方を定義済み。そのまま使ってよい）。
     重大度は色だけで区別せず、バッジに文言（Critical/High/Medium/Low）も必ず併記する。
     未使用の指摘（`cvss-decisions.jsonl`の`unused`）は、判定の隣に無彩色の文言バッジ「未使用・実質問題なし」を併記し、指摘データにも`unused`を持たせる。並びはMarkdownと同じ（同じ帯では未使用が末尾）。
   - **装飾を排したレイアウト**: `box-shadow`によるカードの浮き上がりは使わず、`1px solid var(--line-soft)`
     の罫線で区画するフラットなレイアウトにする。角丸は使う場合も2〜4px程度に抑える。
   - **構成をMarkdown版（`report_template.md`）と一致させる**: 冒頭に表紙情報（対象システム／
     報告書番号／作成日／実施体制／機密区分「社外秘」を罫線表で表示）・改訂履歴表・目次（各節への
     ページ内リンク）を置き、以降はMarkdown版と同じ章立て番号（1. エグゼクティブサマリー、
     2. 実施メタデータ、3. カテゴリ別実施状況、4. 指摘サマリー、5. 指摘詳細、6. リスク分析、
     7. 要確認事項、…）で構成する。「2. 実施メタデータ」（解析日時・使用モデル・エージェント
     起動数・修正案監査レビューの厳格度・CVSS環境メトリクスの反映有無等）と「4. 指摘サマリー」
     （重大度・CVSS v3.1/v4.0スコア・ファイル・概要の一覧表。クリックで5節の該当指摘へスクロール）
     は省略しない。
   - **指摘詳細の表示**: 各指摘は5dで生成した4フィールド（わかりやすい解説／技術的詳細解説／
     該当コードの問題点／修正内容の解説）と5eの監査レビュー結果、5fのCVSSスコアを、
     `report_template.md`の5節と同じ小見出し（概要／わかりやすい解説／技術的詳細解説／該当コード／
     該当コードの問題点／攻撃シナリオ／推奨される修正／修正内容の解説／修正後に残るリスクと別経路（あれば）／修正案の監査レビュー）に
     加え、重大度バッジの隣にCVSS v3.1/v4.0スコアのバッジ（例:「CVSS3.1: 9.8」「CVSS4.0: 9.3」）を
     漏れなく表示する。フィールド数が多く縦に長くなるため、`<details>`要素等で「わかりやすい解説」
     まではデフォルト展開・それ以降を折りたたみにする、といった判断は`artifact-design`スキルの
     作法に従って良いが、**折りたたむ場合も初期状態で概要とわかりやすい解説は必ず見える状態にする**
     （非技術者の読者が開かずに要点を把握できるようにするため）。
   - **設計意図の新ブロック**: 5節の各指摘に、修正内容の解説の後ろへ見出し「元の処理の意図と、修正による挙動の変化」を、代替案があれば続けて「設計方針に従えない場合の代替案」（表ごと）を、`report_template.md`と同じ語で表示する。「修正後に残るリスクと別経路」があれば、修正内容の解説の直後（「元の処理の意図と、修正による挙動の変化」の前）に同じ見出しで表示する。
   - **CVSS整合性確認の表示**: 6節冒頭に`cvss_consistency_note`（CVSS整合性確認）を表示する。
   - **リスク分析（6節）の表示**: `report_template.md`6節と同じ内容（CVSS v3.1/v4.0のメトリクスごとの
     判定根拠、ベクター文字列、環境メトリクスを反映した場合はその内訳）を指摘ごとに表示する。
     `report_template.md`6節同様、**5→6・6→5の双方向にページ内リンクを設ける**: 5節の各指摘カードに
     この6節該当箇所へのリンク（例:「リスク分析を見る」）を、6節の各リスク分析ブロックにも
     対応する5節の指摘へ戻るリンク（例:「5.{{n}}の指摘に戻る」）を、それぞれ設ける。6節側は
     `<details>`要素等で初期状態は折りたたんでおいてよい（メトリクス単位の詳細はスコア・重大度を
     見て興味を持った読者だけが開けばよい情報のため。5節側のCVSSスコアバッジは折りたたまず常に
     表示する）。
   - **EPSS・KEVの表示**: SCA由来でCVEを持つ指摘のカードと8節に、`report_template.md`と同じEPSS・KEV・取得日時・根拠URLを表示する。KEV掲載は文言つきのバッジ「KEV掲載」とし、色だけで区別しない（色は既存の状態色の変数（`--critical`系等）を流用し、紫・藍系は使わない）。根拠URLは新規タブで開くリンク（`target="_blank" rel="noopener noreferrer"`）にする。値は`epss-kev.json`から埋め込み（動的算出の対象外）、ページからはCDN許可リスト（`artifact-design`スキル）以外へ通信しない。

   指摘一覧には、**「統合 / IPA / OWASP ASVS / OWASP Cheat Sheet / CWE Top25 / SCA」を切り替える
   タブまたはフィルタボタン**を設け、選択した出典の`sources`タグを持つ指摘だけを表示する
   （新規のArtifact発行は不要）。表示/非表示の切替は`element.hidden`のトグルで実装すること
   （Artifact基盤のリセットCSSが`[hidden]{display:none!important}`を強制するため、
   `style.display`の直接操作は避ける）。該当指摘が0件の出典タブは非表示にするか「該当なし」と表示する
   （0件判定は、手順3で集約したCONFIRMED・PLAUSIBLE指摘のうち、当該出典の`type`を持つ
   `sources`エントリが1件以上あるかで判定する）。
   Artifactツールが利用できない、または拒否された場合は、手順5（`references/modes/mode3-report.md`）のMarkdownレポート（保存できていれば）
   またはテキスト応答のみで完了とし、その旨をユーザーに一言伝える。

   **ローカル保存するHTMLの文字コード**: ディスクに保存するHTML（成果物の置き場所を含む）は先頭に`<!doctype html>`と`<meta charset="utf-8">`を付ける。無いとSafari等で日本語が文字化けする。Artifact公開用には付けない（土台はArtifact側が付ける）。

   **公開・保存前の秘密値の検査**: HTML（ローカル保存用とArtifact公開用）とArtifactに渡すファイルを作業ディレクトリに書いた後、Artifactの公開の前に、手順5（`references/modes/mode3-report.md`「秘密値の漏れの検査」）の`scripts/check_secret_leak.py`を、`--outputs <作業ディレクトリ> --outputs <成果物の保存先>`と2回指定して実行し（保存先への複製の前のファイルは作業ディレクトリ、複製後のファイルは保存先で走査する。保存前のHTMLも作業ディレクトリに置いて走査する）、`RESULT: OK`を確かめてから公開する。手順7の後にも同じ検査を再実行する。埋め込む指摘データ（`FINDINGS`等）はマスク後の値から作る。

   **「推奨される修正」のdiff色分け表示**: `fix_suggestion`はunified diff形式（`-`/`+`行）で
   書かれている前提のため、無色の`<pre>`でそのまま表示せず、行頭の`-`/`+`を解析して削除行・
   追加行を色分けする。新しいCSS変数は増やさず、既存の`--confirmed-bg`/`--confirmed-text`
   （追加行）・`--critical-bg`/`--critical`（削除行）を再利用する。実装例:
   ```js
   function diffHTML(text){
     return text.split('\n').map(line=>{
       if(line.startsWith('+') && !line.startsWith('+++')) return `<div class="diff-add">${esc(line)}</div>`;
       if(line.startsWith('-') && !line.startsWith('---')) return `<div class="diff-del">${esc(line)}</div>`;
       return `<div class="diff-ctx">${esc(line)}</div>`;
     }).join('');
   }
   // 呼び出し側: <pre class="fix">${diffHTML(f.fix)}</pre>（従来の${esc(f.fix)}から置き換える）
   ```
   ```css
   .diff-add{background:var(--confirmed-bg); color:var(--confirmed-text);}
   .diff-del{background:var(--critical-bg); color:var(--critical); text-decoration:line-through; opacity:.85;}
   .diff-ctx{opacity:.75;}
   ```
   （クラス名・細部の見た目は`artifact-design`スキルの作法に従って調整してよいが、既存の
   CSS変数を再利用する方針とdiff行の色分けという機能自体は必ず実装する）

   **`</script>`エスケープ（既知の不具合への対策）**: `vulnerable_code`・`fix_suggestion`・
   `failure_scenario`等、実コードや攻撃ペイロード例をJS文字列としてArtifactの`<script>`
   ブロックに埋め込む際、文字列内に`</script`という並びが含まれる場合（例: XSSの攻撃例として
   `<script>...</script>`をそのまま引用した場合）は、**必ず`<\/script`のようにスラッシュの前に
   バックスラッシュを入れてエスケープする**こと。ブラウザのHTMLパーサーは、JS文字列の中身かどうかに
   関わらず`</script>`という文字並びを見つけた時点でスクリプトブロックを終了させてしまうため、
   エスケープを怠ると以降のスクリプト（残りの指摘データ・フィルタ機能等）が実行されずページ上に
   テキストとしてそのまま表示される不具合が実際に発生した経緯がある（`docs/HISTORY.md`参照）。
