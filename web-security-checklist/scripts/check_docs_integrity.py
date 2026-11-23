#!/usr/bin/env python3
"""スキル文書（SKILL.md・references/**/*.md・assets/*.md・adapters/**/*.md）の整合性検査（標準ライブラリのみ）。
失われたリポジトリ外の verify_phase2.py（HEAD 1a4d17d 基準）のうち、再現できる検査の後継。
[1] ファイル: サイズの下限・上限（SIZE_RANGE。表に無いファイルは DEFAULT_SIZE_RANGE、
    表に無い references/assets のファイルはWARN）、コードフェンス(```)の数が偶数、BOM・CRLFはWARN。
[2] G0読込予算（SKILL.md＋必読5本の合計が G0_BUDGET 以内）。
[3] split:add/split:end の数・入れ子・単独行・表記違い、追加ブロックの行数上限（マーカー行を
    含むファイル内の合計。ADD_LINE_CAPS）、追加ブロックへの本文の複製。
[4] SKILL.md の frontmatter（---・name・description・閉じ---）。
[5] ゲート: SKILL.md の G0・モード2必読・ゲート一覧（GATE_FILES と照合）、mode3-full-audit.md の
    gate マーカーの集合・順序・mode3-only・files（GATE_FILES と照合）・キー文、GATE-TOKEN 行の
    位置・形式・一意性・漏洩・総数（WARN）、ゲートファイル冒頭のキー文。条件付きゲート
    （CONDITIONAL_GATES。G2）は、マーカーの conditional、SKILL.md の「条件付き」と最終応答の
    報告文、「G2: 設計書なし」の記録指示、モード2の条件付き必読(d)も照合する。
[6] 参照: references/・assets/・scripts/・docs/・adapters/ で始まるパスの実在（無ければNG）、
    `名前.md` 等の裸のファイル名（見つからなければWARN）。
[7] 原典の版: references/sources/VERSIONS.json の構造（scripts/check_sources.py の validate_versions を読み込んで
    検査する。二重管理しない）、確認日が根拠の本文の「確認日」と一致すること（confirmed_basis=human）、採用版の文字列
    （adopted_text）が根拠のreferencesの本文にあること、CWE Top 25の順位（adopted_detail.ranking）が
    references/sources/cwe-top25.md の表の順と一致すること、Cheat Sheetの参照名（adopted_detail.referenced）が
    references/sources/owasp-cheatsheets.md の表と一致すること、affects のファイルの実在。
NG/WARNの行は検査ごとに一意な [コード] で始まる（自己テストはコードで照合する）。
再現しない検査: 分割前の本文との照合（範囲の被覆・本文＝範囲連結＋EDIT）。EDIT一覧が失われ、
その後の改訂で本文が変わっているため（docs/HISTORY.md 39節）。本文の差し替え・部分的な削除は
検出しない（サイズの下限とフェンスの偶奇で、中身の大きな欠落だけを捉える）。
上限を超える変更をしたら、実測を確かめて表を更新し、HISTORYに記録する。
終了コード 0=OK（WARNのみでも0） / 1=NG。--self-test は現在の文書の一時コピーで、
正常系がOK・破壊ケースがすべて想定のコードで検出されることを確かめる。Python 3.9以上で動く。
"""

from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unicodedata

ADD, END = "<!--split:add-->", "<!--split:end-->"
# サイズの(下限, 上限)(バイト)。2026-10-09の実測から、上限は+4%（最低+300B）を100B単位で
# 切り上げ、下限は約半分（100B単位で切り捨て）。下限は中身の大きな欠落を捉えるためのもの
SIZE_RANGE = {
    # 上下限を再計算（14,552→。S1のG2のポインタ・(d)の末尾の追記を含む。実測+4%を100B単位で切り上げ、下限は約半分）
    "SKILL.md": (7600, 15900),  # 15,277（P6第2弾: 実測+4%を100B単位で切り上げた上限に下げた）
    # 上下限を再計算: BUILDER役割と委任記録のnote/再開の書式を追加。G0に置けないため（7,994→）
    # 再計算: 戻り値のdeviations欄とその転記・OPERATIONS 5節の参照を追加。G0に置けないため（9,513→）
    # 再計算: G3との順序を追加し余裕が28Bになったため。G0に置けないため（10,954→。その後の追記を含む）
    # 上下限を再計算: DESIGN役の行とシェルの許可を追加し余裕が69Bになったため。G0に置けないため（11,571→。HEADの実測）
    # 実測のみ更新: S1-4のBUILDERの追加の読込の行（11,831→。余裕345Bで最低+300Bを満たすため上下限は据え置き）
    # 再計算: run6-followup（D）BUILDERの追加の読込に「統合版に当たらない申告の列挙」を追記。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分（12,055→12,133）。レビュー反映で12,136（上限内のため上下限は据え置き）
    # 再計算: ops-followup（A-5）SYNTH・SCA-SYNTHの役割（表の2行・実行制約と戻り値の項・委任記録の1句）を追加。余裕が足りないため、実測+4%を100B単位で切り上げ、下限は約半分（12,136→14,395）
    # 再計算: ops-followupレビュー反映（SYNTH・SCA-SYNTHを実物の指示書に合わせて役割ごとの項に分け、P7-AUDITの行・逐次起動の記録の1句を追加。14,395→17,280。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    "references/core/agent-roles.md": (8600, 18000),  # 17,280
    "references/core/handoff-files.md": (3400, 8000),  # P1仮組込み
    "references/modes/category-map.md": (1300, 3000),  # 2,608
    "references/core/common-principles.md": (3900, 8200),  # 7,838
    # 実測のみ更新: run6-followup（B）判定記録のtmpの定義を追記（28,463→28,663。上限内のため上下限は据え置き）
    # 再計算: finding-precision（改善2）「前提条件の確認」の節（追加ブロック）と判定記録のprem
    # の1文を追記（28,698→32,190。上限を超えたため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: finding-precisionレビュー反映（naの定義・(d)とv3.1のACの関係・該当行の「前提(x)」に
    # よるWARNの抑止、既存の原則「AC/AT」への2行。32,190→33,386。余裕が300B未満になったため、
    # 実測+4%を100B単位で切り上げ、下限は約半分）
    "references/cvss/cvss-scoring.md": (16600, 34800),  # 33,386
    "references/cvss/cvss.md": (1800, 4100),  # 3,770
    # 上下限を再計算: 基準年度版を明記し、表をTop 25（公式の全25件）と補助に分けた（3,162→）
    "references/sources/cwe-top25.md": (2400, 5300),  # 4,932
    # P4: database.mdを7ファイルに分割（実測+4%（最低+300B）を100B単位で切り上げ、下限は約半分）
    "references/checklists/database/_index.md": (1500, 3400),  # 3,064
    "references/checklists/database/sqli.md": (1200, 2800),  # 2,473
    "references/checklists/database/access.md": (1100, 2600),  # 2,238
    "references/checklists/database/data-protection.md": (1400, 3200),  # 2,888
    "references/checklists/database/network-tls.md": (1200, 2700),  # 2,376
    "references/checklists/database/logging.md": (1100, 2500),  # 2,154
    # P4: 確認依頼に既定のアカウント（DB-OPS-10）とパッチ（DB-OPS-11）を追加（利用者の承認 2026-11-17。同じ規則で再計算）
    "references/checklists/database/ops-requests.md": (1600, 3500),  # 3,104
    # 上下限を再計算: EPSS・KEVの節を追加。G0に置けないため（5,474→）
    # 実測のみ更新（8,094→。上限内のため上下限は据え置き）
    # 再計算: finding-precision（改善3）「根本原因ごとの指摘の単位」の節（追加ブロック）を追記
    # （8,170→9,823。上限を超えたため、実測+4%を100B単位で切り上げ、下限は約半分）
    "references/checklists/dependency-sca.md": (4900, 10300),  # 9,823
    # 新規: ゲートG2（設計書の候補があるときだけ読む。オーケストレータ用）。実測+4%（最低+300B）を100B単位で切り上げ
    "references/design/design-intent.md": (2400, 5300),  # 4,920
    # 新規: Red/Blue用の新項目の定義（design-intentから分割。ゲート対象外）。同じ算定
    # 再計算: compat_classの③の境界の1行を追加（S1-4レビュー反映。4,240→4,397。余裕が300B未満になったため、実測+300B（4%は300B未満）を100B単位で切り上げ。下限は約半分で据え置き）
    # 再計算: fix_suggestionのdiffとalternativesの案の対応・同率の最高・暫定のdiffの扱いを追記（4,397→5,568。実測+300B（4%は300B未満）を100B単位で切り上げ、下限は約半分）
    "references/design/design-fields.md": (2700, 5900),  # 5,568
    # 新規: 5eの専用監査エージェント用の追加項目（S1-2。ゲート対象外）。同じ算定
    # 再計算: design_conflict_checkの(c)と判定への反映に、表の案への対応・暫定案の「要検討」扱いを追記（7,071→7,982。実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: 判定への反映に、個別指摘の5eの最大3ラウンド・再修正の範囲（機構を足さない）・第3ラウンドの制限・3ラウンドで解消しないときの開示と「要再検討（残存）」を追記（7,982→9,396→9,831。実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: 実測の更新（判定への反映の追記の確定後。HEADの実測7,982→10,183。旧コメントの9,831は更新漏れ。実測+4%を100B単位で切り上げ、下限は約半分）
    "references/design/design-audit.md": (5000, 10600),  # 10,183
    # 新規: 統合修正版・5cの合成diffでの元の挙動の保持（S1-4。BUILDER・統合版の独立監査・Arbiterが読む。ゲート対象外）。同じ算定
    # 再計算: S1-4レビュー反映（同時適用の確認・統合で生じる変化・独立監査の3フィールド等。3,265→5,519。実測+300B（4%は300B未満）を100B単位で切り上げ、下限は約半分）
    # 再計算: 統合時の変化を申告へ反映してから独立監査へ渡す順序・両方の申告の併記・申告のみの訂正の再監査を追記（5,519→6,840。実測+300B（4%は300B未満）を100B単位で切り上げ、下限は約半分）
    # 再計算: run6-followup（D）個別案の申告のうち統合版に当たらない記述の列挙と反映・申告の置き場所・Arbiterによるコード欠陥の直接修正と再監査を追記（HEADの実測7,031→8,528。旧コメントの6,840は更新漏れ。上限を超えたため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: run6-followupレビュー反映（NOTES.mdの見出し名の固定・反映の時点・区分①〜③の見直しの基準・Arbiterが直す先と更新するファイル。8,528→8,863。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    "references/design/design-integrated.md": (4400, 9300),  # 8,863
    # 上下限を再計算: 5d補足（未執筆項目の規則）を追加。G0に置けないため（30,221→）
    # 再計算: 5c補足2（統合修正版の規則）を追加。G0に置けないため（32,718→）
    # 再計算: 5d補足（文体）を追加。G0に置けないため（34,768→）
    # 再計算: 5c(a)②のTop 25の表と5c補足の@@の条件を明記。G0に置けないため（35,291→。その後の追記を含む）
    # 再計算: 5eに専用監査エージェントへの申告項目・design-audit.mdの受け渡し・Arbiterの引き継ぎ規則の追記（S1-2。HEADの実測36,572→。実測+4%を100B単位で切り上げ）
    # 再計算: 5dにS1-3の1段落（設計意図の新項目をWriterへ最終版で渡す。37,302→。実測+4%を100B単位で切り上げ、下限は約半分）
    # 実測のみ更新: S1-3レビュー反映（5eとの順序・文体・最終判定の1行。37,687→。上限内のため上下限は据え置き）
    # 実測のみ更新: S1-4の統合修正版・5cの合成diffのポインタ段落（38,405→。余裕359Bで最低+300Bを満たすため上下限は据え置き）
    # 再計算: S1-4レビュー反映（ポインタ段落の拡張と5eの標準セルフチェックのポインタ1行。38,841→39,163。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: 5b補足3（統合した群の新項目の統合規則）を追加（HEADの実測39,333→40,785。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: 実測の更新（5b補足3の確定後。HEADの実測39,333→41,202。旧コメントの40,785は更新漏れ。実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: run6-followup（A・B・C・D）make_idmap.pyによる対応表の生成・tmpの定義・Writerへの連鎖切断の相手の渡し方・5c補足2③の再監査の整合を追記（41,202→43,110。上限を超えたため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 実測のみ更新: run6-followupレビュー反映（make_idmap.pyの入力の形・WRITER起動前の検算・tmpのハイフン・5c補足2③の整合。43,110→43,879。上限内のため上下限は据え置き）
    # 再計算: ops-followup（A-2・A-5）5d補足（該当コードの行番号。locate_snippet.py）と5c補足3（連結成分が大きいときのSYNTH委任）を追記（43,879→46,244。上限を超えたため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 実測のみ更新: ops-followupレビュー反映（5c補足3の目安と定義・5d補足のパケット形式。46,244→46,652。上限内のため上下限は据え置き）
    # 再計算: finding-precision（改善1・3）5d補足（本文の参照の照合。check_refs.py）と5b補足4
    # （同一箇所の指摘の相互参照）を追記（46,652→50,268。上限を超えたため、実測+4%を100B単位で
    # 切り上げ、下限は約半分）
    # 実測のみ更新: finding-precisionレビュー反映（5b補足4の対象の機械的な列挙〔--findings〕と
    # 相手が多いときの書き方、5d補足のモード2の対象・--extra-root。50,268→51,834。余裕466Bで
    # 最低+300Bを満たすため上下限は据え置き）
    # P6第2弾: 5d〜5fをfinding-final.mdへ分けた（51,652→32,603）。上限は実測+4%を100B単位で切り上げ、下限は据え置き
    "references/pipeline/finding-arbiter.md": (25100, 34000),  # 32,603
    # P6第2弾で新設（finding-arbiter.mdの5d〜5f）。実測+4%を100B単位で切り上げ、下限は約半分
    "references/pipeline/finding-final.md": (9800, 20600),  # 19,728
    "references/pipeline/finding-pipeline.md": (8000, 15800),  # 15,157（P6第2弾。実測+4%）
    "references/pipeline/fix-audit-strictness.md": (3200, 6800),  # 6,405
    "references/sources/ipa-secure-website.md": (2000, 4500),  # 4,182
    # 実測のみ更新: EPSS・KEVの表を使う条件を1行追加（8,638→。上限内のため上下限は据え置き）
    # 再計算: A・B（原典の最新版・確認日の確認）の手順1への1文を追加。余裕が足りないため、実測+4%を100B単位で切り上げ、下限は約半分（8,796→9,019）
    "references/modes/mode2-audit-review.md": (4500, 9400),  # 9,019
    # 上下限を再計算: 出典別IPAの2章のグループを追加。G0に置けないため（6,266→）
    # 再計算: S1-3の新項目の転記の段落を追加（6,341→。同じ算定）
    # 実測のみ更新: S1-3レビュー反映（段落後の空行。6,868→。上限内のため上下限は据え置き）
    # 再計算: 手順7の詳細の列挙と設計方針の新項目に「修正後に残るリスクと別経路」を、末尾に手順7の後の秘密値の検査（scripts/check_secret_leak.py）の導線を追記（HEADの実測6,869→7,345。上限を超えたため、実測+300B（4%は300B未満）を100B単位で切り上げ、下限は約半分）
    "references/modes/mode3-by-source.md": (3600, 8100),  # 7,787（P3でパスが長くなった。実測+300Bを100B単位で切り上げ）
    # 実測のみ更新（16,901→。上限内のため上下限は据え置き）
    # 上下限を再計算: ゲートG2（設計書の探索の条件付き読込）の記述を追加。G0に置けないため（17,068→）
    # 実測のみ更新: 手順0に原典の確認日の確認のポインタ1文（81B）を追加（18,127→18,208。上限内のため上下限は据え置き）
    "references/modes/mode3-full-audit.md": (9000, 18100),  # 17,345（P6第2弾。実測+4%）
    # 上下限を再計算: EPSS・KEVの表示を追加。G0に置けないため（12,046→）
    # 再計算: S1-3の新ブロックのHTML対応（5節の小見出しの列挙に2ブロック名を追記。13,009→。実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: 公開・保存前の秘密値の検査（scripts/check_secret_leak.py）の段落を追加（13,336→13,717。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 実測のみ更新: 5節の小見出しの列挙と新ブロックの段落に「修正後に残るリスクと別経路」を追記（13,717→13,975。余裕325Bで最低+300Bを満たすため上下限は据え置き）
    # 再計算: 公開・保存前の秘密値の検査の実行の時点と範囲（--outputsの2回指定で作業ディレクトリと保存先を走査）を明確化（HEADの実測13,336→14,398。上限を超えたため、実測+4%を100B単位で切り上げ、下限は約半分）
    "references/modes/mode3-html.md": (7100, 15000),  # 14,398
    # 上下限を再計算: 手順5にEPSS・KEVの照合を追加。G0に置けないため（9,639→）
    # 再計算: 残すWARNの記録先を追加。G0に置けないため（10,209→。その後の追記を含む）
    # 再計算: S1-3の新項目の記載の段落を追加（10,522→。同じ算定）
    # 再計算: S1-3レビュー反映（5e確定後への統一・指示文の行名と転記元・衝突あり/なしの文言・最終判定の注記。11,594→。同じ算定）
    # 再計算: 秘密値の漏れの検査（scripts/check_secret_leak.py）の1行を追加ブロックに追加（12,172→13,067。実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: 設計方針の新項目の記載に「修正後に残るリスクと別経路」への記載を追記（13,067→13,516。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: 秘密値の漏れの検査の対象・実行の時点と範囲（--outputsの2回指定）・結果行の記載先を追記（HEADの実測12,172→14,494。上限を超えたため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: run6-followup（E）EPSS・KEVの状況行の定型を追記（HEADの実測14,494→14,961。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: run6-followupレビュー反映（状況行の種類の列挙を補った。14,961→15,481。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 実測のみ更新: ops-followup（A-5）2節の委任エージェント実績にSYNTH・SCA-SYNTHの行と9節の書き方を追記（15,481→15,741。余裕459Bで最低+300Bを満たすため上下限は据え置き）
    # 再計算: ops-followupレビュー反映（保存ゲートに5c補足3を使った場合の1文。15,741→15,946。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: 2節の「原典の最新版確認」の記入（モード3の終了時のA＋B。規則の本体はsource-versions.md）を追加。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分（15,946→16,576）
    # 実測のみ更新: 第三者レビューの反映（モード2で保存するときの2節の書き方・A〔最新版の確認〕＋B〔確認日の経過〕の定義。16,576→16,804。余裕496Bで最低+300Bを満たすため上下限は据え置き）
    # 再計算: finding-precision（改善1〜3）--require-premの1文・本文の参照の照合（check_refs.py）・
    # 同一箇所の相互言及の検査の段落を追加ブロックに追記（16,804→17,997。上限を超えたため、
    # 実測+4%を100B単位で切り上げ、下限は約半分）
    # 実測のみ更新: finding-precisionレビュー反映（--extra-root・--findingsの1句ずつ。
    # 17,997→18,206。余裕594Bのため上下限は据え置き）
    "references/modes/mode3-report.md": (8900, 19700),  # 18,912（P4で運用の確認依頼を追加）
    "references/sources/owasp-cheatsheets.md": (800, 2000),  # 1,610
    "references/checklists/principles.md": (7200, 15100),  # 14,457
    # 新規: 原典の最新版・確認日の確認の手順（モード3の手順0・手順5とモード2の手順1が指す。ゲート対象外）。実測+4%（最低+300B）を100B単位で切り上げ、下限は約半分（初版7,372→設計変更後8,505）
    # 再計算: 第三者レビューの反映（モード2の2節の書き方・締め切りとBashのタイムアウト・Cheat Sheetの一致の限界・確認日の根拠・要確認。8,505→10,202。上限を超えたため、実測+4%を100B単位で切り上げ、下限は約半分）
    "references/sources/source-versions.md": (5100, 10700),  # 10,202
    # 上下限を再計算: 5c補足2（統合修正版）・5d補足（未執筆項目）の注記を追加（21,416→）
    # 再計算: 文体の注記と9節の運用上の逸脱の注記を追加（22,296→）
    # 再計算: 8節のEPSS・KEVの表と5節の悪用状況の行の注記を追加（22,924→）
    # 再計算: 4節のファイル欄と5節のdiff形式の注記を追加（26,440→。その後の追記を含む）
    # 再計算: S1-3の新項目（2節2行・4節の要約表・5.Nの2行と2ブロック・9/10節の注記。27,365→。同じ算定）
    # 再計算: S1-3レビュー反映（衝突あり/なしの固定文言・互換性の区分の説明・要検討の行と利用者判断事項の説明・1節の注記・最終判定の注記。32,513→。同じ算定）
    # 再計算: 5.Nに「修正後に残るリスクと別経路」のブロックと注記を追加（35,631→37,420。上限を超えたため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 再計算: 実測の更新（5.Nの「修正後に残るリスクと別経路」の追加の確定後。HEADの実測36,354→37,653。旧コメントの37,420は更新漏れ。実測+4%を100B単位で切り上げ、下限は約半分）
    # 実測のみ更新: 2節に「原典の最新版確認」の行を追加（37,653→38,086。余裕1,114Bのため上下限は据え置き）
    # 実測のみ更新: 第三者レビューの反映（2節の行の注記。38,086→38,407。余裕793Bのため上下限は据え置き）
    "assets/templates/report_template.md": (18800, 39200),  # 38,407
    # 上下限を再計算: SCAの3.1・3.2にEPSS・KEVの注記を追加（8,804→。旧コメントの8,702は更新漏れ）
    # 再計算: IPAの2章とCWEの補助の見出しの注記を追加（9,122→）
    # 再計算: S1-3の新項目の行とブロックを追加（9,564→。同じ算定）
    # 再計算: S1-3レビュー反映（互換性の区分・衝突あり/なしの固定文言の注記。11,265→。同じ算定）
    # 再計算: 指摘ブロックに「修正後に残るリスクと別経路」と冒頭の注記の1文を追加（11,629→11,915。余裕が300B未満になったため、実測+4%を100B単位で切り上げ、下限は約半分）
    # 実測を確認: HEADの実測11,629→11,915（コメントどおり。同じ算定で上下限は変わらない）
    "assets/templates/report_template_by_source.md": (5900, 12400),  # 11,915
    # P8・P9: 環境別の雛形（adapters/。Claude Codeのモードは読まない）。2026-11-22の実測+4%（最低+300B）を100B単位で切り上げ、下限は約半分
    "adapters/README.md": (700, 1900),  # 1,517
    "adapters/claude-code/README.md": (200, 900),  # 588
    "adapters/copilot/README.md": (1900, 4200),  # 3,819
    "adapters/copilot/github-com/instructions.md": (2000, 4500),  # 4,193
    "adapters/copilot/vscode/SKILL-copilot.md": (2800, 6100),  # 5,741
    "adapters/gh-aw/README.md": (2000, 4400),  # 4,044
    "adapters/gh-aw/workflows/wsc-full-audit.md": (1900, 4300),  # 3,967
    "adapters/gh-aw/workflows/wsc-pr-review.md": (2100, 4600),  # 4,268
}
DEFAULT_SIZE_RANGE = (0, 20000)  # 表に無いファイル（旧verifyの「他20,000B」）
UNLISTED_OK = "references/lang/"  # 表に無くてもWARNにしない（既定の範囲で足りる）
# G0（モード3の起動時読込）: SKILL.md＋必読5本。上限は旧verifyと同じ
G0_FILES = (
    "SKILL.md",
    "references/modes/mode3-full-audit.md",
    "references/pipeline/finding-pipeline.md",
    "references/pipeline/fix-audit-strictness.md",
    "references/cvss/cvss.md",
    "references/core/common-principles.md",
)
# 66,000→67,800: S1のゲートG2のポインタ（SKILL.md・mode3-full-audit.md・finding-pipeline.mdの
# 3ファイル。変更前の合計は65,601で、G2の追加分は約1,870B）。規則本体はG0外の
# references/design/design-intent.md・design-fields.md に置く。実測67,472+約330Bの余裕。
# 既存の文を縮めて収める案は、規則や理由の欠落を招くため採らない（R0の調査結果）。
G0_BUDGET = 62940  # P7モード2修正（common-principles.md・cvss.md・finding-pipeline.mdの圧縮）後の実測値（旧63,288。その前は65,665）
MODE2_FILES = (
    "references/modes/mode2-audit-review.md",
    "references/pipeline/finding-pipeline.md",
    "references/pipeline/fix-audit-strictness.md",
    "references/cvss/cvss.md",
    "references/core/common-principles.md",
    "references/core/agent-roles.md",
)
# モード2のゲートM4（手順4の前。P6で必読から移した）。SKILL.mdの「遅延ロード（ゲートM4」の行と照合
MODE2_GATE_FILES = (
    "references/pipeline/finding-arbiter.md",
    "references/pipeline/finding-final.md",  # P6第2弾: finding-arbiter.mdの5d〜5fを分けた
    "references/cvss/cvss-scoring.md",
)
MODE2_GATE_KEY = "遅延ロード（ゲートM4"
# ゲートとファイル（マーカーの順。R1はファイルを持たない）。SKILL.mdとgateマーカーの両方と照合
GATE_FILES = {
    "R1": (),
    "G1": ("references/core/agent-roles.md", "references/core/handoff-files.md"),
    "G2": ("references/design/design-intent.md",),  # 条件付き（CONDITIONAL_GATES）
    "G3": (
        "references/pipeline/finding-arbiter.md",
        "references/pipeline/finding-final.md",
        "references/cvss/cvss-scoring.md",
        "references/checklists/principles.md",
        "references/sources/ipa-secure-website.md",
        "references/sources/cwe-top25.md",
        "references/sources/owasp-cheatsheets.md",
        "references/checklists/dependency-sca.md",
    ),
    "G5": ("references/modes/mode3-report.md", "assets/templates/report_template.md"),
    "G6": ("references/modes/mode3-html.md",),
    "G7": ("references/modes/mode3-by-source.md", "assets/templates/report_template_by_source.md"),
}
GATE_ORDER = tuple(GATE_FILES)
# 条件付きゲート: 条件を満たしたとき（設計書が見つかったとき）だけ読む。満たさなければ未読でよく、
# 「G2: 設計書なし」と記録する。マーカーに conditional を付ける
CONDITIONAL_GATES = ("G2",)
NONE_PHRASE = (
    "G2: 設計書なし（探索:"  # 記録は「G2: 設計書なし（探索: <検索>、候補0件）」の形
)
FILE_GATES = GATE_ORDER[1:]  # SKILL.mdにファイル一覧を持つゲート
GATE_DOC = "references/modes/mode3-full-audit.md"
# 追加ブロックの行数上限（マーカー行を含むファイル内の合計。旧verifyのCAPと同じ数え方）。
# 2026-10-09の実測+4行。表に無いファイルは追加ブロックを持たない（0）
ADD_LINE_CAPS = {
    "SKILL.md": 73,  # 69
    "references/core/agent-roles.md": 9,  # 5
    "references/design/design-intent.md": 9,  # 5
    "references/core/common-principles.md": 8,  # 4（P6: 語の対応表を1行にした。実測+4行）
    # finding-precisionの「前提条件の確認」の追加ブロックで21→27。実測+4行に再計算
    "references/cvss/cvss-scoring.md": 24,  # 20（P6: 語の対応表を1行にした。実測+4行）
    "references/cvss/cvss.md": 9,  # 5（P6。実測+4行）
    # 実測69: finding-precisionの5b補足4・5d補足（本文の参照の照合）で66→69（上限内で据え置き）
    "references/pipeline/finding-arbiter.md": 44,  # 40（P6第2弾: 5d補足・5f等の追加ブロックをfinding-final.mdへ移し、対応表を1行にした。実測+4行。旧70・実測66: 5d補足の追加ブロックで53→56、5c補足2で→58、5d補足（文体）で→59、その後の追記でHEAD時点61、5b補足3で→63、ops-followupで5d補足（該当コードの行番号）と5c補足3により→66。実測+4行に再計算）
    "references/pipeline/finding-pipeline.md": 10,  # 6（P6第2弾: 対応表を1行にした。実測+4行）
    "references/pipeline/fix-audit-strictness.md": 9,  # 5（P6。実測+4行）
    # finding-precisionの「根本原因ごとの指摘の単位」で新設。実測+4行
    "references/checklists/dependency-sca.md": 8,  # 4
    "references/modes/mode2-audit-review.md": 13,  # 9（P6。実測+4行）
    "references/modes/mode3-by-source.md": 10,  # 6（P6。実測+4行）
    "references/modes/mode3-full-audit.md": 35,  # 31（P6第2弾: 対応表を1行にした。実測+4行）
    "references/pipeline/finding-final.md": 36,  # 32（P6第2弾で新設。実測+4行）
    "references/modes/mode3-html.md": 11,  # 7（P6。実測+4行）
    # 実測25: finding-precisionの--require-prem・本文の参照の照合で23→25（上限内で据え置き）
    "references/modes/mode3-report.md": 24,  # 20（P6: 語の対応表を1行にした。実測+4行。旧27: EPSS・KEVの照合で21→22、秘密値の漏れの検査で→23）
}
DEFAULT_ADD_LINE_CAP = 0
DUP_MIN = 20  # 追加ブロック内のこの字数以上の行が本文と同一なら複製
# GATE-TOKEN行を持つファイルとゲート（G3はfinding-arbiterがG3A、finding-finalがG3F、cvss-scoringがG3B）
TOKEN_FILES = {
    "references/core/agent-roles.md": "G1",
    "references/design/design-intent.md": "G2",
    "references/pipeline/finding-arbiter.md": "G3",
    "references/pipeline/finding-final.md": "G3",
    "references/cvss/cvss-scoring.md": "G3",
    "references/modes/mode3-report.md": "G5",
    "references/modes/mode3-html.md": "G6",
    "references/modes/mode3-by-source.md": "G7",
}
GATE_TOKEN_LINES = 14  # references/内でGATE-TOKENを含む行の数（grep -rc の合計）
SKILL_NAME = "web-security-checklist"
TOKEN_RE = re.compile(r"GATE-TOKEN:(G\d)([A-Z]?)-([0-9a-f]{6})")
GATE_RE = re.compile(r"<!--gate:(\S+)((?: \S+)*?)-->")
PATH_RE = re.compile(
    r"(?<![\w./-])((?:references|assets|scripts|docs|adapters)/[\w.-]+(?:/[\w.-]+)*"
    r"\.(?:md|py|sh|txt|json))(?!\w)",
    re.ASCII,
)
BARE_RE = re.compile(r"`([\w.-]+\.(?:md|py|sh))`", re.ASCII)
BARE_DIRS = ("", "references", "references/lang", "references/core", "references/modes", "references/pipeline",
             "references/cvss", "references/design", "references/checklists", "references/checklists/database",
             "references/sources",
             "assets", "assets/templates", "scripts", "docs")
BARE_SKIP = "references/lang/"  # 対象アプリのコード例（settings.py等）を書く文書
# 実行時に作る成果物の名前（スキル内に無くてよい。NOTES.mdはBUILDERの説明書: S1-4）
RUNTIME_RE = re.compile(r"security-audit-report[\w-]*\.md|5b-pair-table\.md|NOTES\.md")
# WARNで報告する検査のコード（他はNG）
WARN_CODES = ("size-unlisted", "size-gone", "bom", "crlf", "tok-total", "ref-bare")


def targets(root: str) -> list[str]:
    """検査対象の相対パス（docs/・evals/は対象外）"""
    out = ["SKILL.md"] if os.path.isfile(os.path.join(root, "SKILL.md")) else []
    for pat in (("references", "**", "*.md"), ("assets", "**", "*.md"), ("adapters", "**", "*.md")):
        for f in sorted(glob.glob(os.path.join(root, *pat), recursive=True)):
            out.append(os.path.relpath(f, root).replace(os.sep, "/"))
    return out


def load(root: str, ng: list[str], warn: list[str]):
    """(サイズ, 行の列) を返す。BOM・CRLFはWARNにして取り除いた行で検査する"""
    sizes: dict[str, int] = {}
    texts: dict[str, list[str]] = {}
    for rel in targets(root):
        try:
            with open(os.path.join(root, rel), "rb") as f:
                raw = f.read()
        except OSError as e:
            ng.append(f"[read] {rel} を読めない ({e})")
            continue
        sizes[rel] = len(raw)
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            ng.append(f"[utf8] {rel} がUTF-8として読めない")
            continue
        if s.startswith("﻿"):
            warn.append(f"[bom] {rel} の先頭にBOMがある")
            s = s[1:]
        if "\r\n" in s:
            warn.append(f"[crlf] {rel} の改行にCRLFがある")
            s = s.replace("\r\n", "\n")
        texts[rel] = s.split("\n")
    return sizes, texts


def marker_key(ln: str) -> str:
    """表記違いの比較用: NFKC・小文字・空白除去"""
    return re.sub(r"\s", "", unicodedata.normalize("NFKC", ln)).casefold()


def blocks(lines: list[str]) -> tuple[list[tuple[int, int]], list[str]]:
    """追加ブロック [(開始行, 終了行)]（1始まり・マーカー行を含む）と構造エラー"""
    out: list[tuple[int, int]] = []
    err: list[str] = []
    start = None
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if s == ADD:
            if start is not None:
                err.append(f"[marker-nest] L{i}: split:addの入れ子（L{start}が未終了）")
            start = i
        elif s == END:
            if start is None:
                err.append(f"[marker-orphan] L{i}: 対応するsplit:addの無いsplit:end")
            else:
                out.append((start, i))
                start = None
        elif marker_key(ln) in (ADD, END):
            err.append(f"[marker-variant] L{i}: split:マーカーの表記違い（{s[:30]}）")
        elif "<!--split:" in marker_key(ln):
            err.append(
                f"[marker-inline] L{i}: split:マーカーが単独行でない、または未知"
            )
    if start is not None:
        err.append(f"[marker-unclosed] L{start}: split:addが閉じていない")
    n_add = sum(1 for ln in lines if ln.strip() == ADD)
    n_end = sum(1 for ln in lines if ln.strip() == END)
    if n_add != n_end:
        err.append(
            f"[marker-count] split:addとsplit:endの数が不一致（{n_add}/{n_end}）"
        )
    return out, err


def inside(bl: list[tuple[int, int]], i: int) -> tuple[int, int] | None:
    for s, e in bl:
        if s <= i <= e:
            return (s, e)
    return None


def norm(s: str) -> str:
    return " ".join(s.split())


def file_check(sizes, texts, root, ng, warn, info):
    for rel, n in sizes.items():
        lo, hi = SIZE_RANGE.get(rel, DEFAULT_SIZE_RANGE)
        mark = "  ← 範囲外" if not lo <= n <= hi else ""
        info.append(f"  {rel}: {n:,} / {lo:,}〜{hi:,}（余裕 {hi - n:,}）{mark}")
        if n > hi:
            ng.append(f"[size-max] {rel} が {n:,}B（上限 {hi:,}B を {n - hi:,}B 超過）")
        if n < lo:
            ng.append(f"[size-min] {rel} が {n:,}B（下限 {lo:,}B 未満。中身の欠落？）")
        if rel not in SIZE_RANGE and not rel.startswith(UNLISTED_OK):
            warn.append(f"[size-unlisted] {rel} がサイズ表に無い（表の更新漏れ）")
    for rel in SIZE_RANGE:
        if rel not in sizes:
            warn.append(f"[size-gone] サイズ表の {rel} が無い（表の更新漏れか欠落）")
    for rel, lines in texts.items():
        k = sum(1 for ln in lines if ln.lstrip().startswith("```"))
        if k % 2:
            ng.append(f"[fence] {rel} のコードフェンス(```)が{k}行（奇数）")


def g0_check(sizes, texts, root, ng, warn, info):
    tot = 0
    for rel in G0_FILES:
        if rel not in sizes:
            ng.append(f"[g0-missing] {rel} が無い（予算を計算できない）")
        tot += sizes.get(rel, 0)
    info.append(f"  合計 {tot:,} / 上限 {G0_BUDGET:,}（余裕 {G0_BUDGET - tot:,}）")
    parts = [f"{os.path.basename(r)} {sizes.get(r, 0):,}" for r in G0_FILES]
    info.append("  内訳: " + ", ".join(parts))
    m2 = sum(sizes.get(r, 0) for r in MODE2_FILES)
    m4 = sum(sizes.get(r, 0) for r in MODE2_GATE_FILES)
    info.append(f"  参考: モード2必読{len(MODE2_FILES)}本 {m2:,}、ゲートM4 {m4:,}（上限なし）")
    if tot > G0_BUDGET:
        ng.append(f"[g0-budget] 読込予算超過 {tot:,}B > {G0_BUDGET:,}B")


def marker_check(sizes, texts, root, ng, warn, info):
    body: dict[str, tuple[str, int]] = {}
    adds: list[tuple[str, int, str]] = []
    for rel, lines in texts.items():
        bl, err = blocks(lines)
        for m in err:
            ng.append(m.replace("] ", f"] {rel} ", 1))
        tot = sum(e - s + 1 for s, e in bl)
        cap = ADD_LINE_CAPS.get(rel, DEFAULT_ADD_LINE_CAP)
        if bl or rel in ADD_LINE_CAPS:
            info.append(f"  {rel}: ブロック{len(bl)} 行数{tot} / 上限{cap}")
        if tot > cap:
            ng.append(f"[add-cap] {rel} の追加ブロックの行数{tot}が上限{cap}を超過")
        for i, ln in enumerate(lines, 1):
            s = norm(ln)
            if s in (ADD, END) or not s:
                continue
            if inside(bl, i):
                adds.append((rel, i, s))
            else:
                body.setdefault(s, (rel, i))
    for rel, i, s in adds:
        if len(s) >= DUP_MIN and s in body:
            r2, i2 = body[s]
            ng.append(
                f"[add-dup] {rel} L{i} の追加ブロック行が本文（{r2} L{i2}）と同一"
            )


def front_check(sizes, texts, root, ng, warn, info):
    """SKILL.mdのfrontmatter: 先頭の---、name、空でないdescription、閉じ---"""
    lines = texts.get("SKILL.md")
    if lines is None:
        return
    if not lines or lines[0].strip() != "---":
        ng.append("[fm-open] SKILL.md の1行目が --- でない")
        return
    keys: dict[str, list[str]] = {}
    cur = None
    for i, ln in enumerate(lines[1:], 2):
        if ln.strip() == "---":
            break
        m = re.match(r"([A-Za-z_][\w-]*):(.*)$", ln)
        if m:
            cur = m.group(1)
            keys[cur] = [m.group(2).strip()]
        elif ln.startswith((" ", "\t")) and cur:
            keys[cur].append(ln.strip())
        elif ln.strip():
            ng.append(f"[fm-close] SKILL.md の閉じ --- が無い（L{i} がYAMLでない）")
            return
    else:
        ng.append("[fm-close] SKILL.md の閉じ --- が無い")
        return
    name = keys.get("name", [""])[0].strip("'\"")
    info.append(f"  name: {name}、description: {len(keys.get('description', []))}行")
    if name != SKILL_NAME:
        ng.append(f"[fm-name] SKILL.md の name が {name!r}（期待 {SKILL_NAME}）")
    desc = [
        x for x in keys.get("description", []) if x not in ("", ">", ">-", "|", "|-")
    ]
    if not desc:
        ng.append("[fm-desc] SKILL.md の description が空、または無い")


def path_list(lines: list[str], key: str) -> tuple[int | None, list[str]] | None:
    """keyを含む行の「次のNつ」のNと、続く「1. `パス`」の列"""
    for i, ln in enumerate(lines):
        if key in ln:
            m = re.search(r"次の(\d+)つ", ln)
            items = []
            for x in lines[i + 1 :]:
                m2 = re.match(r"\d+\. `([^`]+)`", x)
                if not m2:
                    break
                items.append(m2.group(1))
            return (int(m.group(1)) if m else None), items
    return None


def skill_lists(skill, root, ng, info):
    """SKILL.mdのG0・モード2必読・ゲート一覧・分割構成を検査し、{ゲート: ファイル}を返す"""
    for key, label, want in (
        ("必読ファイル（G0", "G0", G0_FILES[1:]),
        ("必読ファイル（モード2", "モード2", MODE2_FILES),
    ):
        got = path_list(skill, key)
        if got is None:
            ng.append(f"[list-none] SKILL.mdに{label}の必読一覧（{key}）が無い")
            continue
        n, items = got
        info.append(f"  SKILL.md {label}必読: {len(items)}本（見出しの数 {n}）")
        if n != len(items):
            ng.append(
                f"[list-count] {label}必読は「次の{n}つ」だが一覧は{len(items)}本"
            )
        if sorted(items) != sorted(want):
            miss = [x for x in want if x not in items]
            extra = [x for x in items if x not in want]
            ng.append(f"[list-content] {label}必読が違う（欠落 {miss}・余分 {extra}）")
        elif tuple(items) != tuple(want):
            ng.append(f"[list-order] {label}必読の順序違い（{items}）")
    gates: dict[str, list[str]] = {}
    order = []
    for ln in skill:
        m = re.match(r"- (G\d)（[^）]*）: (.+)$", ln)
        if m:
            order.append(m.group(1))
            if (m.group(1) in CONDITIONAL_GATES) != ("条件付き" in ln.split("）")[0]):
                ng.append(
                    f"[gate-cond] SKILL.mdの{m.group(1)}の「条件付き」の表記が違う"
                )
            if m.group(1) in gates:
                ng.append(f"[gate-dup] SKILL.mdのゲート一覧で{m.group(1)}が重複")
            files = re.findall(r"`((?:references|assets)/[^`]+)`", m.group(2))
            gates[m.group(1)] = files
    if tuple(order) != FILE_GATES:
        ng.append(f"[gate-order] SKILL.mdのゲート一覧が {order}（期待 {FILE_GATES}）")
    for g, files in gates.items():
        info.append(f"  SKILL.md {g}: {len(files)}本")
        if tuple(files) != GATE_FILES.get(g):
            ng.append(f"[gate-files] SKILL.mdの{g}の一覧がGATE_FILESと違う（{files}）")
    rep_line = next((x for x in skill if "ゲート別に1行で報告" in x), "")
    if NONE_PHRASE not in rep_line:
        ng.append(
            f"[gate-cond-report] SKILL.mdの最終応答の報告文に「{NONE_PHRASE}」が無い"
        )
    if not any(
        re.match(r"\(d\) ", x) and "references/design/design-intent.md" in x for x in skill
    ):
        ng.append(
            "[m2-cond] SKILL.mdのモード2の条件付き必読(d)にdesign-intent.mdが無い"
        )
    for ln in skill:
        m = re.match(r"- (\d+)ファイル（(.+)）\s*$", ln)
        if m:
            k = len([x for x in m.group(2).split(",") if x.strip()])
            if int(m.group(1)) != k:
                ng.append(
                    f"[split-count] 分割構成が「{m.group(1)}ファイル」で列挙は{k}件"
                )
    m4 = [x for x in skill if x.startswith("**" + MODE2_GATE_KEY)]
    if len(m4) != 1:
        ng.append(f"[m2-gate] SKILL.mdにモード2のゲートM4の行（{MODE2_GATE_KEY}）が{len(m4)}行")
    else:
        got = tuple(re.findall(r"`((?:references|assets)/[^`]+)`", m4[0]))
        if got != MODE2_GATE_FILES:
            ng.append(f"[m2-gate] SKILL.mdのゲートM4の一覧がMODE2_GATE_FILESと違う（{list(got)}）")
        elif "GATE-TOKEN:" not in m4[0]:
            ng.append("[m2-gate] SKILL.mdのゲートM4の行にGATE-TOKEN:行の引用の指示が無い")
    for rel in sorted({x for fs in gates.values() for x in fs} | set(MODE2_FILES) | set(MODE2_GATE_FILES)):
        if not os.path.isfile(os.path.join(root, rel)):
            ng.append(f"[gate-exist] SKILL.mdの必読・ゲートの {rel} が実在しない")
    return gates


def marker_gates(doc, ng, info):
    """mode3-full-audit.mdのgateマーカー（集合・順序・mode3-only・files・キー文）"""
    bl, _ = blocks(doc)
    found: list[tuple[str, int, list[str], list[str]]] = []
    for i, ln in enumerate(doc, 1):
        for m in GATE_RE.finditer(ln):
            attrs = m.group(2).split()
            files = []
            for a in attrs:
                if a.startswith("files="):
                    files = [x for x in a[len("files=") :].split(",") if x]
            found.append((m.group(1), i, attrs, files))
    names = [g for g, _, _, _ in found]
    info.append(f"  {GATE_DOC} gateマーカー: {' '.join(names)}")
    if sorted(set(names)) != sorted(GATE_ORDER) or len(names) != len(set(names)):
        miss = [g for g in GATE_ORDER if g not in names]
        dup = sorted({g for g in names if names.count(g) > 1})
        extra = [g for g in names if g not in GATE_ORDER]
        ng.append(
            f"[gm-set] gateマーカーが違う（欠落 {miss}・重複 {dup}・余分 {extra}）"
        )
    elif tuple(names) != GATE_ORDER:
        ng.append(f"[gm-order] gateマーカーの順序が {names}（期待 {GATE_ORDER}）")
    for g, i, attrs, files in found:
        if "mode3-only" not in attrs:
            ng.append(f"[gm-mode3] L{i} の{g}マーカーにmode3-onlyが無い")
        if (g in CONDITIONAL_GATES) != ("conditional" in attrs):
            ng.append(f"[gm-cond] L{i} の{g}マーカーのconditionalの有無が違う")
        b = inside(bl, i)
        if not b:
            ng.append(f"[gm-outside] L{i} の{g}マーカーが追加ブロックの外")
        key = "【R1" if g == "R1" else f"【ゲート{g}"
        if not b or not any(key in x for x in doc[b[0] - 1 : b[1]]):
            ng.append(
                f"[gm-key] {g}のキー文（{key}…）がマーカーと同じ追加ブロックに無い"
            )
        if g in CONDITIONAL_GATES and b:
            if not any(NONE_PHRASE in x for x in doc[b[0] - 1 : b[1]]):
                ng.append(
                    f"[gm-cond-none] {g}の追加ブロックに「{NONE_PHRASE}」の記録指示が無い"
                )
        if g in GATE_FILES and tuple(files) != GATE_FILES[g]:
            ng.append(f"[gm-files] {g}マーカーのfilesがGATE_FILESと違う（{files}）")


def token_check(texts, gates, ng, warn, info):
    """GATE-TOKEN行: 対象ファイルに1行・先頭の追加ブロック内・一意・漏洩なし・キー文"""
    toks: dict[str, list[tuple[int, str]]] = {}
    for rel, lines in texts.items():
        for i, ln in enumerate(lines, 1):
            if ln.strip().startswith("GATE-TOKEN:"):
                toks.setdefault(rel, []).append((i, ln.strip()))
    seen_label: dict[str, str] = {}
    seen_hex: dict[str, str] = {}
    for rel in sorted(set(toks) | set(TOKEN_FILES)):
        got = toks.get(rel, [])
        if rel not in TOKEN_FILES:
            ng.append(f"[tok-unexpected] 想定外のGATE-TOKEN行 {rel} L{got[0][0]}")
            continue
        g = TOKEN_FILES[rel]
        if rel not in texts:
            ng.append(f"[tok-nofile] {rel} が無い（{g}のGATE-TOKEN行を確認できない）")
            continue
        if not got:
            ng.append(f"[tok-missing] {rel} のGATE-TOKEN行が無い")
        elif len(got) > 1:
            ng.append(f"[tok-multi] {rel} のGATE-TOKEN行が{len(got)}行（1行のはず）")
        lines = texts[rel]
        bl, _ = blocks(lines)
        head = bl[0] if bl and bl[0][0] == 1 else None
        for i, s in got:
            m = TOKEN_RE.fullmatch(s)
            if not m:
                ng.append(f"[tok-format] {rel} L{i} の形式が不正（{s[:40]}）")
                continue
            label, hx = m.group(1) + m.group(2), m.group(3)
            if m.group(1) != g:
                ng.append(f"[tok-gate] {rel} のトークン{label}がゲート{g}と合わない")
            if g in gates and rel not in gates[g]:
                ng.append(f"[tok-unlisted] {rel} がSKILL.mdの{g}の一覧に無い")
            if not head or not head[0] <= i <= head[1]:
                ng.append(
                    f"[tok-pos] {rel} L{i} のGATE-TOKEN行が先頭の追加ブロックに無い"
                )
            if label in seen_label:
                ng.append(f"[tok-dup-name] {label}が{seen_label[label]}と{rel}で重複")
            if hx in seen_hex:
                ng.append(f"[tok-dup-value] 値{hx}が{seen_hex[hx]}と{rel}で重複")
            seen_label[label], seen_hex[hx] = rel, rel
            for r2, l2 in texts.items():  # 値はゲート文・他ファイルに書かない
                for j, x in enumerate(l2, 1):
                    if hx in x and not (r2 == rel and j == i):
                        ng.append(f"[tok-leak] {rel} の値{hx}が {r2} L{j} に漏洩")
        key = re.compile(rf"本ファイルはゲート{g}(?:（[^）]*）)?で`Read`するファイル")
        top = lines[: head[1]] if head else []
        if not any(key.search(x) for x in top):
            ng.append(f"[tok-key] {rel} の先頭の追加ブロックに{g}のキー文が無い")
        info.append(f"  {rel}: {', '.join(s for _, s in got) or '（無し）'}")
    for g in FILE_GATES:
        if g in gates and not any(TOKEN_FILES.get(r) == g for r in gates[g]):
            ng.append(
                f"[tok-gate-none] SKILL.mdの{g}の一覧にトークンを持つファイルが無い"
            )
    n = sum(
        1
        for rel, lines in texts.items()
        if rel.startswith("references/")
        for ln in lines
        if "GATE-TOKEN" in ln
    )
    info.append(f"  references/内のGATE-TOKENを含む行: {n}（期待 {GATE_TOKEN_LINES}）")
    if n != GATE_TOKEN_LINES:
        warn.append(
            f"[tok-total] references/内のGATE-TOKEN行が{n}（期待 {GATE_TOKEN_LINES}）"
        )


def gate_check(sizes, texts, root, ng, warn, info):
    skill = texts.get("SKILL.md")
    if skill is None:
        ng.append("[gate-noskill] SKILL.mdを読めない")
        return
    gates = skill_lists(skill, root, ng, info)
    if GATE_DOC in texts:
        marker_gates(texts[GATE_DOC], ng, info)
    else:
        ng.append(f"[gm-nodoc] {GATE_DOC} が無い")
    token_check(texts, gates, ng, warn, info)


def ref_check(sizes, texts, root, ng, warn, info):
    paths: dict[str, list[str]] = {}
    bare: dict[str, list[str]] = {}
    for rel, lines in texts.items():
        for i, ln in enumerate(lines, 1):
            for p in PATH_RE.findall(ln):
                paths.setdefault(p, []).append(f"{rel} L{i}")
            for b in [] if rel.startswith(BARE_SKIP) else BARE_RE.findall(ln):
                bare.setdefault(b, []).append(f"{rel} L{i}")
    for p, at in sorted(paths.items()):
        if not os.path.isfile(os.path.join(root, p)):
            ng.append(
                f"[ref-missing] {p} が実在しない（{at[0]} ほか{len(at) - 1}箇所）"
            )
    for b, at in sorted(bare.items()):
        if RUNTIME_RE.fullmatch(b):
            continue
        if not any(os.path.isfile(os.path.join(root, d, b)) for d in BARE_DIRS):
            warn.append(f"[ref-bare] `{b}` がスキル内に見つからない（{at[0]}）")
    n = sum(len(v) for v in paths.values())
    info.append(f"  パス形式 {len(paths)}種（{n}箇所）、裸のファイル名 {len(bare)}種")


VERSIONS_REL = "references/sources/VERSIONS.json"
CWE_ROW_RE = re.compile(r"^\| CWE-(\d+) \|")
CONFIRMED_RE = re.compile(r"確認日[:：]?\s*(\d{4}-\d\d-\d\d)")


def md_section(lines: list[str], head: str) -> list[str]:
    """見出し(##)が head で始まる節の本文の行（次の見出しまで）"""
    out: list[str] = []
    on = False
    for ln in lines:
        if ln.startswith("## "):
            on = ln.startswith(head)
            continue
        if on:
            out.append(ln)
    return out


def load_check_sources(root: str):
    """scripts/check_sources.py を読み込む（VERSIONS.json の検証を二重管理しないため。
    .pyc を書かない）"""
    path = os.path.join(root, "scripts", "check_sources.py")
    old, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec = importlib.util.spec_from_file_location("check_sources_loaded", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.dont_write_bytecode = old


def versions_check(sizes, texts, root, ng, warn, info):
    path = os.path.join(root, VERSIONS_REL)
    if not os.path.isfile(path):
        ng.append(f"[ver-missing] {VERSIONS_REL} が無い")
        return
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:  # UnicodeDecodeErrorもValueError
        ng.append(f"[ver-json] {VERSIONS_REL} を読めない・JSONでない ({e})")
        return
    try:
        mod = load_check_sources(root)
    except Exception as e:  # ファイルが無い・構文エラー等
        ng.append(
            f"[ver-import] scripts/check_sources.py を読み込めない ({type(e).__name__} {e})"
        )
        return
    probs = mod.validate_versions(doc)
    for x in probs:  # 構造の検査は check_sources.py の validate_versions に一本化する
        code = (
            "ver-schema"
            if x.startswith(("最上位", "schema", "sources"))
            else "ver-field"
        )
        ng.append(f"[{code}] VERSIONS.json: {x}")
    if probs:
        return
    src = doc["sources"]
    for key, s in src.items():
        for a in s["affects"]:
            if not os.path.isfile(os.path.join(root, a["file"])):
                ng.append(
                    f"[ver-file] {key}.affects のファイルが実在しない ({a['file']})"
                )
        text, base = s.get("adopted_text"), s.get("adopted_in")
        if text is not None:
            body = "\n".join(texts.get(base, [])) if isinstance(base, str) else ""
            if not (text and text in body):
                ng.append(
                    f"[ver-text] {key}: 採用版の文字列 {text!r} が {base} の本文に無い"
                    "（referencesの版の記述との食い違い、またはadopted_inの誤り）"
                )
        if s["confirmed_basis"] == "human":
            body = "\n".join(texts.get(base, [])) if isinstance(base, str) else ""
            dates = CONFIRMED_RE.findall(body)
            if not dates or max(dates) != s["confirmed_on"]:
                ng.append(
                    f"[ver-date] {key}: confirmed_on {s['confirmed_on']} が {base} の"
                    f"「確認日」の記述（{', '.join(dates) or 'なし'}）と違う"
                )
        det = s.get("adopted_detail") or {}
        if key == "cwe_top25":
            rows = md_section(texts.get("references/sources/cwe-top25.md", []), "## Top 25")
            table = [f"CWE-{m.group(1)}" for m in map(CWE_ROW_RE.match, rows) if m]
            if det.get("ranking") != table:
                ng.append(
                    f"[ver-rank] {key}: adopted_detail.ranking が references/sources/cwe-top25.md の"
                    f"Top 25の表の順と違う（表{len(table)}件、"
                    f"記録{len(det.get('ranking') or [])}件）"
                )
        if key == "owasp_cheatsheets":
            names: list[str] = []
            for ln in texts.get("references/sources/owasp-cheatsheets.md", []):
                cells = [c.strip() for c in ln.strip().strip("|").split("|")]
                if ln.startswith("|") and len(cells) == 2 and "---" not in cells[1]:
                    if cells[0] != "カテゴリ":
                        names += [x.strip() for x in cells[1].split(",")]
            refs = [r["name"] for r in det.get("referenced", [])]
            if set(names) != set(refs):
                diff = sorted(set(names) ^ set(refs))
                ng.append(
                    f"[ver-sheets] {key}: adopted_detail.referenced が references/"
                    f"owasp-cheatsheets.md の表のシート名と違う（差: {', '.join(diff)[:120]}）"
                )
    info.append(f"  原典 {len(src)}件: {', '.join(src)}")


STEPS = (
    ("[1] ファイル（サイズの範囲・フェンス）", file_check),
    ("[2] G0読込予算", g0_check),
    ("[3] マーカーと追加ブロック", marker_check),
    ("[4] SKILL.mdのfrontmatter", front_check),
    ("[5] ゲート", gate_check),
    ("[6] 参照の実在", ref_check),
    ("[7] 原典の版（VERSIONS.json）", versions_check),
)


def check(root: str) -> tuple[list[str], list[str], list[str]]:
    """(NG, WARN, 項目ごとの表示行) を返す"""
    ng: list[str] = []
    warn: list[str] = []
    info: list[str] = [f"root: {root}"]
    if not os.path.isfile(os.path.join(root, "SKILL.md")):
        ng.append(f"[no-skill] {root} に SKILL.md が無い（--root を確認）")
        return ng, warn, info
    sizes, texts = load(root, ng, warn)
    for title, fn in STEPS:
        n0, k = len(ng), len(info)
        info.append(title)
        try:
            fn(sizes, texts, root, ng, warn, info)
        except Exception as e:  # 想定外の形でもTracebackにしない
            ng.append(f"[internal] {title}: {type(e).__name__} {e}")
        bad = len(ng) - n0
        info[k] = f"{title}: {'OK' if not bad else f'NG ({bad})'}"
    return ng, warn, info


def run(root: str) -> bool:
    ng, warn, info = check(root)
    for x in info:
        print(x)
    for m in warn:
        print("WARN:", m)
    for m in ng:
        print("NG:", m)
    print("RESULT:", f"NG ({len(ng)})" if ng else "OK")
    return not ng


def selftest(src: str) -> bool:
    """自己検査の本体は scripts/selftests/st_check_docs_integrity.py（本体の読込を減らすため分けた）。"""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "selftests"))
    import st_check_docs_integrity

    return st_check_docs_integrity._st_entry(globals(), src)


if __name__ == "__main__":
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=here, help="スキルディレクトリ（既定: 本体）")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        sys.exit(0 if selftest(a.root) else 1)
    sys.exit(0 if run(a.root) else 1)
