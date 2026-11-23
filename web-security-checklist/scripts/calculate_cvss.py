#!/usr/bin/env python3
"""CVSS v3.1 / v4.0 スコア計算スクリプト。

web-security-checklist SKILLのArbiterが、指摘ごとに判定したCVSSベクター文字列から
正確な数値スコアを機械的に算出するために使う。CVSSのスコア計算式（特にv4.0のマクロベクター
補間アルゴリズム）は人手の暗算では誤差が出やすいため、実装が公開されているPythonパッケージ
`cvss`（PyPI、Red Hat製、CVSS v4.0公式検証用ベクター集で実地検証済み）に計算を委譲する。
Arbiterの役割は「どのメトリクス値が該当するか」の判定（技術的な裏付けが必要な部分）に限定し、
「値からスコアを導く」計算そのものはこのスクリプトに任せることで、SKILL全体の「推測より実証」の
方針を計算結果にも適用する。

使い方:
    python3 scripts/calculate_cvss.py --v3-vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    python3 scripts/calculate_cvss.py --v4-vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    python3 scripts/calculate_cvss.py --v3-vector "..." --v4-vector "..."

    環境メトリクス（CR/IR/AR等）を含めたい場合は、ベクター文字列自体にそれらを埋め込んで渡す
    （例: ".../S:U/C:H/I:H/A:H/CR:H/IR:M/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H"）。
    v3.1はBaseメトリクスのみのベクターならbase_scoreのみを返し、Environmental系メトリクスが
    含まれていれば environmental_score も併せて返す。v4.0はBase/Threat/Environmentalの区別なく
    単一のスコアを返す仕様のため、渡したベクターに含まれるメトリクスがそのまま反映される。

出力: 標準出力にJSON1行。パース失敗時は該当バージョンのオブジェクトに `"error"` フィールドを
含め、スコアを捏造しない（実施メタデータ・指摘本文には、この出力をそのまま転記すること）。

前提: `pip3 install -r scripts/requirements-cvss.txt` が必要（検証済みバージョンを固定している。
未導入の場合はエラーメッセージでその旨を報告し、推測でスコアを埋めないこと。`references/core/common-principles.md`の
「誠実な報告」原則に従う）。
"""

import argparse
import json
import sys

try:
    from cvss import CVSS3, CVSS4
    from cvss.exceptions import CVSS3Error, CVSS4Error
except ImportError:
    print(
        json.dumps(
            {
                "error": "Pythonパッケージ 'cvss' が見つかりません。"
                "`pip3 install -r scripts/requirements-cvss.txt` を実行してから"
                "再実行してください。このエラーが解消できない場合はCVSSスコアを推測で埋めず、"
                "「CVSS計算ツールが利用できないため未算出」と正直に報告してください。"
            }
        )
    )
    sys.exit(1)


def score_v3(vector: str) -> dict:
    try:
        c = CVSS3(vector)
    except CVSS3Error as e:
        return {"vector": vector, "error": f"無効なCVSS v3.1ベクターです: {e}"}
    except Exception as e:
        return {"vector": vector, "error": f"CVSS v3.1の計算に失敗しました: {e}"}

    result = {
        "vector": vector,
        "base_score": c.base_score,
        "base_severity": c.severities()[0],
    }
    # Environmental系メトリクス（CR/IR/AR/MAV等）がベクター文字列に明示的に含まれている場合のみ、
    # environmental_scoreも併記する（`c.metrics`は未指定分もBase値等で補完済みのため、入力文字列に
    # 実際に書かれていたメトリクスだけを持つ`c.original_metrics`で判定する。未指定なら
    # environmental_score は base_score と同値になり冗長なため省略する）。
    env_metrics = {"CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
    specified = set(c.original_metrics.keys())
    if specified & env_metrics:
        result["environmental_score"] = c.environmental_score
        result["environmental_severity"] = c.severities()[2]
    return result


def score_v4(vector: str) -> dict:
    try:
        c = CVSS4(vector)
    except CVSS4Error as e:
        return {"vector": vector, "error": f"無効なCVSS v4.0ベクターです: {e}"}
    except Exception as e:
        return {"vector": vector, "error": f"CVSS v4.0の計算に失敗しました: {e}"}

    return {
        "vector": vector,
        "score": c.base_score,
        "severity": c.severity,
    }


# 自己テスト用の既知ベクター（期待値はいずれも一次資料で確認済み）。
# v3.1側は実在CVEの公表スコア（Log4Shell/CVE-2021-44228、EternalBlue系、Heartbleed/CVE-2014-0160）、
# v4.0側はFIRST.org公式のCVSS v4.0検証用ベクター集
# （https://github.com/FIRSTdotorg/cvss-resources 配下 vectorFiles/reference-vectors・
# reference-scores、全66,331件の中からBaseのみで一致を確認できた代表例）から採った。
# `cvss`パッケージの新しいバージョンで計算結果が変わっていないかを確認するための回帰テスト。
_SELF_TEST_CASES = [
    (
        "v3",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "base_score",
        10.0,
    ),  # Log4Shell
    (
        "v3",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "base_score",
        8.8,
    ),  # EternalBlue/CVE-2017-0144(NVD公表値)
    (
        "v3",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "base_score",
        7.5,
    ),  # Heartbleed
    ("v3", "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "base_score", 1.6),
    (
        "v4",
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:L/E:X",
        "score",
        9.1,
    ),
    (
        "v4",
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:H/E:X",
        "score",
        7.1,
    ),
    (
        "v4",
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/E:X",
        "score",
        6.8,
    ),
    (
        "v4",
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:H/SA:N/E:X",
        "score",
        1.8,
    ),
]


def run_self_test() -> int:
    failures = []
    for version, vector, field, expected in _SELF_TEST_CASES:
        result = score_v3(vector) if version == "v3" else score_v4(vector)
        got = result.get(field)
        if got is None or abs(float(got) - expected) > 0.05:
            failures.append((version, vector, field, expected, result))
    if failures:
        print(
            f"自己テスト失敗: {len(failures)}/{len(_SELF_TEST_CASES)}件が不一致です。"
            "`cvss`パッケージのバージョンが想定と異なる可能性があります。",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"自己テスト成功: {len(_SELF_TEST_CASES)}/{len(_SELF_TEST_CASES)}件が一致しました。"
    )
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="CVSS v3.1 / v4.0 ベクター文字列からスコアを計算する（web-security-checklist SKILL用）"
    )
    parser.add_argument(
        "--v3-vector",
        help="CVSS v3.1のベクター文字列（例: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H）",
    )
    parser.add_argument(
        "--v4-vector",
        help="CVSS v4.0のベクター文字列（例: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H）",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="既知ベクターで計算結果を検証する（依存パッケージの更新確認用。CI/導入確認で実行）",
    )
    args = parser.parse_args()

    if args.self_test:
        sys.exit(run_self_test())

    if not args.v3_vector and not args.v4_vector:
        parser.error(
            "--v3-vector と --v4-vector のうち少なくとも一方を指定してください。"
        )

    output = {}
    if args.v3_vector:
        output["v3"] = score_v3(args.v3_vector)
    if args.v4_vector:
        output["v4"] = score_v4(args.v4_vector)

    print(json.dumps(output, ensure_ascii=False, default=float))


if __name__ == "__main__":
    main()
