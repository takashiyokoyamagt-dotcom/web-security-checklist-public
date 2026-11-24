# CWE Top 25 対応表

出典: CWE Top 25 Most Dangerous Software Weaknesses (MITRE)
https://cwe.mitre.org/top25/
基準: CWE Top 25 2025年版（確認日 2026-10-10。出典 https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html ）

指摘を報告する際、可能であれば該当するCWE番号を付記してください（例:「CWE-89 (SQL Injection)」）。
以下は代表的なCWEと `principles.md` のカテゴリの対応です。Top 25の表は基準の年度版の公式の全25件（順位順）であり、
補助の表はTop 25に載らないが本スキルが使うCWEである（新しい年度版が出たら区分を見直す。WebSearch等で確認してよい）。

## Top 25（基準の年度版の全25件）

| CWE | 内容 | 対応カテゴリ |
| --- | --- | --- |
| CWE-79 | Cross-site Scripting (XSS) | 入力値検証 |
| CWE-89 | SQL Injection | 入力値検証、データベース |
| CWE-352 | Cross-Site Request Forgery (CSRF) | 通信・セキュリティ設定 |
| CWE-862 | Missing Authorization | アクセス制御・認可 |
| CWE-787 | Out-of-bounds Write | 依存関係管理（メモリ安全性） |
| CWE-22 | Path Traversal | 入力値検証、ファイルアップロード |
| CWE-416 | Use After Free | 依存関係管理（メモリ安全性） |
| CWE-125 | Out-of-bounds Read | 依存関係管理（メモリ安全性） |
| CWE-78 | OS Command Injection | 入力値検証 |
| CWE-94 | Code Injection | 入力値検証 |
| CWE-120 | Classic Buffer Overflow | 依存関係管理（メモリ安全性） |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | ファイルアップロード |
| CWE-476 | NULL Pointer Dereference | 依存関係管理（メモリ安全性） |
| CWE-121 | Stack-based Buffer Overflow | 依存関係管理（メモリ安全性） |
| CWE-502 | Deserialization of Untrusted Data | 入力値検証 |
| CWE-122 | Heap-based Buffer Overflow | 依存関係管理（メモリ安全性） |
| CWE-863 | Incorrect Authorization | アクセス制御・認可 |
| CWE-20 | Improper Input Validation | 入力値検証 |
| CWE-284 | Improper Access Control | アクセス制御・認可 |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | エラー処理・ログ、アクセス制御・認可 |
| CWE-306 | Missing Authentication for Critical Function | 認証、アクセス制御・認可 |
| CWE-918 | Server-Side Request Forgery (SSRF) | 入力値検証、通信・セキュリティ設定 |
| CWE-77 | Command Injection | 入力値検証 |
| CWE-639 | Authorization Bypass Through User-Controlled Key (IDOR) | アクセス制御・認可 |
| CWE-770 | Allocation of Resources Without Limits or Throttling | ビジネスロジック・API設計 |

## 補助（Top 25に載らないが本スキルが使うもの）

| CWE | 内容 | 対応カテゴリ |
| --- | --- | --- |
| CWE-287 | Improper Authentication | 認証 |
| CWE-798 | Use of Hard-coded Credentials | 暗号・秘密情報管理、データベース |
| CWE-259 | Use of Hard-coded Password | 暗号・秘密情報管理 |
| CWE-321 | Use of Hard-coded Cryptographic Key | 暗号・秘密情報管理 |
| CWE-285 | Improper Authorization | アクセス制御・認可 |
| CWE-611 | Improper Restriction of XML External Entity Reference (XXE) | 入力値検証 |
| CWE-209 | Generation of Error Message Containing Sensitive Information | エラー処理・ログ |
| CWE-532 | Insertion of Sensitive Information into Log File | エラー処理・ログ |
| CWE-319 | Cleartext Transmission of Sensitive Information | 通信・セキュリティ設定 |
| CWE-613 | Insufficient Session Expiration | セッション管理 |
| CWE-384 | Session Fixation | セッション管理 |
| CWE-1104 | Use of Unmaintained Third Party Components | 依存関係管理 |
| CWE-117 | Improper Output Neutralization for Logs | データベース |
| CWE-213 | Exposure of Sensitive Information Due to Incompatible Policies | データベース |
| CWE-250 | Execution with Unnecessary Privileges | データベース |
| CWE-256 | Plaintext Storage of a Password | データベース |
| CWE-269 | Improper Privilege Management | データベース |
| CWE-295 | Improper Certificate Validation | データベース |
| CWE-311 | Missing Encryption of Sensitive Data | データベース |
| CWE-312 | Cleartext Storage of Sensitive Information | データベース |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | データベース |
| CWE-400 | Uncontrolled Resource Consumption | データベース |
| CWE-521 | Weak Password Requirements | データベース |
| CWE-540 | Inclusion of Sensitive Information in Source Code | データベース |
| CWE-564 | Use of Hibernate with HQL/SQL Query String Containing External Input | データベース |
| CWE-653 | Improper Isolation or Compartmentalization | データベース |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | データベース |
| CWE-778 | Insufficient Logging | データベース |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | データベース |
| CWE-943 | Improper Neutralization of Special Elements in Data Query Logic | データベース |
| CWE-1327 | Binding to an Unrestricted IP Address | データベース |
| CWE-1392 | Use of Default Credentials | データベース |
| CWE-1395 | Dependency on Vulnerable Third-Party Component | データベース |

## 使い方
- モード2/3の指摘の`category`フィールドとして、`principles.md`のカテゴリ名に加えてCWE番号を併記すると
  レポートの説得力・検索性が上がる。
- **`sources`の`CWE`タグ（Top 25掲載の意味ではない）は、指摘に付けたCWE番号が実際にこのファイルの表（Top 25・補助の両方）に
  載っている場合のみ付与する。** 表に無いCWE番号（例: `principles.md`カテゴリ11のCWE-841等）は、
  `category`フィールドにCWE番号として記載してよいが、`CWE`タグは付けない（出典別レポートの
  CWEタブ/ファイルに含めない）。これは「有効なCWE番号である」ことと「この表に載る」ことは別の主張であり、
  後者を裏付ける一次情報がこの表だけだからである。補助の表のCWEも出典別レポートのCWE番号別グループに使う。
- 「Top 25に載る」と述べる箇所（`finding-arbiter.md` 5c(a)のタイブレーク②等）は、Top 25の表だけを指す。
