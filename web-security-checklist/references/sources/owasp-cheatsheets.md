# OWASP Cheat Sheet Series 参照メモ

出典: https://cheatsheetseries.owasp.org/

`principles.md` の各カテゴリに対応する主なCheat Sheet。実装方法に迷ったら該当するシート名を根拠に引用する
（詳細な実装コードはユーザーに原典確認を促すか、`references/lang/*.md` の具体例を優先する）。

| カテゴリ | 主なCheat Sheet |
| --- | --- |
| 入力値検証 | Input Validation, SQL Injection Prevention, OS Command Injection Defense, Cross Site Scripting Prevention, Path Traversal Prevention |
| 認証 | Authentication, Password Storage, Credential Stuffing Prevention, Multifactor Authentication |
| セッション管理 | Session Management |
| アクセス制御・認可 | Authorization, Access Control |
| データベース | SQL Injection Prevention, Database Security |
| 暗号・秘密情報管理 | Cryptographic Storage, Secrets Management, Key Management |
| エラー処理・ログ | Logging, Error Handling |
| 通信・セキュリティ設定 | HTTP Headers, Transport Layer Security, Cross-Site Request Forgery Prevention, CORS Security |
| ファイルアップロード・ファイル操作 | File Upload |
| 依存関係管理 | Vulnerable Dependency Management |
| ビジネスロジック・API設計 | REST Security, Mass Assignment |

## 使い方
- 指摘やコード提案の根拠として「OWASP Cheat Sheet: ○○」の形で引用する。
- Cheat Sheetは頻繁に更新される。内容が古いと疑われたら最新版をWebSearch等で確認する。
