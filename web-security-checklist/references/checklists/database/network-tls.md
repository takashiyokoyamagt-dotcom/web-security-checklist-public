# DB接続の暗号化とDBサーバの配置

| ID | 証跡 | 重大度目安 | 確認内容 | 検出の手掛かり | 根拠 |
| --- | --- | --- | --- | --- | --- |
| DB-NET-01 | SRC+CFG | High | WebとDBの間の通信をTLSで暗号化し、証明書とホスト名を検証する（Postgresは `sslmode=verify-full`。`require` は検証しない実装がある） | `sslmode=disable`・`require`、`ssl: false`、`useSSL=false`、`rejectUnauthorized: false`、DB側の `ssl=off` | CWE-319、CWE-295。ISM-1277 |
| DB-NET-02 | CFG | High | DBをインターネットに直接公開しない（プライベートなネットワークに置く） | composeの `ports: "5432:5432"`、Terraformの `publicly_accessible = true`、DBポートへの `0.0.0.0/0` | CWE-1327。ISM-1271 |
| DB-NET-03 | CFG | High | DBへの接続元を、必要な相手（アプリサーバ等）だけに絞る | `pg_hba.conf` の `host all all 0.0.0.0/0`、`bind-address = 0.0.0.0` と全許可のFW、セキュリティグループの全開放 | CWE-1327。ISM-1271 |
| DB-NET-04 | CFG | Medium | ローカルからしか使わないDBは、ネットワーク待受を止めるか localhost だけで待ち受ける | `listen_addresses = '*'`、`bind_ip_all`、ポートの公開が不要な構成で `ports` がある | CWE-1327。ISM-1272 |
| DB-NET-05 | CFG+OPS | Medium | DBサーバとWebサーバを機能として分離する（同じホスト・コンテナに同居させない） | 1つのコンテナ・supervisordでアプリとDBを起動、同一インスタンスの定義 | CWE-653。ISM-1269 |
| DB-NET-06 | CFG+OPS | Medium | 開発・テスト・ステージング・本番のDBを互いに分離する | 環境別設定の接続先ホストやDB名・認証情報が同じ、tfvarsの共有 | CWE-653。ISM-1273 |
| DB-NET-07 | CFG+OPS | Low | DBサーバを利用者の端末と別のネットワークセグメントに置く | IaCのサブネットで端末用とDBが同じCIDR | CWE-653。ISM-1270 |

注: 設定ファイルは「書かれている内容」を示すだけで、実際の待受・適用済みのFW・ネットワーク分離は確かめられない。設定が見当たらないことだけを根拠に指摘せず、`ops-requests.md` の確認依頼にする。ISM-1277の「ASD承認の暗号技術」への適合も運用で確認する。
