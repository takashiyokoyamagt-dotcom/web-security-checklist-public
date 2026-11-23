// sample-vulnerable-app の評価用の種データ。監査の対象に含めないよう、アプリのディレクトリの外に置く。
// setup-evals.sh が、アプリのディレクトリ（コピー先）をカレントにして、data/app.db を新しく作るときに1回だけ実行する。
// 表の定義はカレントの db.js の CREATE TABLE をそのまま使う（db.js を読み込むと data/app.db が開かれ、表が作られる）。
// sqlite3 も db.js から読まれるので、カレントの node_modules のものを使う。
// パスワードは平文の見本値（GET /users の平文パスワード返却などを再現する前提のデータ）。
// id を明示しているので、既に種データがあるDBに再実行すると UNIQUE 制約で失敗する（二重投入しない）。
const path = require('node:path');

const { db } = require(path.resolve('db.js'));

db.serialize(() => {
  db.run(
    'INSERT INTO users (id, email, password, is_admin) VALUES (?, ?, ?, ?)',
    [1, 'bob@example.com', 'pw123', 0],
    (err) => {
      if (err) {
        console.error(`seed failed: ${err.message}`);
        process.exitCode = 1;
      }
    },
  );
});
db.close();
