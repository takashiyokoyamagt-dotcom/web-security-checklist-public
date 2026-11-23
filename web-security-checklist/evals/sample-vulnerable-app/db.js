const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// 【意図的な脆弱性】DBファイルパス・管理者パスワードの扱いが雑（本来は config.js 経由でも
// 環境変数化すべきだが、ここでは config.js 自体にハードコードしている点が問題の本体）
const db = new sqlite3.Database(path.join(__dirname, 'data', 'app.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    password TEXT,
    is_admin INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    body TEXT
  )`);
});

// 【意図的な脆弱性】生SQL文字列を返すだけのヘルパー。呼び出し側で文字列結合してしまっている
// （db.js自体は悪くないが、routes側の使い方がSQLiを誘発する設計になっている）
function rawQuery(sql, callback) {
  db.all(sql, callback);
}

module.exports = { db, rawQuery };
