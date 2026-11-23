const express = require('express');
const jwt = require('jsonwebtoken');
const { db } = require('../db');
const config = require('../config');

const router = express.Router();

function getUserFromToken(req) {
  const token = req.cookies && req.cookies.token;
  if (!token) return null;
  try {
    return jwt.verify(token, config.jwtSecret);
  } catch (e) {
    return null;
  }
}

// 【意図的な脆弱性】IDOR (Insecure Direct Object Reference) CWE-639
// ログイン中のユーザーが自分以外の :id を指定しても、所有者チェックをせずプロフィールを返している
router.get('/users/:id/profile', (req, res) => {
  const currentUser = getUserFromToken(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'ログインが必要です' });
  }
  // currentUser.userId と req.params.id が一致するかのチェックが無い
  db.get(
    'SELECT id, email, is_admin FROM users WHERE id = ?',
    [req.params.id],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(row);
    }
  );
});

// 【意図的な脆弱性】一覧APIでの他ユーザーデータ混入（OWASP API Security Top 10 API3:2023 / CWE-213, CWE-862）
// 認証チェックが一切なく、ページネーションも存在しないため、未ログインの第三者でも
// GET /users を1回呼ぶだけで全ユーザーのemail・password（平文）・is_adminを丸ごと取得できる。
router.get('/users', (req, res) => {
  // currentUser のチェックも、limit/offsetによるページネーションも一切ない
  db.all('SELECT id, email, password, is_admin FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 【意図的な脆弱性】管理者専用エンドポイントのはずが、認可チェックが無い CWE-862/CWE-285
router.post('/users/:id/make-admin', (req, res) => {
  const currentUser = getUserFromToken(req);
  if (!currentUser) {
    return res.status(401).json({ error: 'ログインが必要です' });
  }
  // isAdmin チェックをしていない。ログインしてさえいれば誰でも他人を管理者に昇格できる
  db.run('UPDATE users SET is_admin = 1 WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true });
  });
});

module.exports = router;
