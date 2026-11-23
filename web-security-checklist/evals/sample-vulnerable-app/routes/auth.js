const express = require('express');
const jwt = require('jsonwebtoken');
const { db } = require('../db');
const config = require('../config');

const router = express.Router();

// 【意図的な脆弱性】パスワードを平文のまま保存（ハッシュ化していない） CWE-256/CWE-259
// 【意図的な脆弱性】Mass Assignment（OWASP API Security Top 10 / CWE-915）
// req.body から email/password 以外に is_admin もそのまま取り出してINSERTしている。
// 明示的なフィールド許可リスト(allowlist)がないため、サインアップ時に
// { "email": "...", "password": "...", "is_admin": true } を送るだけで
// 誰でも管理者権限を持つアカウントを自己登録できてしまう。
router.post('/signup', (req, res) => {
  const { email, password, is_admin } = req.body;
  db.run(
    'INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)',
    [email, password, is_admin ? 1 : 0], // 平文パスワード保存に加え、is_adminも無検証で受け入れている
    function (err) {
      if (err) {
        // 【意図的な脆弱性】DBエラーの詳細（スタックトレース含む）をそのまま返している CWE-209
        return res.status(500).json({ error: err.message, stack: err.stack });
      }
      res.json({ id: this.lastID, email });
    }
  );
});

// 【意図的な脆弱性】平文パスワード比較・ユーザー列挙が可能・ブルートフォース対策なし
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user) {
      // メールアドレスが存在しない場合と、パスワードが違う場合でメッセージが異なる
      // → ユーザー列挙(user enumeration)が可能
      return res.status(401).json({ error: 'そのメールアドレスは登録されていません' });
    }
    if (user.password !== password) {
      return res.status(401).json({ error: 'パスワードが違います' });
    }

    // 【意図的な脆弱性】JWTに有効期限(exp)を設定していない
    const token = jwt.sign({ userId: user.id, isAdmin: !!user.is_admin }, config.jwtSecret);

    // 【意図的な脆弱性】Cookieに httpOnly / secure / sameSite を設定していない
    res.cookie('token', token);
    res.json({ token });
  });
});

module.exports = router;
