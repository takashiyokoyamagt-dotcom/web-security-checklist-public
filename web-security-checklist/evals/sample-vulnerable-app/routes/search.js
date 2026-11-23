const express = require('express');
const { rawQuery } = require('../db');

const router = express.Router();

// 【意図的な脆弱性】SQLインジェクション (CWE-89)
// クエリパラメータをそのまま文字列結合してSQLを組み立てている
router.get('/search', (req, res) => {
  const keyword = req.query.q || '';
  const sql = `SELECT id, email FROM users WHERE email LIKE '%${keyword}%'`;
  rawQuery(sql, (err, rows) => {
    if (err) {
      // ここでもDBエラーの詳細をそのまま返してしまっている
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// 【意図的な脆弱性】ソート列を外部入力からそのまま組み立てている (allowlist化されていない)
router.get('/search/sorted', (req, res) => {
  const sortBy = req.query.sortBy || 'id';
  const sql = `SELECT id, email FROM users ORDER BY ${sortBy}`;
  rawQuery(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

module.exports = router;
