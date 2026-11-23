const express = require('express');
const { db } = require('../db');

const router = express.Router();

router.post('/posts/:postId/comments', (req, res) => {
  const { body } = req.body;
  // 入力値の長さ・内容の検証なし（何でも保存できる）
  db.run(
    'INSERT INTO comments (post_id, body) VALUES (?, ?)',
    [req.params.postId, body],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

// このエンドポイント自体はJSONで返すので直接のXSSにはならないが、
// views/comment.ejs 側で <%- %>（非エスケープ）を使って表示するテンプレートを用意している
// （'GET /posts/:postId/comments/view' がその表示用エンドポイント）
router.get('/posts/:postId/comments/view', (req, res) => {
  db.all(
    'SELECT body FROM comments WHERE post_id = ?',
    [req.params.postId],
    (err, rows) => {
      if (err) return res.status(500).send(err.message);
      // 【意図的な脆弱性】格納型XSS (Stored XSS, CWE-79)
      // comment.ejs 側で <%- comment.body %> のように非エスケープ出力している
      res.render('comment', { comments: rows });
    }
  );
});

module.exports = router;
