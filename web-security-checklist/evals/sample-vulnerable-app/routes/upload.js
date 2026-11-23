const express = require('express');
const multer = require('multer');
const path = require('path');

const router = express.Router();

// 【意図的な脆弱性】拡張子・MIMEタイプ検証なし、元のファイル名をそのまま使用 (CWE-434, CWE-22)
// 保存先も公開ディレクトリ(public/uploads)で、アップロードされた .js/.php/.html 等がそのまま
// 実行・配信されうる構成になっている
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, '..', 'public', 'uploads')),
  filename: (req, file, cb) => cb(null, file.originalname), // 元のファイル名をそのまま使用
});
const upload = multer({ storage }); // ファイルサイズ上限・拡張子フィルタなし

router.post('/upload', upload.single('file'), (req, res) => {
  res.json({ path: `/uploads/${req.file.originalname}` });
});

module.exports = router;
