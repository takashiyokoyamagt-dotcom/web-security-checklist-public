const express = require('express');
const path = require('path');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const searchRoutes = require('./routes/search');
const commentRoutes = require('./routes/comments');
const uploadRoutes = require('./routes/upload');

const app = express();
app.set('view engine', 'ejs');
app.use(express.json());

// 【意図的な脆弱性】CORSを全オリジンに許可し、認証情報を伴うリクエストも受け入れている
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// 【意図的な脆弱性】アップロードディレクトリをそのまま静的公開している。
// upload.jsで拡張子検証していないため、実行可能ファイルが配信されうる
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// 【意図的な脆弱性】ヘルスチェック用エンドポイントがアプリのバージョン・内部パスを返している
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: process.env.npm_package_version, cwd: __dirname });
});

app.use('/', authRoutes);
app.use('/', userRoutes);
app.use('/', searchRoutes);
app.use('/', commentRoutes);
app.use('/', uploadRoutes);

// 【意図的な脆弱性】本番でもスタックトレースをそのままレスポンスに含めるエラーハンドラ (CWE-209)
app.use((err, req, res, next) => {
  console.error(err); // ここでログにも出るが、機密情報がマスクされていない点も問題
  res.status(500).json({ error: err.message, stack: err.stack });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on ${PORT}`));

module.exports = app;
