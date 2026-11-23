const express = require('express');
const app = express();
app.use(express.json());

// TODO: ログイン機能(サインアップ・ログイン)をここに追加する

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on ${PORT}`));

module.exports = app;
