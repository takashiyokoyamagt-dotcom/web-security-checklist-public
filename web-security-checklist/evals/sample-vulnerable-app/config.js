// 【意図的な脆弱性】シークレットのハードコード (CWE-798, CWE-321)
// APIキー・JWT署名鍵・管理者用パスワードをソースコードに直書きしている。
module.exports = {
  jwtSecret: 'super-secret-key-12345',
  adminApiKey: 'sk_live_51Hxxxx_admin_master_key',
  dbAdminPassword: 'admin123',
};
