// AIVIC Backend Configuration
// AIVIC_APP_URL 環境変数が設定されている場合は自動セットされます
// 未設定の場合: REPLACE_WITH_API_URL を AIVIC アプリの URL（例: https://your-app.amplifyapp.com）に書き換えてください

window.AIVIC_API_URL = "REPLACE_WITH_API_URL";
window.AIVIC_TABLES = {
  "製品マスタ": 0,
  "製品仕様": 1,
  "工程マスタ": 2,
  "製造ライン": 3,
  "生産指示書": 4,
  "生産指示書明細": 5,
  "作業実績": 6,
  "品質検査結果": 7,
  "工程引き継ぎ情報": 8,
  "標準手順書": 9,
  "品質基準": 10,
  "作業履歴": 11,
  "進捗管理": 12,
  "アラート通知": 13,
  "異常値検出ログ": 14
};
