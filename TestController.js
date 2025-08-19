const mysql = require("mysql2/promise");

async function testConnection() {
  try {
    const connection = await mysql.createConnection({
      host: "believe.herosite.pro", // or sqlXXX.milesweb.com
      user: "lzscmnlb_qi_app",
      password: "pzfpAnzzKP7aGeP9pxxC",
      database: "lzscmnlb_qi_app",
      port: 3306
    });
    console.log("✅ Connected to Production MilesWeb MySQL!");
    await connection.end();
  } catch (err) {
    console.error("❌ DB Connection failed:", err.message);
  }
}

testConnection();
