// database.js
// Kết nối PostgreSQL sử dụng thư viện pg
// Sử dụng thông tin từ biến môi trường (xem file .env)

require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER,        // DB_USER trong .env
  host: process.env.DB_HOST,        // DB_HOST trong .env
  database: process.env.DB_DATABASE, // DB_DATABASE trong .env
  password: process.env.DB_PASSWORD, // DB_PASSWORD trong .env
  port: process.env.DB_PORT,         // DB_PORT trong .env
});

// Test kết nối
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Kết nối lỗi:', err);
  } else {
    console.log('Kết nối thành công!', res.rows[0]);
  }
});

module.exports = pool;
