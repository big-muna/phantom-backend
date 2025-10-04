const { Pool } = require("pg");
const dotenv = require("dotenv");

dotenv.config();

const isProduction = process.env.NODE_ENV === "production";

const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  ssl: isProduction ? { rejectUnauthorized: false } : false, // Render requires SSL
});

module.exports = pool;
