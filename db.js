// db.js
import pkg from "pg";
import dotenv from "dotenv";

const { Pool } = pkg;

// Determine environment
const isProduction = process.env.NODE_ENV === "production";

// Load the correct .env file
if (!isProduction) {
  // Use local development env
  dotenv.config({ path: ".env.local" });
  console.log("💻 Using local development environment");
} else {
  // Use production env (Render)
  dotenv.config();
  console.log("🚀 Using production environment");
}

// Create PostgreSQL pool
export const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  ssl: isProduction ? { rejectUnauthorized: false } : false, // SSL only in production
});

// Test the database connection
pool.query("SELECT NOW()")
  .then(res => console.log("✅ DB connected:", res.rows[0]))
  .catch(err => console.error("❌ DB connection error:", err));

export default pool;
