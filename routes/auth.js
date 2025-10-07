// ===============================
// routes/auth.js
// Render PostgreSQL + ES Modules
// ===============================

import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";
const { Pool } = pkg;

const router = express.Router();

// ---------------- PostgreSQL Connection (RenderDB) ----------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // from Render environment
  ssl: { rejectUnauthorized: false },
});

// ---------------- Register ----------------
router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }

  try {
    // Check if user exists
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email",
      [username, email, hashedPassword]
    );

    // Generate token
    const token = jwt.sign(
      { id: result.rows[0].id, email: result.rows[0].email },
      process.env.JWT_SECRET || "default_secret",
      { expiresIn: "1d" }
    );

    res.json({
      message: "✅ User registered successfully!",
      user: result.rows[0],
      token,
    });
  } catch (err) {
    console.error("❌ Registration error:", err);
    res.status(500).json({ message: "Registration failed." });
  }
});

// ---------------- Login ----------------
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "❌ User not found." });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "❌ Invalid password." });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || "default_secret",
      { expiresIn: "1d" }
    );

    res.json({
      message: "✅ Login successful",
      token,
      user: { id: user.id, username: user.username, email: user.email },
    });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ message: "Login failed." });
  }
});

// ---------------- Export ----------------
export default router;

