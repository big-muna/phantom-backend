const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../db"); // PostgreSQL pool connection

const router = express.Router();

// ---------------- Register ----------------
router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }

  try {
    // Check if user already exists
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email",
      [username, email, hashedPassword]
    );

    // Generate JWT token on registration
    const token = jwt.sign(
      { id: result.rows[0].id, email: result.rows[0].email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ 
      message: "✅ User registered successfully!", 
      user: result.rows[0],
      token
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ message: "❌ Registration failed." });
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
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "✅ Login successful",
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "❌ Login failed." });
  }
});

module.exports = router;
