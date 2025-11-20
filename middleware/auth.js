// middleware/auth.js
import jwt from "jsonwebtoken";

// Middleware to verify JWT tokens
export const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "default_secret");
    req.user = decoded; // attach user info to request
    next();
  } catch (err) {
    console.error("JWT auth error:", err);
    res.status(403).json({ message: "Invalid or expired token." });
  }
};
