import { RequestHandler } from "express";
import { getDB, getConnectionStatus } from "../db";
import { getUserPermissions, getUserModules } from "../rbac";
import { LoginRequest, LoginResponse } from "@shared/api";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "HanuramFoods@SecureKey2024#XyZ!9k2mP";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "8h";

// Login attempt tracking (in-memory, per IP)
const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();
const MAX_ATTEMPTS = 10;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

export const handleLogin: RequestHandler = async (req, res) => {
  const dbStatus = getConnectionStatus();
  if (dbStatus !== "connected") {
    return res.status(503).json({ success: false, message: "Database not connected. Please try again later." } as LoginResponse);
  }

  const ip = req.ip || "unknown";
  const now = Date.now();

  // Check lockout
  const attempts = loginAttempts.get(ip);
  if (attempts && attempts.count >= MAX_ATTEMPTS && now - attempts.lastAttempt < LOCKOUT_MS) {
    const remaining = Math.ceil((LOCKOUT_MS - (now - attempts.lastAttempt)) / 60000);
    return res.status(429).json({ success: false, message: `Too many failed attempts. Try again in ${remaining} minutes.` });
  }

  const { username, password } = req.body as LoginRequest;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Username and password are required" } as LoginResponse);
  }

  // Basic input validation
  if (typeof username !== "string" || username.length > 50 || typeof password !== "string" || password.length > 100) {
    return res.status(400).json({ success: false, message: "Invalid input" });
  }

  try {
    const db = getDB();
    if (!db) return res.status(503).json({ success: false, message: "Database connection lost" } as LoginResponse);

    const user = await db.collection("users").findOne({ username: username.trim() });

    if (!user || user.status !== "active") {
      // Track failed attempt
      const cur = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
      loginAttempts.set(ip, { count: cur.count + 1, lastAttempt: now });
      return res.status(401).json({ success: false, message: "Invalid username or password" } as LoginResponse);
    }

    // Password check — support both plain (legacy) and hashed
    let passwordValid = false;
    if (user.password.startsWith("$2")) {
      // bcrypt hash
      passwordValid = await bcrypt.compare(password, user.password);
    } else {
      // Plain text (legacy) — compare and upgrade to hash
      passwordValid = user.password === password;
      if (passwordValid) {
        // Upgrade to bcrypt hash silently
        const hashed = await bcrypt.hash(password, 12);
        await db.collection("users").updateOne({ _id: user._id }, { $set: { password: hashed } });
      }
    }

    if (!passwordValid) {
      const cur = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
      loginAttempts.set(ip, { count: cur.count + 1, lastAttempt: now });
      return res.status(401).json({ success: false, message: "Invalid username or password" } as LoginResponse);
    }

    // Clear failed attempts on success
    loginAttempts.delete(ip);

    const permissions = await getUserPermissions(user.role_id);
    const modules = await getUserModules(user._id.toString());

    // Sign JWT
    const token = jwt.sign(
      { id: user._id.toString(), username: user.username, role_id: user.role_id },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN } as any
    );

    res.json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        role_id: user.role_id,
        permissions,
        modules,
      },
      token,
    } as LoginResponse);
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, message: "Server error during login" } as LoginResponse);
  }
};
