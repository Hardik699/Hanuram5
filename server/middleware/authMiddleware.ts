import { RequestHandler } from "express";
import { getDB } from "../db";
import { hasPermission } from "../rbac";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "HanuramFoods@SecureKey2024#XyZ!9k2mP";

// Extract and verify JWT from Authorization header
export function extractUser(req: any): { username: string; id: string; role_id: number } | null {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;

  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    return { username: decoded.username, id: decoded.id, role_id: decoded.role_id };
  } catch {
    return null;
  }
}

export function requirePermission(requiredPermission: string): RequestHandler {
  return async (req, res, next) => {
    try {
      const userInfo = extractUser(req);

      if (!userInfo) {
        // Fallback: allow if no auth header (backward compat for now)
        return next();
      }

      const db = getDB();
      if (!db) return res.status(503).json({ success: false, message: "Database connection lost" });

      const user = await db.collection("users").findOne({ username: userInfo.username });

      if (!user || user.status !== "active") {
        return res.status(401).json({ success: false, message: "Unauthorized" });
      }

      const hasAccess = await hasPermission(user.role_id, requiredPermission);
      if (!hasAccess) {
        return res.status(403).json({ success: false, message: `Forbidden: Missing permission: ${requiredPermission}` });
      }

      (req as any).user = user;
      next();
    } catch (error) {
      console.error("Permission check error:", error);
      res.status(500).json({ success: false, message: "Server error during permission check" });
    }
  };
}

export const requireAuth: RequestHandler = async (req, res, next) => {
  try {
    const userInfo = extractUser(req);
    if (!userInfo) return res.status(401).json({ success: false, message: "Unauthorized: No valid token" });

    const db = getDB();
    if (!db) return res.status(503).json({ success: false, message: "Database connection lost" });

    const user = await db.collection("users").findOne({ username: userInfo.username });
    if (!user || user.status !== "active") {
      return res.status(401).json({ success: false, message: "Unauthorized: Invalid or inactive user" });
    }

    (req as any).user = user;
    next();
  } catch (error) {
    console.error("Auth error:", error);
    res.status(500).json({ success: false, message: "Server error during authentication" });
  }
};
