import { Router, Request, Response } from "express";
import { getLoginLogs, getUserLoginLogs } from "../models/LoginLog";

const router = Router();

console.log("Login logs router initialized");

// Get all login logs (admin only)
router.get("/", async (req: Request, res: Response) => {
  try {
    console.log("GET /api/login-logs called");
    const limit = parseInt(req.query.limit as string) || 100;
    const skip = parseInt(req.query.skip as string) || 0;
    
    console.log(`Fetching login logs: limit=${limit}, skip=${skip}`);
    
    const result = await getLoginLogs(limit, skip);
    
    if (!result.success) {
      console.error("Error fetching login logs:", result.error);
      return res.status(500).json({ success: false, error: "Failed to fetch login logs", data: [], total: 0 });
    }
    
    res.json(result);
  } catch (error) {
    console.error("Error in login logs route:", error);
    res.status(500).json({ success: false, error: "Failed to fetch login logs", data: [], total: 0 });
  }
});

// Get login logs for specific user
router.get("/user/:username", async (req: Request, res: Response) => {
  try {
    console.log("GET /api/login-logs/user/:username called");
    const { username } = req.params;
    const limit = parseInt(req.query.limit as string) || 50;
    
    const result = await getUserLoginLogs(username, limit);
    
    if (!result.success) {
      console.error("Error fetching user login logs:", result.error);
      return res.status(500).json({ success: false, error: "Failed to fetch user login logs", data: [] });
    }
    
    res.json(result);
  } catch (error) {
    console.error("Error in user login logs route:", error);
    res.status(500).json({ success: false, error: "Failed to fetch user login logs", data: [] });
  }
});

export default router;
