import { getDB } from "../db";

export interface LoginLog {
  _id?: string;
  username: string;
  email?: string;
  ipAddress: string;
  userAgent?: string;
  loginTime: Date;
  logoutTime?: Date;
  status: "success" | "failed";
  failureReason?: string;
}

export async function createLoginLog(log: Omit<LoginLog, "_id">) {
  try {
    const database = getDB();
    if (!database) {
      console.error("Database not connected");
      return { success: false, error: "Database not connected" };
    }
    
    const collection = database.collection("login_logs");
    const result = await collection.insertOne({
      ...log,
      loginTime: new Date(log.loginTime),
      logoutTime: log.logoutTime ? new Date(log.logoutTime) : null,
    });
    return { success: true, data: result };
  } catch (error) {
    console.error("Error creating login log:", error);
    return { success: false, error };
  }
}

export async function getLoginLogs(limit: number = 100, skip: number = 0) {
  try {
    const database = getDB();
    if (!database) {
      console.error("Database not connected");
      return { success: false, error: "Database not connected", data: [], total: 0 };
    }
    
    const collection = database.collection("login_logs");
    const logs = await collection
      .find({})
      .sort({ loginTime: -1 })
      .limit(limit)
      .skip(skip)
      .toArray();
    
    const total = await collection.countDocuments();
    
    return { success: true, data: logs, total };
  } catch (error) {
    console.error("Error fetching login logs:", error);
    return { success: false, error, data: [], total: 0 };
  }
}

export async function getUserLoginLogs(username: string, limit: number = 50) {
  try {
    const database = getDB();
    if (!database) {
      console.error("Database not connected");
      return { success: false, error: "Database not connected", data: [] };
    }
    
    const collection = database.collection("login_logs");
    const logs = await collection
      .find({ username })
      .sort({ loginTime: -1 })
      .limit(limit)
      .toArray();
    
    return { success: true, data: logs };
  } catch (error) {
    console.error("Error fetching user login logs:", error);
    return { success: false, error, data: [] };
  }
}
