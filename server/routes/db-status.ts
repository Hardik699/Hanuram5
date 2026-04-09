import { RequestHandler } from "express";
import { getConnectionStatus } from "../db";

export interface DBStatusResponse {
  status: "connected" | "disconnected" | "connecting";
  message: string;
}

export const handleDBStatus: RequestHandler = (_req, res) => {
  const status = getConnectionStatus();

  res.json({
    status: status,
    message:
      status === "connected"
        ? "Database is connected"
        : status === "connecting"
          ? "Connecting to database..."
          : "Database is disconnected",
  });
};
