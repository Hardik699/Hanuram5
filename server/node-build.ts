import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { createServer } from "./index";
import * as express from "express";
import { disconnectDB } from "./db";

async function startServer() {
  try {
    console.log("🚀 Starting Faction App server...");
    const app = await createServer();
    console.log("✅ Express server created successfully");
    const port = process.env.PORT || 3000;

    // In production, serve the built SPA files
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);

    // Resolve SPA dist path robustly — try several candidates and pick the first that contains index.html
    const candidates = [
      path.join(__dirname, "../spa"),
      path.join(__dirname, "../../spa"),
      path.join(process.cwd(), "dist/spa"),
      path.join(process.cwd(), "spa"),
    ];

    let distPath = candidates.find((p) => {
      try {
        return fs.existsSync(path.join(p, "index.html"));
      } catch {
        return false;
      }
    });

    if (!distPath) {
      // Fallback to first candidate; we'll guard sendFile below
      distPath = candidates[0];
    }
    const indexHtmlPath = path.join(distPath, "index.html");

    // Serve static files
    app.use(express.static(distPath));

    // Use middleware fallback (no wildcard) to avoid path-to-regexp parsing issues
    app.use((req, res) => {
      // Don't serve index.html for API or health routes
      if (req.path.startsWith("/api/") || req.path.startsWith("/health")) {
        return res.status(404).json({ error: "API endpoint not found" });
      }

      // Ensure index file exists before sending
      if (!fs.existsSync(indexHtmlPath)) {
        console.error("index.html not found at", indexHtmlPath);
        return res.status(500).json({ error: "Frontend assets not found" });
      }

      res.sendFile(indexHtmlPath);
    });

    app.listen(port, () => {
      console.log(`🚀 Faction App server running on port ${port}`);
      console.log(`📱 Frontend: http://localhost:${port}`);
      console.log(`🔧 API: http://localhost:${port}/api`);
    });

    // Graceful shutdown
    process.on("SIGTERM", async () => {
      console.log("🛑 Received SIGTERM, shutting down gracefully");
      await disconnectDB();
      process.exit(0);
    });

    process.on("SIGINT", async () => {
      console.log("🛑 Received SIGINT, shutting down gracefully");
      await disconnectDB();
      process.exit(0);
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
}

startServer().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
