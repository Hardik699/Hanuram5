import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.resolve(__dirname, "../.env");
const result = dotenv.config({ path: envPath });
if (result.parsed) {
  Object.assign(process.env, result.parsed);
}
import express from "express";
import cors from "cors";
import { securityHeaders, simpleRateLimit, validateInput } from "./middleware/securityMiddleware";
import { errorHandler, Logger } from "./middleware/errorHandler";
import multer from "multer";
import { handleDemo, handlePopulateSampleData } from "./routes/demo";
import { handleLogin } from "./routes/login";
import loginLogsRouter from "./routes/login-logs";
import { handleDBStatus } from "./routes/db-status";
import { handleBackupStart, handleBackupProgress } from "./routes/backup";
import {
  handleGetCategories,
  handleCreateCategory,
  handleUpdateCategory,
  handleDeleteCategory,
  handleClearAllCategories,
} from "./routes/categories";
import {
  handleGetSubCategories,
  handleCreateSubCategory,
  handleUpdateSubCategory,
  handleDeleteSubCategory,
  handleClearAllSubCategories,
} from "./routes/subcategories";
import {
  handleGetUnits,
  handleCreateUnit,
  handleUpdateUnit,
  handleDeleteUnit,
  handleClearAllUnits,
} from "./routes/units";
import {
  handleGetVendors,
  handleCreateVendor,
  handleUpdateVendor,
  handleDeleteVendor,
  handleClearAllVendors,
  handleUploadVendorsExcel,
} from "./routes/vendors";
import {
  handleGetRawMaterials,
  handleGetRawMaterialById,
  handleCreateRawMaterial,
  handleUpdateRawMaterial,
  handleDeleteRawMaterial,
  handleAddRMVendorPrice,
  handleGetRMVendorPrices,
  handleGetRMPriceLogs,
  handleDeleteRMPriceLog,
  handleUploadRawMaterials,
  handleExportRawMaterials,
  handleSyncLatestRMPrice,
  handleGetRawMaterialLogs,
  handleGetRMPriceHistory,
  handleClearAllRawMaterials,
  handleClearAllRMPrices,
  handleFixMissingUnitShortCodes,
  handleMigrateRMCodes,
  handleResetRMCounter,
  handleUploadRMPrices,
  handleDeleteRMByCodeRange,
  handleAddUnitConversion,
  handleDeleteUnitConversion,
} from "./routes/raw-materials";
import {
  handleGetRecipes,
  handleCreateRecipe,
  handleUpdateRecipe,
  handleDeleteRecipe,
  handlePatchLabourCost,
  handleGetRecipeItems,
  handleGetRecipeHistory,
  handleDeleteRecipeHistory,
  handleGetRecipeLogs,
  handleCreateRecipeSnapshot,
  handleGetPackagingCosts,
  handleSavePackagingCosts,
} from "./routes/recipes";
import {
  handleGetQuotationsByRecipe,
  handleGetQuotation,
  handleCreateQuotation,
  handleUpdateQuotation,
  handleDeleteQuotation,
  handleChangeQuotationVendor,
  handleGetQuotationLogs,
} from "./routes/quotations";
import { connectDB, getConnectionStatus } from "./db";
import {
  handleGetLabour,
  handleCreateLabour,
  handleUpdateLabour,
  handleDeleteLabour,
  handleGetRecipeLabour,
  handleAddRecipeLabour,
  handleDeleteRecipeLabour,
  handleGetLabourById,
} from "./routes/labour";
import {
  handleGetOpCosts,
  handleCreateOpCost,
  handleUpdateOpCost,
  handleDeleteOpCost,
  handleBulkUpdateOpCosts,
} from "./routes/op-costs";
import {
  handleGetBrands,
  handleCreateBrand,
  handleUpdateBrand,
  handleDeleteBrand,
  handleClearAllBrands,
} from "./routes/brands";
import { requirePermission } from "./middleware/authMiddleware";

export async function createServer() {
  console.log("📋 Creating Express server and initializing database...");
  const app = express();

  // Wrap route registration methods to log failures and identify problematic paths
  const _wrap = (method: string) => {
    const orig = (app as any)[method];
    (app as any)[method] = function (path: any, ...handlers: any[]) {
      try {
        return orig.call(this, path, ...handlers);
      } catch (err) {
        console.error(
          `Route registration failed for method=${String(method)} path=${String(path)}`,
        );
        console.error(err);
        throw err;
      }
    };
  };

  ["get", "post", "put", "delete", "use"].forEach((m) => _wrap(m));

  // Request logging middleware
  app.use((req, res, next) => {
    const startTime = Date.now();
    const path = req.path;
    const method = req.method;

    // Log API requests (not assets)
    if (path.startsWith("/api/") || path === "/health") {
      console.log(`📥 ${method} ${path}`);
    }

    // Track response
    const originalSend = res.send;
    res.send = function (data: any) {
      const duration = Date.now() - startTime;
      if (path.startsWith("/api/") || path === "/health") {
        console.log(
          `📤 ${method} ${path} - Status: ${res.statusCode} - ${duration}ms`,
        );
      }
      return originalSend.call(this, data);
    };

    next();
  });

  // Security Middleware - Apply first for maximum protection
  app.use(securityHeaders); // Add security headers
  app.use(simpleRateLimit); // Rate limiting
  app.use(validateInput); // Input validation

  // CORS Middleware
  app.use(
    cors({
      origin: process.env.ALLOWED_ORIGINS?.split(",") || "*",
      credentials: false,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization"],
      maxAge: 86400, // 24 hours
    }),
  );

  // Body Parsing Middleware
  app.use(express.json({ limit: "10mb" })); // Limit JSON payload to 10MB
  app.use(express.urlencoded({ extended: true, limit: "10mb" }));

  // Multer configuration for file uploads
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
      fileSize: 50 * 1024 * 1024, // 50MB limit
    },
    fileFilter: (req, file, cb) => {
      const allowedMimes = [
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel",
        "text/csv",
        "application/csv",
      ];
      if (allowedMimes.includes(file.mimetype)) {
        cb(null, true);
      } else {
        cb(new Error("Only Excel or CSV files are allowed"));
      }
    },
  });

  // Initialize database connection
  const dbConnected = await connectDB();
  if (!dbConnected) {
    console.error(
      "⚠️ Database connection failed - API routes may not work properly",
    );
  } else {
    console.log("✅ Database connection successful");
  }

  // Health check and API routes
  console.log("🔧 Registering API routes...");

  // Health check endpoint - not behind API path
  app.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      timestamp: new Date().toISOString(),
      database: getConnectionStatus(),
    });
  });

  app.get("/api/ping", (_req, res) => {
    const ping = process.env.PING_MESSAGE ?? "ping";
    res.json({ message: ping });
  });

  app.get("/api/demo", handleDemo);
  // Provide a GET route for demo population for convenience during local testing
  app.get("/api/demo/populate-sample-data", handlePopulateSampleData);
  app.post("/api/demo/populate-sample-data", handlePopulateSampleData);

  // Authentication routes
  app.post("/api/login", handleLogin);
  app.use("/api/login-logs", loginLogsRouter);
  app.get("/api/db-status", handleDBStatus);
  app.post("/api/backup", handleBackupStart);
  app.get("/api/backup/progress/:jobId", handleBackupProgress);

  // Category routes
  app.get("/api/categories", handleGetCategories);
  app.post("/api/categories", handleCreateCategory);
  app.delete("/api/categories/clear/all", handleClearAllCategories);
  app.put("/api/categories/:id", handleUpdateCategory);
  app.delete("/api/categories/:id", handleDeleteCategory);

  // SubCategory routes
  app.get("/api/subcategories", handleGetSubCategories);
  app.post("/api/subcategories", handleCreateSubCategory);
  app.delete("/api/subcategories/clear/all", handleClearAllSubCategories);
  app.put("/api/subcategories/:id", handleUpdateSubCategory);
  app.delete("/api/subcategories/:id", handleDeleteSubCategory);

  // Unit routes
  app.get("/api/units", handleGetUnits);
  app.post("/api/units", handleCreateUnit);
  app.delete("/api/units/clear/all", handleClearAllUnits);
  app.put("/api/units/:id", handleUpdateUnit);
  app.delete("/api/units/:id", handleDeleteUnit);

  // Brand routes
  app.get("/api/brands", handleGetBrands);
  app.post("/api/brands", handleCreateBrand);
  app.delete("/api/brands/clear/all", handleClearAllBrands);
  app.put("/api/brands/:id", handleUpdateBrand);
  app.delete("/api/brands/:id", handleDeleteBrand);

  // Vendor routes
  app.get("/api/vendors", handleGetVendors);
  app.post("/api/vendors", handleCreateVendor);
  app.post(
    "/api/vendors/upload",
    upload.single("file"),
    handleUploadVendorsExcel,
  );
  app.delete("/api/vendors/clear/all", handleClearAllVendors);
  app.put("/api/vendors/:id", handleUpdateVendor);
  app.delete("/api/vendors/:id", handleDeleteVendor);

  // Raw Material routes - specific paths first
  app.post("/api/raw-materials/upload", handleUploadRawMaterials as any);
  app.post("/api/raw-materials/upload-prices", handleUploadRMPrices as any);
  app.post("/api/raw-materials/delete-range", handleDeleteRMByCodeRange as any);
  app.get("/api/raw-materials/export", handleExportRawMaterials as any);
  app.delete("/api/raw-materials/clear/all", handleClearAllRawMaterials);
  app.delete("/api/raw-materials/prices/clear/all", handleClearAllRMPrices);
  app.post(
    "/api/raw-materials/migrate/fix-unit-shortcodes",
    handleFixMissingUnitShortCodes,
  );
  app.post("/api/raw-materials/migrate/codes", handleMigrateRMCodes);
  app.post("/api/raw-materials/reset-counter", handleResetRMCounter);

  // General RM routes
  app.get("/api/raw-materials", handleGetRawMaterials);
  app.post("/api/raw-materials", handleCreateRawMaterial);
  app.post("/api/raw-materials/vendor-price", handleAddRMVendorPrice);
  app.get(
    "/api/raw-materials/:rawMaterialId/vendor-prices",
    handleGetRMVendorPrices,
  );
  app.get("/api/raw-materials/:rawMaterialId/price-logs", handleGetRMPriceLogs);
  app.get("/api/raw-materials/:rawMaterialId/logs", handleGetRawMaterialLogs);
  app.get(
    "/api/raw-materials/:rawMaterialId/price-history",
    handleGetRMPriceHistory,
  );
  app.delete(
    "/api/raw-materials/:rawMaterialId/price-logs/:logId",
    handleDeleteRMPriceLog,
  );
  app.post(
    "/api/raw-materials/:rawMaterialId/sync-latest-price",
    handleSyncLatestRMPrice,
  );

  // Unit conversion routes
  app.post("/api/raw-materials/unit-conversion/add", handleAddUnitConversion);
  app.post("/api/raw-materials/unit-conversion/delete", handleDeleteUnitConversion);

  // Get single raw material by ID (must be before parameterized PUT/DELETE)
  app.get("/api/raw-materials/:id", handleGetRawMaterialById);

  // Parameterized routes last
  app.put("/api/raw-materials/:id", handleUpdateRawMaterial);
  app.delete("/api/raw-materials/:id", handleDeleteRawMaterial);

  // Recipe routes - Specific routes first, then general routes
  app.get("/api/recipes", handleGetRecipes);
  app.post("/api/recipes", handleCreateRecipe);
  app.post("/api/recipes/snapshot", handleCreateRecipeSnapshot);

  // Recipe sub-routes (specific paths before parameterized routes)
  app.get("/api/recipes/:recipeId/items", handleGetRecipeItems);
  app.get("/api/recipes/:recipeId/history", handleGetRecipeHistory);
  app.delete(
    "/api/recipes/:recipeId/history/:historyId",
    handleDeleteRecipeHistory,
  );
  app.get("/api/recipes/:recipeId/logs", handleGetRecipeLogs);
  app.get("/api/recipes/:recipeId/packaging-costs", handleGetPackagingCosts);
  app.post("/api/recipes/:recipeId/packaging-costs", handleSavePackagingCosts);

  // General parameterized routes (least specific, at the end)
  app.put("/api/recipes/:id", handleUpdateRecipe);
  app.patch("/api/recipes/:id/labour-cost", handlePatchLabourCost);
  app.delete("/api/recipes/:id", handleDeleteRecipe);

  // Quotation routes
  app.get("/api/quotations/recipe/:recipeId", handleGetQuotationsByRecipe);
  app.get("/api/quotations/:quotationId", handleGetQuotation);
  app.post("/api/quotations", handleCreateQuotation);
  app.put("/api/quotations/:quotationId", handleUpdateQuotation);
  app.delete("/api/quotations/:quotationId", handleDeleteQuotation);
  app.post(
    "/api/quotations/:quotationId/items/:quotationItemId/change-vendor",
    handleChangeQuotationVendor,
  );
  app.get("/api/quotations/:quotationId/logs", handleGetQuotationLogs);

  // Labour management routes
  app.get("/api/labour", handleGetLabour);
  app.post("/api/labour", handleCreateLabour);
  app.get("/api/labour/:id", handleGetLabourById);
  app.put("/api/labour/:id", handleUpdateLabour);
  app.delete("/api/labour/:id", handleDeleteLabour);

  // Recipe labour routes (for associating labour to recipes)
  app.get("/api/recipes/:recipeId/labour", handleGetRecipeLabour);
  app.post("/api/recipes/labour", handleAddRecipeLabour);
  app.delete("/api/recipes/labour/:id", handleDeleteRecipeLabour);

  // OP Cost routes
  app.get("/api/op-costs", handleGetOpCosts);
  app.post("/api/op-costs", handleCreateOpCost);
  app.put("/api/op-costs/bulk-update", handleBulkUpdateOpCosts);
  app.put("/api/op-costs/:id", handleUpdateOpCost);
  app.delete("/api/op-costs/:id", handleDeleteOpCost);

  console.log("✅ All API routes registered successfully");

  // SPA fallback - return 404 only for API routes
  // Non-API routes will be handled by Vite dev server
  app.use((req, res, next) => {
    // Only handle API and health routes
    if (req.path.startsWith("/api/") || req.path === "/health") {
      // This is an unmatched API route
      return res.status(404).json({
        success: false,
        message: "API endpoint not found",
        timestamp: new Date().toISOString(),
      });
    }

    // For all other routes, let Vite handle them (SPA routes)
    // Don't send any response - just pass to next middleware
    // This allows Vite's dev server to serve the routes
    next();
  });

  // Global error handling middleware (must be last)
  app.use(errorHandler);

  return app;
}
