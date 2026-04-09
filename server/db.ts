import { MongoClient, Db } from "mongodb";
import bcrypt from "bcryptjs";
import { createDatabaseIndexes } from "./db-indexes";

let client: MongoClient | null = null;
let db: Db | null = null;
let connectionStatus = "disconnected";

// Hash password helper
async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, 12);
}

export async function connectDB(): Promise<boolean> {
  if (db) {
    return true;
  }

  const MONGODB_URI = process.env.MONGODB_URI;

  try {
    if (!MONGODB_URI) {
      console.error("❌ MONGODB_URI environment variable is not set");
      return false;
    }

    console.log("🔌 Attempting to connect to MongoDB...");
    connectionStatus = "connecting";
    client = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
      retryWrites: true,
      w: "majority",
    });

    console.log("⏳ Connecting to MongoDB Atlas...");
    await client.connect();
    console.log("✅ MongoDB connection established");

    db = client.db("faction_app");

    // Verify connection by pinging the database
    console.log("🏓 Pinging MongoDB...");
    await db.admin().ping();
    connectionStatus = "connected";
    console.log("✅ Connected to MongoDB");

    // Initialize collections
    await initializeCollections();

    // Create database indexes for performance
    await createDatabaseIndexes(db);

    return true;
  } catch (error) {
    connectionStatus = "disconnected";
    console.error("❌ MongoDB connection failed");
    console.error(
      "Error details:",
      error instanceof Error ? error.message : String(error),
    );
    if (error instanceof Error && error.stack) {
      console.error("Stack trace:", error.stack);
    }
    return false;
  }
}

async function initializeCollections() {
  if (!db) return;

  try {
    const collections = await db.listCollections().toArray();
    const collectionNames = collections.map((c) => c.name);

    // Create roles collection if it doesn't exist
    if (!collectionNames.includes("roles")) {
      await db.createCollection("roles");
      const rolesData = [
        { role_id: 1, role_name: "Super Admin" },
        { role_id: 2, role_name: "Admin" },
        { role_id: 3, role_name: "Manager" },
        { role_id: 4, role_name: "Vendor" },
        { role_id: 5, role_name: "Viewer" },
        { role_id: 6, role_name: "Cost Viewer" },
        { role_id: 7, role_name: "Production" },
      ] as any[];
      await db.collection("roles").insertMany(rolesData);
      console.log("✅ Roles collection initialized");
    }

    // Create permissions collection if it doesn't exist
    if (!collectionNames.includes("permissions")) {
      await db.createCollection("permissions");
      const permissionsData = [
        {
          permission_id: 1,
          permission_key: "dashboard_view",
          description: "View Dashboard",
        },
        {
          permission_id: 2,
          permission_key: "rm_view",
          description: "View Raw Materials",
        },
        {
          permission_id: 3,
          permission_key: "rm_add",
          description: "Add Raw Materials",
        },
        {
          permission_id: 4,
          permission_key: "rm_edit",
          description: "Edit Raw Materials",
        },
        {
          permission_id: 5,
          permission_key: "recipe_view",
          description: "View Recipes",
        },
        {
          permission_id: 6,
          permission_key: "recipe_add",
          description: "Add Recipes",
        },
        {
          permission_id: 7,
          permission_key: "recipe_edit",
          description: "Edit Recipes",
        },
        {
          permission_id: 8,
          permission_key: "category_view",
          description: "View Categories",
        },
        {
          permission_id: 9,
          permission_key: "category_add",
          description: "Add Categories",
        },
        {
          permission_id: 10,
          permission_key: "subcategory_view",
          description: "View SubCategories",
        },
        {
          permission_id: 11,
          permission_key: "subcategory_add",
          description: "Add SubCategories",
        },
        {
          permission_id: 12,
          permission_key: "unit_view",
          description: "View Units",
        },
        {
          permission_id: 13,
          permission_key: "unit_add",
          description: "Add Units",
        },
        {
          permission_id: 14,
          permission_key: "vendor_view",
          description: "View Vendors",
        },
        {
          permission_id: 15,
          permission_key: "vendor_add",
          description: "Add Vendors",
        },
        {
          permission_id: 16,
          permission_key: "vendor_edit",
          description: "Edit Vendors",
        },
        {
          permission_id: 17,
          permission_key: "quotation_view",
          description: "View Quotations",
        },
        {
          permission_id: 18,
          permission_key: "quotation_add",
          description: "Add Quotations",
        },
        {
          permission_id: 20,
          permission_key: "labour_view",
          description: "View Labour",
        },
        {
          permission_id: 21,
          permission_key: "labour_add",
          description: "Add Labour",
        },
        {
          permission_id: 22,
          permission_key: "labour_edit",
          description: "Edit Labour",
        },
        {
          permission_id: 23,
          permission_key: "labour_view_costs",
          description: "View Labour Cost Details",
        },
        {
          permission_id: 24,
          permission_key: "rmc_view_prices",
          description: "View RMC Prices",
        },
        {
          permission_id: 25,
          permission_key: "rm_view_labour_cost",
          description: "View Labour Cost in Raw Materials",
        },
        {
          permission_id: 26,
          permission_key: "rm_view_packing_cost",
          description: "View Packing Cost in Raw Materials",
        },
        {
          permission_id: 27,
          permission_key: "opcost_view",
          description: "View OP Cost Management",
        },
      ] as any[];
      await db.collection("permissions").insertMany(permissionsData);
      console.log("✅ Permissions collection initialized");
    } else {
      // Ensure labour and cost viewing permissions are in the permissions collection
      const permissionsCollection = db.collection("permissions");
      const newPerms = [
        {
          permission_id: 20,
          permission_key: "labour_view",
          description: "View Labour",
        },
        {
          permission_id: 21,
          permission_key: "labour_add",
          description: "Add Labour",
        },
        {
          permission_id: 22,
          permission_key: "labour_edit",
          description: "Edit Labour",
        },
        {
          permission_id: 23,
          permission_key: "labour_view_costs",
          description: "View Labour Cost Details",
        },
        {
          permission_id: 24,
          permission_key: "rmc_view_prices",
          description: "View RMC Prices",
        },
        {
          permission_id: 25,
          permission_key: "rm_view_labour_cost",
          description: "View Labour Cost in Raw Materials",
        },
        {
          permission_id: 26,
          permission_key: "rm_view_packing_cost",
          description: "View Packing Cost in Raw Materials",
        },
        {
          permission_id: 27,
          permission_key: "opcost_view",
          description: "View OP Cost Management",
        },
      ];
      for (const perm of newPerms) {
        await permissionsCollection.updateOne(
          { permission_id: perm.permission_id },
          { $setOnInsert: perm },
          { upsert: true },
        );
      }
      console.log(
        "✅ Labour and cost viewing permissions ensured in permissions collection",
      );
    }

    // Ensure Cost Viewer role exists
    if (collectionNames.includes("roles")) {
      const rolesCollection = db.collection("roles");
      await rolesCollection.updateOne(
        { role_id: 6 },
        { $setOnInsert: { role_id: 6, role_name: "Cost Viewer" } },
        { upsert: true },
      );
      console.log("✅ Cost Viewer role ensured");
    }

    // Create role_permissions collection if it doesn't exist
    if (!collectionNames.includes("role_permissions")) {
      await db.createCollection("role_permissions");
      const rolePermissionsData = [
        // Super Admin - All permissions
        { role_id: 1, permission_id: 1 },
        { role_id: 1, permission_id: 2 },
        { role_id: 1, permission_id: 3 },
        { role_id: 1, permission_id: 4 },
        { role_id: 1, permission_id: 5 },
        { role_id: 1, permission_id: 6 },
        { role_id: 1, permission_id: 7 },
        { role_id: 1, permission_id: 8 },
        { role_id: 1, permission_id: 9 },
        { role_id: 1, permission_id: 10 },
        { role_id: 1, permission_id: 11 },
        { role_id: 1, permission_id: 12 },
        { role_id: 1, permission_id: 13 },
        { role_id: 1, permission_id: 14 },
        { role_id: 1, permission_id: 15 },
        { role_id: 1, permission_id: 16 },
        { role_id: 1, permission_id: 17 },
        { role_id: 1, permission_id: 18 },
        { role_id: 1, permission_id: 19 },
        { role_id: 1, permission_id: 20 },
        { role_id: 1, permission_id: 21 },
        { role_id: 1, permission_id: 22 },
        { role_id: 1, permission_id: 23 },
        { role_id: 1, permission_id: 24 },
        { role_id: 1, permission_id: 25 },
        { role_id: 1, permission_id: 26 },
        { role_id: 1, permission_id: 27 },
        // Admin
        { role_id: 2, permission_id: 1 },
        { role_id: 2, permission_id: 2 },
        { role_id: 2, permission_id: 3 },
        { role_id: 2, permission_id: 4 },
        { role_id: 2, permission_id: 5 },
        { role_id: 2, permission_id: 6 },
        { role_id: 2, permission_id: 7 },
        { role_id: 2, permission_id: 8 },
        { role_id: 2, permission_id: 9 },
        { role_id: 2, permission_id: 12 },
        { role_id: 2, permission_id: 13 },
        { role_id: 2, permission_id: 14 },
        { role_id: 2, permission_id: 15 },
        { role_id: 2, permission_id: 16 },
        { role_id: 2, permission_id: 17 },
        { role_id: 2, permission_id: 18 },
        { role_id: 2, permission_id: 19 },
        { role_id: 2, permission_id: 20 },
        { role_id: 2, permission_id: 21 },
        { role_id: 2, permission_id: 22 },
        { role_id: 2, permission_id: 23 },
        { role_id: 2, permission_id: 24 },
        { role_id: 2, permission_id: 25 },
        { role_id: 2, permission_id: 26 },
        { role_id: 2, permission_id: 27 },
        // Manager - ALL Permissions
        { role_id: 3, permission_id: 1 },
        { role_id: 3, permission_id: 2 },
        { role_id: 3, permission_id: 3 },
        { role_id: 3, permission_id: 4 },
        { role_id: 3, permission_id: 5 },
        { role_id: 3, permission_id: 6 },
        { role_id: 3, permission_id: 7 },
        { role_id: 3, permission_id: 8 },
        { role_id: 3, permission_id: 9 },
        { role_id: 3, permission_id: 10 },
        { role_id: 3, permission_id: 11 },
        { role_id: 3, permission_id: 12 },
        { role_id: 3, permission_id: 13 },
        { role_id: 3, permission_id: 14 },
        { role_id: 3, permission_id: 15 },
        { role_id: 3, permission_id: 16 },
        { role_id: 3, permission_id: 17 },
        { role_id: 3, permission_id: 18 },
        { role_id: 3, permission_id: 20 },
        { role_id: 3, permission_id: 21 },
        { role_id: 3, permission_id: 22 },
        { role_id: 3, permission_id: 23 },
        { role_id: 3, permission_id: 24 },
        { role_id: 3, permission_id: 25 },
        { role_id: 3, permission_id: 26 },
        { role_id: 3, permission_id: 27 },
        // Vendor - ALL Permissions
        { role_id: 4, permission_id: 1 },
        { role_id: 4, permission_id: 2 },
        { role_id: 4, permission_id: 3 },
        { role_id: 4, permission_id: 4 },
        { role_id: 4, permission_id: 5 },
        { role_id: 4, permission_id: 6 },
        { role_id: 4, permission_id: 7 },
        { role_id: 4, permission_id: 8 },
        { role_id: 4, permission_id: 9 },
        { role_id: 4, permission_id: 10 },
        { role_id: 4, permission_id: 11 },
        { role_id: 4, permission_id: 12 },
        { role_id: 4, permission_id: 13 },
        { role_id: 4, permission_id: 14 },
        { role_id: 4, permission_id: 15 },
        { role_id: 4, permission_id: 16 },
        { role_id: 4, permission_id: 17 },
        { role_id: 4, permission_id: 18 },
        { role_id: 4, permission_id: 20 },
        { role_id: 4, permission_id: 21 },
        { role_id: 4, permission_id: 22 },
        { role_id: 4, permission_id: 23 },
        { role_id: 4, permission_id: 24 },
        { role_id: 4, permission_id: 25 },
        { role_id: 4, permission_id: 26 },
        { role_id: 4, permission_id: 27 },
        // Viewer - ALL Permissions
        { role_id: 5, permission_id: 1 },
        { role_id: 5, permission_id: 2 },
        { role_id: 5, permission_id: 3 },
        { role_id: 5, permission_id: 4 },
        { role_id: 5, permission_id: 5 },
        { role_id: 5, permission_id: 6 },
        { role_id: 5, permission_id: 7 },
        { role_id: 5, permission_id: 8 },
        { role_id: 5, permission_id: 9 },
        { role_id: 5, permission_id: 10 },
        { role_id: 5, permission_id: 11 },
        { role_id: 5, permission_id: 12 },
        { role_id: 5, permission_id: 13 },
        { role_id: 5, permission_id: 14 },
        { role_id: 5, permission_id: 15 },
        { role_id: 5, permission_id: 16 },
        { role_id: 5, permission_id: 17 },
        { role_id: 5, permission_id: 18 },
        { role_id: 5, permission_id: 20 },
        { role_id: 5, permission_id: 21 },
        { role_id: 5, permission_id: 22 },
        { role_id: 5, permission_id: 23 },
        { role_id: 5, permission_id: 24 },
        { role_id: 5, permission_id: 25 },
        { role_id: 5, permission_id: 26 },
        { role_id: 5, permission_id: 27 },
        // Cost Viewer - ALL Permissions
        { role_id: 6, permission_id: 1 },
        { role_id: 6, permission_id: 2 },
        { role_id: 6, permission_id: 3 },
        { role_id: 6, permission_id: 4 },
        { role_id: 6, permission_id: 5 },
        { role_id: 6, permission_id: 6 },
        { role_id: 6, permission_id: 7 },
        { role_id: 6, permission_id: 8 },
        { role_id: 6, permission_id: 9 },
        { role_id: 6, permission_id: 10 },
        { role_id: 6, permission_id: 11 },
        { role_id: 6, permission_id: 12 },
        { role_id: 6, permission_id: 13 },
        { role_id: 6, permission_id: 14 },
        { role_id: 6, permission_id: 15 },
        { role_id: 6, permission_id: 16 },
        { role_id: 6, permission_id: 17 },
        { role_id: 6, permission_id: 18 },
        { role_id: 6, permission_id: 20 },
        { role_id: 6, permission_id: 21 },
        { role_id: 6, permission_id: 22 },
        { role_id: 6, permission_id: 23 },
        { role_id: 6, permission_id: 24 },
        { role_id: 6, permission_id: 25 },
        { role_id: 6, permission_id: 26 },
        { role_id: 6, permission_id: 27 },
        // Production - ALL Permissions
        { role_id: 7, permission_id: 1 },
        { role_id: 7, permission_id: 2 },
        { role_id: 7, permission_id: 3 },
        { role_id: 7, permission_id: 4 },
        { role_id: 7, permission_id: 5 },
        { role_id: 7, permission_id: 6 },
        { role_id: 7, permission_id: 7 },
        { role_id: 7, permission_id: 8 },
        { role_id: 7, permission_id: 9 },
        { role_id: 7, permission_id: 10 },
        { role_id: 7, permission_id: 11 },
        { role_id: 7, permission_id: 12 },
        { role_id: 7, permission_id: 13 },
        { role_id: 7, permission_id: 14 },
        { role_id: 7, permission_id: 15 },
        { role_id: 7, permission_id: 16 },
        { role_id: 7, permission_id: 17 },
        { role_id: 7, permission_id: 18 },
        { role_id: 7, permission_id: 20 },
        { role_id: 7, permission_id: 21 },
        { role_id: 7, permission_id: 22 },
        { role_id: 7, permission_id: 23 },
        { role_id: 7, permission_id: 24 },
        { role_id: 7, permission_id: 25 },
        { role_id: 7, permission_id: 26 },
        { role_id: 7, permission_id: 27 },
      ];
      await db.collection("role_permissions").insertMany(rolePermissionsData);
      console.log("✅ Role Permissions collection initialized");
    } else {
      // Ensure labour and cost viewing permissions are added to existing roles
      const rolePermissionsCollection = db.collection("role_permissions");

      // First, remove all existing Production role permissions to ensure clean state
      await rolePermissionsCollection.deleteMany({ role_id: 7 });

      // Add permissions for Production role (7)
      const productionPermissions = [
        { role_id: 7, permission_id: 1 }, // dashboard_view
        { role_id: 7, permission_id: 2 }, // rm_view
        { role_id: 7, permission_id: 3 }, // rm_add
        { role_id: 7, permission_id: 4 }, // rm_edit
        { role_id: 7, permission_id: 5 }, // recipe_view (limited display)
        { role_id: 7, permission_id: 8 }, // category_view
        { role_id: 7, permission_id: 9 }, // category_add
        { role_id: 7, permission_id: 10 }, // subcategory_view
        { role_id: 7, permission_id: 11 }, // subcategory_add
        { role_id: 7, permission_id: 12 }, // unit_view
        { role_id: 7, permission_id: 13 }, // unit_add
        { role_id: 7, permission_id: 24 }, // rmc_view_prices
        { role_id: 7, permission_id: 27 }, // opcost_view
      ];

      if (productionPermissions.length > 0) {
        await rolePermissionsCollection.insertMany(productionPermissions);
        console.log(
          `✅ Production role permissions inserted (${productionPermissions.length} permissions)`,
        );
      }

      // Ensure all roles have ALL permissions (batch operation)
      const allRoleIds = [1, 2, 3, 4, 5, 6, 7];
      const allPermissionIds = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21,
        22, 23, 24, 25, 26, 27,
      ];

      const allRolePermissions = [];
      for (const roleId of allRoleIds) {
        for (const permId of allPermissionIds) {
          allRolePermissions.push({ role_id: roleId, permission_id: permId });
        }
      }

      // Use bulkWrite for efficiency instead of individual updates
      if (allRolePermissions.length > 0) {
        const bulkOps = allRolePermissions.map((rp) => ({
          updateOne: {
            filter: { role_id: rp.role_id, permission_id: rp.permission_id },
            update: { $setOnInsert: rp },
            upsert: true,
          },
        }));

        // Process in batches of 1000 to avoid overwhelming the database
        for (let i = 0; i < bulkOps.length; i += 1000) {
          await rolePermissionsCollection.bulkWrite(bulkOps.slice(i, i + 1000));
        }
      }

      // Ensure Production role exists in roles collection
      const rolesCollection = db.collection("roles");
      await rolesCollection.updateOne(
        { role_id: 7 },
        { $setOnInsert: { role_id: 7, role_name: "Production" } },
        { upsert: true },
      );

      console.log("✅ All permissions ensured for all roles");
    }

    // Create users collection if it doesn't exist
    if (!collectionNames.includes("users")) {
      await db.createCollection("users");
    }

    // Ensure default admin user exists with correct structure
    const defaultUser = await db.collection("users").findOne({
      username: "admin",
    });

    if (!defaultUser) {
      // Create a default admin user with role_id 1 (Super Admin)
      await db.collection("users").insertOne({
        username: "admin",
        password: await hashPassword("admin123"),
        email: "admin@faction.local",
        role_id: 1,
        status: "active",
        createdAt: new Date(),
      });
      console.log(
        "✅ Default admin user created with credentials: admin / admin123",
      );
    } else {
      // Update existing user to ensure correct password and role_id
      await db.collection("users").updateOne(
        { username: "admin" },
        {
          $set: { role_id: 1, status: "active", email: "admin@faction.local" },
        },
      );
      console.log(
        "✅ Default admin user updated with credentials: admin / admin123",
      );
    }

    // Ensure Hardik user exists with Cost Viewer role
    const hardikUser = await db.collection("users").findOne({
      username: "Hardik",
    });

    if (!hardikUser) {
      // Create Hardik user with role_id 6 (Cost Viewer)
      const result = await db.collection("users").insertOne({
        username: "Hardik",
        password: await hashPassword("123"),
        email: "hardik@faction.local",
        role_id: 6,
        status: "active",
        createdAt: new Date(),
      });
      console.log(
        "✅ Hardik user created with credentials: Hardik / 123 (Cost Viewer role)",
      );

      // Add modules for Hardik user
      const hardikUserId = result.insertedId.toString();
      const hardikModules = [
        { user_id: hardikUserId, module_key: "DASHBOARD" },
        { user_id: hardikUserId, module_key: "CATEGORY_UNIT" },
        { user_id: hardikUserId, module_key: "RAW_MATERIAL" },
        { user_id: hardikUserId, module_key: "RAW_MATERIAL_COSTING" },
        { user_id: hardikUserId, module_key: "LABOUR" },
        { user_id: hardikUserId, module_key: "OP_COST" },
      ];
      await db.collection("user_modules").insertMany(hardikModules);
      console.log("✅ Modules assigned to Hardik user");
    } else {
      // Update existing Hardik user to ensure correct password and role_id
      await db.collection("users").updateOne(
        { username: "Hardik" },
        {
          $set: { role_id: 6, status: "active", email: "hardik@faction.local" },
        },
      );
      console.log(
        "✅ Hardik user updated with credentials: Hardik / 123 (Cost Viewer role)",
      );
    }

    // Ensure Production user exists with Production role
    const productionUser = await db.collection("users").findOne({
      username: "Production",
    });

    if (!productionUser) {
      // Create Production user with role_id 7 (Production)
      const result = await db.collection("users").insertOne({
        username: "Production",
        password: await hashPassword("Hanuram@"),
        email: "production@faction.local",
        role_id: 7,
        status: "active",
        createdAt: new Date(),
      });
      console.log(
        "✅ Production user created with credentials: Production / Hanuram@ (Production role)",
      );

      // Add modules for Production user
      const productionUserId = result.insertedId.toString();
      const productionModules = [
        { user_id: productionUserId, module_key: "DASHBOARD" },
        { user_id: productionUserId, module_key: "CATEGORY_UNIT" },
        { user_id: productionUserId, module_key: "RAW_MATERIAL" },
        { user_id: productionUserId, module_key: "RAW_MATERIAL_COSTING" },
        { user_id: productionUserId, module_key: "LABOUR" },
        { user_id: productionUserId, module_key: "OP_COST" },
      ];
      await db.collection("user_modules").insertMany(productionModules);
      console.log("✅ Modules assigned to Production user");
    } else {
      // Update existing Production user to ensure correct password and role_id
      await db.collection("users").updateOne(
        { username: "Production" },
        {
          $set: { role_id: 7, status: "active", email: "production@faction.local" },
        },
      );
      console.log(
        "✅ Production user updated with credentials: Production / Hanuram@ (Production role)",
      );

      // Ensure all modules are assigned to Production user
      const productionUserDoc = await db.collection("users").findOne({
        username: "Production",
      });
      if (productionUserDoc) {
        const productionUserId = productionUserDoc._id.toString();
        const requiredModules = [
          "DASHBOARD",
          "CATEGORY_UNIT",
          "RAW_MATERIAL",
          "RAW_MATERIAL_COSTING",
          "LABOUR",
          "OP_COST",
        ];

        for (const moduleKey of requiredModules) {
          await db.collection("user_modules").updateOne(
            { user_id: productionUserId, module_key: moduleKey },
            {
              $setOnInsert: {
                user_id: productionUserId,
                module_key: moduleKey,
              },
            },
            { upsert: true },
          );
        }
      }
    }

    // Ensure itandit user exists for data entry (Category, Sub Category, Unit, Vendor, Raw Material)
    const itanditUser = await db.collection("users").findOne({
      username: "itandit",
    });

    if (!itanditUser) {
      // Create itandit user with role_id 3 (Data Entry/Vendor)
      const result = await db.collection("users").insertOne({
        username: "itandit",
        password: await hashPassword("itandit@123"),
        email: "itandit@faction.local",
        role_id: 3,
        status: "active",
        createdAt: new Date(),
      });
      console.log(
        "✅ itandit user created with credentials: itandit / itandit@123 (Data Entry role)",
      );

      // Add modules for itandit user
      const itanditUserId = result.insertedId.toString();
      const itanditModules = [
        { user_id: itanditUserId, module_key: "DASHBOARD" },
        { user_id: itanditUserId, module_key: "CATEGORY_UNIT" },
        { user_id: itanditUserId, module_key: "RAW_MATERIAL" },
        { user_id: itanditUserId, module_key: "RAW_MATERIAL_COSTING" },
        { user_id: itanditUserId, module_key: "LABOUR" },
        { user_id: itanditUserId, module_key: "OP_COST" },
      ];
      await db.collection("user_modules").insertMany(itanditModules);
      console.log("✅ Modules assigned to itandit user");
    } else {
      // Update existing itandit user to ensure correct password and role_id
      await db.collection("users").updateOne(
        { username: "itandit" },
        {
          $set: { role_id: 3, status: "active", email: "itandit@faction.local" },
        },
      );
      console.log(
        "✅ itandit user updated with credentials: itandit / itandit@123 (Data Entry role)",
      );

      // Ensure required modules are assigned to itandit user
      const itanditUserDoc = await db.collection("users").findOne({
        username: "itandit",
      });
      if (itanditUserDoc) {
        const itanditUserId = itanditUserDoc._id.toString();
        const requiredModules = ["CATEGORY_UNIT", "RAW_MATERIAL"];

        for (const moduleKey of requiredModules) {
          await db.collection("user_modules").updateOne(
            { user_id: itanditUserId, module_key: moduleKey },
            {
              $setOnInsert: {
                user_id: itanditUserId,
                module_key: moduleKey,
              },
            },
            { upsert: true },
          );
        }
        console.log("✅ itandit user modules ensured");
      }
    }

    // Create categories collection
    if (!collectionNames.includes("categories")) {
      await db.createCollection("categories");
      // Create unique index on category name
      await db
        .collection("categories")
        .createIndex({ name: 1 }, { unique: true });
      console.log("✅ Categories collection initialized");
    } else {
      // Fix existing categories that have missing/null status
      const catResult = await db.collection("categories").updateMany(
        { status: { $exists: false } },
        { $set: { status: "active" } }
      );
      if (catResult.modifiedCount > 0)
        console.log(`✅ Fixed ${catResult.modifiedCount} categories with missing status → active`);
    }

    // Create subcategories collection
    if (!collectionNames.includes("subcategories")) {
      await db.createCollection("subcategories");
      // Create unique index on subcategory name within a category
      await db
        .collection("subcategories")
        .createIndex({ name: 1 }, { unique: true });
      console.log("✅ SubCategories collection initialized");
    } else {
      // Fix existing subcategories that have missing/null status
      const subResult = await db.collection("subcategories").updateMany(
        { status: { $exists: false } },
        { $set: { status: "active" } }
      );
      if (subResult.modifiedCount > 0)
        console.log(`✅ Fixed ${subResult.modifiedCount} subcategories with missing status → active`);
    }

    // Create units collection
    if (!collectionNames.includes("units")) {
      await db.createCollection("units");
      // Create unique index on unit name
      await db.collection("units").createIndex({ name: 1 }, { unique: true });
      console.log("✅ Units collection initialized");
    } else {
      // Fix existing units that have missing/null status
      const unitResult = await db.collection("units").updateMany(
        { status: { $exists: false } },
        { $set: { status: "active" } }
      );
      if (unitResult.modifiedCount > 0)
        console.log(`✅ Fixed ${unitResult.modifiedCount} units with missing status → active`);

      // Fix existing labour records missing editLog
      const labourResult = await db.collection("labour").updateMany(
        { editLog: { $exists: false } },
        { $set: { editLog: [], createdBy: "admin" } }
      );
      if (labourResult.modifiedCount > 0)
        console.log(`✅ Fixed ${labourResult.modifiedCount} labour records with missing editLog`);
    }

    // Create vendors collection
    if (!collectionNames.includes("vendors")) {
      await db.createCollection("vendors");
      // Create unique index on vendor name
      await db.collection("vendors").createIndex({ name: 1 }, { unique: true });
      console.log("✅ Vendors collection initialized");
    }

    // Create raw materials collection
    if (!collectionNames.includes("raw_materials")) {
      await db.createCollection("raw_materials");
      // Create unique index on RM code
      await db
        .collection("raw_materials")
        .createIndex({ code: 1 }, { unique: true });
      console.log("✅ Raw Materials collection initialized");
    }

    // Create RM vendor prices collection (for price history and vendor-specific pricing)
    if (!collectionNames.includes("rm_vendor_prices")) {
      await db.createCollection("rm_vendor_prices");
      console.log("✅ RM Vendor Prices collection initialized");
    }

    // Create RM price logs collection (for price change tracking)
    if (!collectionNames.includes("rm_price_logs")) {
      await db.createCollection("rm_price_logs");
      console.log("✅ RM Price Logs collection initialized");
    }

    // Create RM audit logs collection (for tracking all edits and deletes)
    if (!collectionNames.includes("raw_material_logs")) {
      await db.createCollection("raw_material_logs");
      console.log("✅ Raw Material Logs collection initialized");
    }

    // Create recipes collection
    if (!collectionNames.includes("recipes")) {
      await db.createCollection("recipes");
      // Create unique index on recipe code
      await db.collection("recipes").createIndex({ code: 1 }, { unique: true });
      console.log("✅ Recipes collection initialized");
    }

    // Create recipe items collection (RMs in each recipe)
    if (!collectionNames.includes("recipe_items")) {
      await db.createCollection("recipe_items");
      console.log("✅ Recipe Items collection initialized");
    }

    // Create recipe history collection (snapshots of recipes over time)
    if (!collectionNames.includes("recipe_history")) {
      await db.createCollection("recipe_history");
      console.log("✅ Recipe History collection initialized");
    }

    // Create recipe logs collection (logs for changes in recipes)
    if (!collectionNames.includes("recipe_logs")) {
      await db.createCollection("recipe_logs");
      console.log("✅ Recipe Logs collection initialized");
    }

    // Create quotations collection
    if (!collectionNames.includes("quotations")) {
      await db.createCollection("quotations");
      // Create index on recipe ID for faster queries
      await db.collection("quotations").createIndex({ recipeId: 1 });
      console.log("✅ Quotations collection initialized");
    }

    // Create quotation items collection (RMs in each quotation)
    if (!collectionNames.includes("quotation_items")) {
      await db.createCollection("quotation_items");
      // Create index on quotation ID
      await db.collection("quotation_items").createIndex({ quotationId: 1 });
      console.log("✅ Quotation Items collection initialized");
    }

    // Create quotation logs collection (for tracking vendor changes and edits)
    if (!collectionNames.includes("quotation_logs")) {
      await db.createCollection("quotation_logs");
      // Create index on quotation ID
      await db.collection("quotation_logs").createIndex({ quotationId: 1 });
      console.log("✅ Quotation Logs collection initialized");
    }

    // Create app_data collection if it doesn't exist
    if (!collectionNames.includes("app_data")) {
      await db.createCollection("app_data");
      console.log("✅ App data collection initialized");
    }

    // Create user_modules collection for module-based access control
    if (!collectionNames.includes("user_modules")) {
      await db.createCollection("user_modules");
      // Get the admin user's ObjectId for module assignment
      const adminUser = await db.collection("users").findOne({
        username: "admin",
      });
      if (adminUser) {
        const adminUserId = adminUser._id.toString();
        // Initialize with admin user having all modules
        const adminUserModules = [
          { user_id: adminUserId, module_key: "DASHBOARD" },
          { user_id: adminUserId, module_key: "CATEGORY_UNIT" },
          { user_id: adminUserId, module_key: "RAW_MATERIAL" },
          { user_id: adminUserId, module_key: "LABOUR" },
          { user_id: adminUserId, module_key: "RAW_MATERIAL_COSTING" },
          { user_id: adminUserId, module_key: "OP_COST" },
        ] as any[];
        await db.collection("user_modules").insertMany(adminUserModules);
        console.log(
          "✅ User modules collection initialized with admin modules",
        );
      }
    } else {
      // Ensure all required modules exist for admin user
      const adminUser = await db.collection("users").findOne({
        username: "admin",
      });
      if (adminUser) {
        const adminUserId = adminUser._id.toString();
        const requiredModules = [
          "DASHBOARD",
          "CATEGORY_UNIT",
          "RAW_MATERIAL",
          "LABOUR",
          "RAW_MATERIAL_COSTING",
          "OP_COST",
        ];
        const userModulesCollection = db.collection("user_modules");
        for (const moduleKey of requiredModules) {
          await userModulesCollection.updateOne(
            { user_id: adminUserId, module_key: moduleKey },
            {
              $setOnInsert: {
                user_id: adminUserId,
                module_key: moduleKey,
              },
            },
            { upsert: true },
          );
        }
        console.log("✅ Admin user modules ensured");
      }
    }

    // Create labour collection for factory labour management
    if (!collectionNames.includes("labour")) {
      await db.createCollection("labour");
      // Create unique index on labour code
      await db.collection("labour").createIndex({ code: 1 }, { unique: true });
      console.log("✅ Labour collection initialized");
    }

    // Create recipe labour collection (linking labour to recipes)
    if (!collectionNames.includes("recipe_labour")) {
      await db.createCollection("recipe_labour");
      // Create index on recipe ID for faster queries
      await db.collection("recipe_labour").createIndex({ recipeId: 1 });
      console.log("✅ Recipe Labour collection initialized");
    }

    // Create recipe packaging costs collection
    if (!collectionNames.includes("recipe_packaging_costs")) {
      await db.createCollection("recipe_packaging_costs");
      // Create unique index on recipe ID
      await db
        .collection("recipe_packaging_costs")
        .createIndex({ recipeId: 1 }, { unique: true });
      console.log("✅ Recipe Packaging Costs collection initialized");
    }
  } catch (error) {
    console.error("Error initializing collections:", error);
  }
}

export function getDB(): Db | null {
  return db;
}

export function getConnectionStatus(): string {
  return connectionStatus;
}

export async function disconnectDB(): Promise<void> {
  if (client) {
    await client.close();
    client = null;
    db = null;
    connectionStatus = "disconnected";
    console.log("Disconnected from MongoDB");
  }
}


