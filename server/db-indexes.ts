import { Db } from "mongodb";

/**
 * Create all necessary database indexes for optimal query performance
 * This should be called after database connection is established
 */
export async function createDatabaseIndexes(db: Db): Promise<void> {
  try {
    console.log("📊 Creating database indexes for performance optimization...");

    // Recipe indexes
    await db.collection("recipes").createIndex({ updatedAt: -1 });
    await db.collection("recipes").createIndex({ code: 1 }, { unique: true });
    console.log("✅ Recipe indexes created");

    // Recipe items indexes
    await db.collection("recipe_items").createIndex({ recipeId: 1 });
    await db.collection("recipe_items").createIndex({ rawMaterialId: 1 });
    await db.collection("recipe_items").createIndex({ recipeId: 1, rawMaterialId: 1 });
    console.log("✅ Recipe items indexes created");

    // Raw materials indexes
    await db.collection("raw_materials").createIndex({ code: 1 }, { unique: true });
    await db.collection("raw_materials").createIndex({ categoryId: 1 });
    await db.collection("raw_materials").createIndex({ subCategoryId: 1 });
    await db.collection("raw_materials").createIndex({ is_deleted: 1 });
    await db.collection("raw_materials").createIndex({ updatedAt: -1 });
    console.log("✅ Raw materials indexes created");

    // Vendor prices indexes
    await db.collection("rm_vendor_prices").createIndex({ rawMaterialId: 1 });
    await db.collection("rm_vendor_prices").createIndex({ vendorId: 1 });
    await db.collection("rm_vendor_prices").createIndex({ rawMaterialId: 1, addedDate: -1 });
    console.log("✅ Vendor prices indexes created");

    // Quotations indexes
    await db.collection("quotations").createIndex({ recipeId: 1 });
    await db.collection("quotations").createIndex({ createdAt: -1 });
    await db.collection("quotations").createIndex({ recipeId: 1, createdAt: -1 });
    console.log("✅ Quotations indexes created");

    // Quotation items indexes
    await db.collection("quotation_items").createIndex({ quotationId: 1 });
    await db.collection("quotation_items").createIndex({ rawMaterialId: 1 });
    console.log("✅ Quotation items indexes created");

    // Recipe history indexes
    await db.collection("recipe_history").createIndex({ recipeId: 1 });
    await db.collection("recipe_history").createIndex({ recipeId: 1, snapshotDate: -1 });
    console.log("✅ Recipe history indexes created");

    // Recipe logs indexes
    await db.collection("recipe_logs").createIndex({ recipeId: 1 });
    await db.collection("recipe_logs").createIndex({ recipeId: 1, changeDate: -1 });
    console.log("✅ Recipe logs indexes created");

    // Labour indexes
    await db.collection("labour").createIndex({ recipeId: 1 });
    await db.collection("labour").createIndex({ type: 1 });
    await db.collection("labour").createIndex({ recipeId: 1, type: 1 });
    console.log("✅ Labour indexes created");

    // Packaging costs indexes
    await db.collection("packaging_costs").createIndex({ recipeId: 1 }, { unique: true });
    console.log("✅ Packaging costs indexes created");

    console.log("✅ All database indexes created successfully!");
  } catch (error) {
    console.error("❌ Error creating database indexes:", error);
    // Don't throw - indexes are nice to have but not critical
  }
}
