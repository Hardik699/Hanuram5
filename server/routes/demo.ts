import { RequestHandler } from "express";
import { DemoResponse } from "@shared/api";
import { getDB, getConnectionStatus } from "../db";
import { ObjectId } from "mongodb";

export const handleDemo: RequestHandler = (req, res) => {
  const response: DemoResponse = {
    message: "Hello from Express server",
  };
  res.status(200).json(response);
};

// POST /api/demo/populate-sample-data
export const handlePopulateSampleData: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    // Check if sample recipes already exist (idempotent)
    const existing = await db.collection("recipes").findOne({ name: { $in: ["Fulwadi", "Kaju Katli", "Methi Mathri"] } });
    if (existing) {
      return res.json({ success: true, message: "Sample data already present" });
    }

    // Create units
    const units = [
      { name: "kg" },
      { name: "g" },
      { name: "nos" },
    ];

    const insertedUnits: any[] = [];
    for (const u of units) {
      const r = await db.collection("units").updateOne({ name: u.name }, { $setOnInsert: { name: u.name } }, { upsert: true });
      const doc = await db.collection("units").findOne({ name: u.name });
      insertedUnits.push(doc);
    }

    const unitKg = insertedUnits.find((x) => x.name === "kg");

    // Create categories and subcategories
    const category = { name: "Snacks & Sweets" };
    await db.collection("categories").updateOne({ name: category.name }, { $setOnInsert: category }, { upsert: true });
    const catDoc = await db.collection("categories").findOne({ name: category.name });

    const subcategories = [
      { name: "Namkeen", categoryId: catDoc._id.toString() },
      { name: "Mithai", categoryId: catDoc._id.toString() },
    ];

    for (const s of subcategories) {
      await db.collection("subcategories").updateOne(
        { name: s.name },
        { $setOnInsert: { ...s } },
        { upsert: true },
      );
    }

    const subNamkeen = await db.collection("subcategories").findOne({ name: "Namkeen" });
    const subMithai = await db.collection("subcategories").findOne({ name: "Mithai" });

    // Create vendors
    const vendors = [
      { name: "Local Supplier A", phone: "" },
      { name: "Cashew Supplier", phone: "" },
    ];

    for (const v of vendors) {
      await db.collection("vendors").updateOne({ name: v.name }, { $setOnInsert: v }, { upsert: true });
    }

    const vendorA = await db.collection("vendors").findOne({ name: "Local Supplier A" });
    const vendorCashew = await db.collection("vendors").findOne({ name: "Cashew Supplier" });

    // Create raw materials
    const rawMaterials = [
      {
        name: "Besan (Gram Flour)",
        categoryId: catDoc._id.toString(),
        categoryName: catDoc.name,
        subCategoryId: subNamkeen._id.toString(),
        subCategoryName: subNamkeen.name,
        unitId: unitKg._id.toString(),
        unitName: unitKg.name,
        createdBy: "demo",
      },
      {
        name: "Ghee",
        categoryId: catDoc._id.toString(),
        categoryName: catDoc.name,
        subCategoryId: subMithai._id.toString(),
        subCategoryName: subMithai.name,
        unitId: unitKg._id.toString(),
        unitName: unitKg.name,
        createdBy: "demo",
      },
      {
        name: "Sugar",
        categoryId: catDoc._id.toString(),
        categoryName: catDoc.name,
        subCategoryId: subMithai._id.toString(),
        subCategoryName: subMithai.name,
        unitId: unitKg._id.toString(),
        unitName: unitKg.name,
        createdBy: "demo",
      },
      {
        name: "Cashew (Kaju)",
        categoryId: catDoc._id.toString(),
        categoryName: catDoc.name,
        subCategoryId: subMithai._id.toString(),
        subCategoryName: subMithai.name,
        unitId: unitKg._id.toString(),
        unitName: unitKg.name,
        createdBy: "demo",
      },
      {
        name: "Maida (All-purpose Flour)",
        categoryId: catDoc._id.toString(),
        categoryName: catDoc.name,
        subCategoryId: subNamkeen._id.toString(),
        subCategoryName: subNamkeen.name,
        unitId: unitKg._id.toString(),
        unitName: unitKg.name,
        createdBy: "demo",
      },
      {
        name: "Dried Methi (Fenugreek)",
        categoryId: catDoc._id.toString(),
        categoryName: catDoc.name,
        subCategoryId: subNamkeen._id.toString(),
        subCategoryName: subNamkeen.name,
        unitId: unitKg._id.toString(),
        unitName: unitKg.name,
        createdBy: "demo",
      },
      {
        name: "Edible Oil",
        categoryId: catDoc._id.toString(),
        categoryName: catDoc.name,
        subCategoryId: subNamkeen._id.toString(),
        subCategoryName: subNamkeen.name,
        unitId: unitKg._id.toString(),
        unitName: unitKg.name,
        createdBy: "demo",
      },
    ];

    const insertedRMs: any[] = [];
    for (const rm of rawMaterials) {
      const r = await db.collection("raw_materials").updateOne(
        { name: rm.name },
        { $setOnInsert: { ...rm, code: rm.name.slice(0, 3).toUpperCase(), createdAt: new Date(), updatedAt: new Date() } },
        { upsert: true },
      );
      const doc = await db.collection("raw_materials").findOne({ name: rm.name });
      insertedRMs.push(doc);
    }

    // Add vendor prices for raw materials
    const prices = [
      { rmName: "Besan (Gram Flour)", vendor: vendorA, quantity: 25, pricePerUnit: 120 },
      { rmName: "Ghee", vendor: vendorA, quantity: 25, pricePerUnit: 700 },
      { rmName: "Sugar", vendor: vendorA, quantity: 25, pricePerUnit: 40 },
      { rmName: "Cashew (Kaju)", vendor: vendorCashew, quantity: 25, pricePerUnit: 2000 },
      { rmName: "Maida (All-purpose Flour)", vendor: vendorA, quantity: 25, pricePerUnit: 60 },
      { rmName: "Dried Methi (Fenugreek)", vendor: vendorA, quantity: 25, pricePerUnit: 250 },
      { rmName: "Edible Oil", vendor: vendorA, quantity: 25, pricePerUnit: 120 },
    ];

    for (const p of prices) {
      const rmDoc = insertedRMs.find((x) => x.name === p.rmName);
      if (!rmDoc) continue;

      const vendorPrice = {
        rawMaterialId: rmDoc._id.toString(),
        vendorId: p.vendor._id.toString(),
        vendorName: p.vendor.name,
        quantity: p.quantity,
        unitId: unitKg._id.toString(),
        unitName: unitKg.name,
        price: p.pricePerUnit,
        addedDate: new Date(),
        createdBy: "demo",
      };

      await db.collection("rm_vendor_prices").insertOne(vendorPrice);

      // Update last price on RM
      await db.collection("raw_materials").updateOne(
        { _id: rmDoc._id },
        { $set: { lastAddedPrice: p.pricePerUnit, lastVendorName: p.vendor.name, lastPriceDate: new Date(), updatedAt: new Date() } },
      );
    }

    // Create recipes: Fulwadi, Kaju Katli, Methi Mathri
    // Fulwadi
    const besan = insertedRMs.find((x) => x.name === "Besan (Gram Flour)");
    const ghee = insertedRMs.find((x) => x.name === "Ghee");
    const sugar = insertedRMs.find((x) => x.name === "Sugar");

    const recipesToCreate: any[] = [];

    recipesToCreate.push({
      name: "Fulwadi",
      batchSize: 10,
      unitId: unitKg._id.toString(),
      unitName: unitKg.name,
      items: [
        { rawMaterialId: besan._id.toString(), rawMaterialName: besan.name, rawMaterialCode: besan.code, quantity: 6, unitId: unitKg._id.toString(), unitName: unitKg.name, price: besan.lastAddedPrice, totalPrice: 6 * besan.lastAddedPrice, yield: 6 },
        { rawMaterialId: ghee._id.toString(), rawMaterialName: ghee.name, rawMaterialCode: ghee.code, quantity: 1, unitId: unitKg._id.toString(), unitName: unitKg.name, price: ghee.lastAddedPrice, totalPrice: 1 * ghee.lastAddedPrice, yield: 1 },
        { rawMaterialId: sugar._id.toString(), rawMaterialName: sugar.name, rawMaterialCode: sugar.code, quantity: 1, unitId: unitKg._id.toString(), unitName: unitKg.name, price: sugar.lastAddedPrice, totalPrice: 1 * sugar.lastAddedPrice, yield: 1 },
      ],
    });

    // Kaju Katli
    const kaju = insertedRMs.find((x) => x.name === "Cashew (Kaju)");
    recipesToCreate.push({
      name: "Kaju Katli",
      batchSize: 10,
      unitId: unitKg._id.toString(),
      unitName: unitKg.name,
      items: [
        { rawMaterialId: kaju._id.toString(), rawMaterialName: kaju.name, rawMaterialCode: kaju.code, quantity: 6, unitId: unitKg._id.toString(), unitName: unitKg.name, price: kaju.lastAddedPrice, totalPrice: 6 * kaju.lastAddedPrice, yield: 6 },
        { rawMaterialId: sugar._id.toString(), rawMaterialName: sugar.name, rawMaterialCode: sugar.code, quantity: 3, unitId: unitKg._id.toString(), unitName: unitKg.name, price: sugar.lastAddedPrice, totalPrice: 3 * sugar.lastAddedPrice, yield: 3 },
        { rawMaterialId: ghee._id.toString(), rawMaterialName: ghee.name, rawMaterialCode: ghee.code, quantity: 0.5, unitId: unitKg._id.toString(), unitName: unitKg.name, price: ghee.lastAddedPrice, totalPrice: 0.5 * ghee.lastAddedPrice, yield: 0.5 },
      ],
    });

    // Methi Mathri
    const maida = insertedRMs.find((x) => x.name === "Maida (All-purpose Flour)");
    const methi = insertedRMs.find((x) => x.name === "Dried Methi (Fenugreek)");
    const oil = insertedRMs.find((x) => x.name === "Edible Oil");

    recipesToCreate.push({
      name: "Methi Mathri",
      batchSize: 10,
      unitId: unitKg._id.toString(),
      unitName: unitKg.name,
      items: [
        { rawMaterialId: maida._id.toString(), rawMaterialName: maida.name, rawMaterialCode: maida.code, quantity: 6, unitId: unitKg._id.toString(), unitName: unitKg.name, price: maida.lastAddedPrice, totalPrice: 6 * maida.lastAddedPrice, yield: 6 },
        { rawMaterialId: methi._id.toString(), rawMaterialName: methi.name, rawMaterialCode: methi.code, quantity: 0.2, unitId: unitKg._id.toString(), unitName: unitKg.name, price: methi.lastAddedPrice, totalPrice: 0.2 * methi.lastAddedPrice, yield: 0.2 },
        { rawMaterialId: oil._id.toString(), rawMaterialName: oil.name, rawMaterialCode: oil.code, quantity: 1, unitId: unitKg._id.toString(), unitName: unitKg.name, price: oil.lastAddedPrice, totalPrice: 1 * oil.lastAddedPrice, yield: 1 },
      ],
    });

    const createdRecipes: any[] = [];

    for (const r of recipesToCreate) {
      // Use recipes insertion logic similar to route
      // Calculate totals
      const totalRawMaterialCost = r.items.reduce((sum: number, it: any) => sum + (it.totalPrice || 0), 0);
      const pricePerUnit = r.batchSize > 0 ? totalRawMaterialCost / r.batchSize : 0;

      const recipeDoc = {
        code: `RES${Math.floor(Math.random() * 10000)}`,
        name: r.name,
        batchSize: r.batchSize,
        unitId: r.unitId,
        unitName: r.unitName,
        totalRawMaterialCost,
        pricePerUnit: parseFloat(pricePerUnit.toFixed(2)),
        createdAt: new Date(),
        updatedAt: new Date(),
        createdBy: "demo",
      };

      const recipeResult = await db.collection("recipes").insertOne(recipeDoc);
      const recipeId = recipeResult.insertedId.toString();

      const itemsWithRecipeId = r.items.map((it: any) => ({ ...it, recipeId }));
      await db.collection("recipe_items").insertMany(itemsWithRecipeId);

      const historySnapshot = {
        recipeId,
        recipeCode: recipeDoc.code,
        recipeName: recipeDoc.name,
        snapshotDate: new Date(),
        totalRawMaterialCost,
        pricePerUnit: recipeDoc.pricePerUnit,
        items: r.items,
        createdReason: "initial_creation",
        changedBy: "demo",
      };

      await db.collection("recipe_history").insertOne(historySnapshot);

      createdRecipes.push({ ...recipeDoc, _id: recipeResult.insertedId, items: r.items });
    }

    res.json({ success: true, message: "Sample data populated", data: { recipes: createdRecipes } });
  } catch (error) {
    console.error("Error populating sample data:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};
