import { RequestHandler } from "express";
import { getDB, getConnectionStatus } from "../db";
import { ObjectId } from "mongodb";

export interface RecipeItem {
  _id?: ObjectId;
  recipeId: string;
  rawMaterialId: string;
  rawMaterialName: string;
  rawMaterialCode: string;
  quantity: number;
  unitId?: string;
  unitName?: string;
  price: number;
  vendorId?: string;
  vendorName?: string;
  moisturePercentage?: number;
  yield?: number; // in kg or liter
  totalPrice: number; // quantity * price
}

export interface Recipe {
  _id?: ObjectId;
  code: string;
  name: string;
  recipeType?: string; // "master" or "sub"
  batchSize: number;
  unitId: string;
  unitName: string;
  yield?: number;
  moisturePercentage?: number;
  totalRawMaterialCost: number;
  pricePerUnit: number; // totalCost / yield
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
}

export interface RecipeHistory {
  _id?: ObjectId;
  recipeId: string;
  recipeCode: string;
  recipeName: string;
  snapshotDate: Date;
  totalRawMaterialCost: number;
  pricePerUnit: number;
  items: RecipeItem[];
  createdReason?: string; // "initial_creation" | "price_change" | "manual_update"
  changedBy: string;
}

export interface RecipeLog {
  _id?: ObjectId;
  recipeId: string;
  recipeItemId?: string;
  rawMaterialId?: string;
  fieldChanged: string; // "quantity", "price", "moisture", "yield", "batch_size", "unit"
  oldValue: any;
  newValue: any;
  changeDate: Date;
  changedBy: string;
  recipeCode: string;
}

// Get next Recipe code
const getNextRecipeCode = async (db: any): Promise<string> => {
  const appData = await db
    .collection("app_data")
    .findOne({ key: "recipe_counter" });

  let nextNumber = 1;
  if (appData && appData.value) {
    nextNumber = appData.value + 1;
  }

  await db
    .collection("app_data")
    .updateOne(
      { key: "recipe_counter" },
      { $set: { value: nextNumber } },
      { upsert: true },
    );

  return `RES${String(nextNumber).padStart(3, "0")}`;
};

// Calculate recipe totals
const calculateRecipeTotals = (items: RecipeItem[], yieldValue: number) => {
  const totalCost = items.reduce(
    (sum, item) => sum + (item.totalPrice || 0),
    0,
  );
  const pricePerUnit = yieldValue > 0 ? totalCost / yieldValue : 0;

  return {
    totalRawMaterialCost: totalCost,
    pricePerUnit: parseFloat(pricePerUnit.toFixed(2)),
  };
};

// GET all recipes with pagination
export const handleGetRecipes: RequestHandler = async (req, res) => {
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

    // Get pagination parameters from query
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(100, parseInt(req.query.limit as string) || 50);
    const skip = (page - 1) * limit;

    // Get total count for pagination
    const total = await db.collection("recipes").countDocuments();

    // Fetch paginated recipes
    const recipes = await db
      .collection("recipes")
      .find({})
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    res.json({
      success: true,
      data: recipes,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching recipes:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// POST create recipe
export const handleCreateRecipe: RequestHandler = async (req, res) => {
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

    const {
      name,
      recipeType,
      batchSize,
      unitId,
      unitName,
      yield: yieldValue,
      moisturePercentage,
      items,
      createdBy,
    } = req.body;

    // Validate required fields
    if (
      !name ||
      !batchSize ||
      !unitId ||
      !yieldValue ||
      !items ||
      items.length === 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Name, batch size, unit, and at least one raw material are required",
      });
    }

    const code = await getNextRecipeCode(db);

    // Process items - ensure they have calculated values
    const processedItems: RecipeItem[] = items.map((item: any) => ({
      ...item,
      totalPrice: item.quantity * item.price,
    }));

    // Calculate totals
    const { totalRawMaterialCost, pricePerUnit } = calculateRecipeTotals(
      processedItems,
      yieldValue,
    );

    const newRecipe: Recipe = {
      code,
      name,
      recipeType: recipeType || "master",
      batchSize,
      unitId,
      unitName,
      yield: yieldValue,
      moisturePercentage,
      totalRawMaterialCost,
      pricePerUnit,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy,
    };

    // Insert recipe
    const recipeResult = await db.collection("recipes").insertOne(newRecipe);
    const recipeId = recipeResult.insertedId.toString();

    // Insert recipe items
    const itemsWithRecipeId = processedItems.map((item: any) => ({
      ...item,
      recipeId,
    }));

    await db.collection("recipe_items").insertMany(itemsWithRecipeId);

    // Create initial history snapshot
    const historySnapshot: RecipeHistory = {
      recipeId,
      recipeCode: code,
      recipeName: name,
      snapshotDate: new Date(),
      totalRawMaterialCost,
      pricePerUnit,
      items: processedItems,
      createdReason: "initial_creation",
      changedBy: createdBy,
    };

    await db.collection("recipe_history").insertOne(historySnapshot);

    res.status(201).json({
      success: true,
      message: "Recipe created successfully",
      data: {
        ...newRecipe,
        _id: recipeResult.insertedId,
        items: processedItems,
      },
    });
  } catch (error) {
    console.error("Error creating recipe:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// PUT update recipe
export const handleUpdateRecipe: RequestHandler = async (req, res) => {
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

    const { id } = req.params;
    const {
      name,
      recipeType,
      batchSize,
      unitId,
      unitName,
      yield: yieldValue,
      moisturePercentage,
      items,
      createdBy,
      productionLabourCostPerKg,
      packingLabourCostPerKg,
    } = req.body;

    // Get existing recipe for logging
    const existingRecipe = await db
      .collection("recipes")
      .findOne({ _id: new ObjectId(id as string) });

    if (!existingRecipe) {
      return res
        .status(404)
        .json({ success: false, message: "Recipe not found" });
    }

    // Process new items
    const processedItems: RecipeItem[] = items.map((item: any) => ({
      ...item,
      recipeId: id,
      totalPrice: item.quantity * item.price,
    }));

    // Calculate new totals
    const { totalRawMaterialCost, pricePerUnit } = calculateRecipeTotals(
      processedItems,
      yieldValue,
    );

    // Log changes for batch size or unit
    if (existingRecipe.batchSize !== batchSize) {
      await db.collection("recipe_logs").insertOne({
        recipeId: id,
        fieldChanged: "batch_size",
        oldValue: existingRecipe.batchSize,
        newValue: batchSize,
        changeDate: new Date(),
        changedBy: createdBy,
        recipeCode: existingRecipe.code,
      });
    }

    if (existingRecipe.unitId !== unitId) {
      await db.collection("recipe_logs").insertOne({
        recipeId: id,
        fieldChanged: "unit",
        oldValue: existingRecipe.unitName,
        newValue: unitName,
        changeDate: new Date(),
        changedBy: createdBy,
        recipeCode: existingRecipe.code,
      });
    }

    if (existingRecipe.yield !== yieldValue) {
      await db.collection("recipe_logs").insertOne({
        recipeId: id,
        fieldChanged: "yield",
        oldValue: existingRecipe.yield,
        newValue: yieldValue,
        changeDate: new Date(),
        changedBy: createdBy,
        recipeCode: existingRecipe.code,
      });
    }

    if (existingRecipe.moisturePercentage !== moisturePercentage) {
      await db.collection("recipe_logs").insertOne({
        recipeId: id,
        fieldChanged: "moisture",
        oldValue: existingRecipe.moisturePercentage,
        newValue: moisturePercentage,
        changeDate: new Date(),
        changedBy: createdBy,
        recipeCode: existingRecipe.code,
      });
    }

    // Fetch existing items to detect item-level changes
    const existingItems = await db
      .collection("recipe_items")
      .find({ recipeId: id })
      .toArray();

    const existingMap: Record<string, any> = {};
    existingItems.forEach((it: any) => {
      existingMap[it.rawMaterialId] = it;
    });

    // Detect added or updated items
    for (const newItem of processedItems) {
      const existingItem = existingMap[newItem.rawMaterialId];
      if (existingItem) {
        // Compare fields for changes
        const fieldsToCheck: Array<{ key: string; label: string }> = [
          { key: "quantity", label: "quantity" },
          { key: "price", label: "price" },
          { key: "moisturePercentage", label: "moisture" },
          { key: "yield", label: "yield" },
        ];

        for (const f of fieldsToCheck) {
          const oldVal = existingItem[f.key];
          const newVal = (newItem as any)[f.key];
          // Normalize undefined -> null for comparison
          if ((oldVal ?? null) !== (newVal ?? null)) {
            await db.collection("recipe_logs").insertOne({
              recipeId: id,
              recipeItemId: existingItem._id
                ? existingItem._id.toString()
                : undefined,
              rawMaterialId: newItem.rawMaterialId,
              fieldChanged: f.key,
              oldValue: oldVal,
              newValue: newVal,
              changeDate: new Date(),
              changedBy: createdBy,
              recipeCode: existingRecipe.code,
            });
          }
        }

        // Mark as processed
        delete existingMap[newItem.rawMaterialId];
      } else {
        // Item added
        await db.collection("recipe_logs").insertOne({
          recipeId: id,
          rawMaterialId: newItem.rawMaterialId,
          fieldChanged: "item_added",
          oldValue: null,
          newValue: newItem,
          changeDate: new Date(),
          changedBy: createdBy,
          recipeCode: existingRecipe.code,
        });
      }
    }

    // Remaining keys in existingMap are removed items
    for (const removedKey of Object.keys(existingMap)) {
      const removedItem = existingMap[removedKey];
      await db.collection("recipe_logs").insertOne({
        recipeId: id,
        recipeItemId: removedItem._id ? removedItem._id.toString() : undefined,
        rawMaterialId: removedItem.rawMaterialId,
        fieldChanged: "item_removed",
        oldValue: removedItem,
        newValue: null,
        changeDate: new Date(),
        changedBy: createdBy,
        recipeCode: existingRecipe.code,
      });
    }

    // Replace recipe items
    await db.collection("recipe_items").deleteMany({ recipeId: id });
    await db.collection("recipe_items").insertMany(processedItems);

    // Update recipe
    const updateData = {
      name,
      recipeType: recipeType || "master",
      batchSize,
      unitId,
      unitName,
      yield: yieldValue,
      moisturePercentage,
      totalRawMaterialCost,
      pricePerUnit,
      productionLabourCostPerKg: productionLabourCostPerKg ?? 0,
      packingLabourCostPerKg: packingLabourCostPerKg ?? 0,
      updatedAt: new Date(),
    };

    await db
      .collection("recipes")
      .updateOne({ _id: new ObjectId(id as string) }, { $set: updateData });

    // Create history snapshot
    const historySnapshot: RecipeHistory = {
      recipeId: id as string,
      recipeCode: existingRecipe.code,
      recipeName: name,
      snapshotDate: new Date(),
      totalRawMaterialCost,
      pricePerUnit,
      items: processedItems,
      createdReason: "manual_update",
      changedBy: createdBy,
    };

    await db.collection("recipe_history").insertOne(historySnapshot);

    res.json({
      success: true,
      message: "Recipe updated successfully",
      data: { ...existingRecipe, ...updateData, items: processedItems },
    });
  } catch (error) {
    console.error("Error updating recipe:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// PATCH labour cost per kg
export const handlePatchLabourCost: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res.status(503).json({ success: false, message: "Database not connected" });
  }
  try {
    const db = getDB();
    if (!db) return res.status(503).json({ success: false, message: "Database error" });
    const { id } = req.params;
    const { productionLabourCostPerKg, packingLabourCostPerKg } = req.body;
    const update: Record<string, number> = {};
    if (productionLabourCostPerKg !== undefined) update.productionLabourCostPerKg = productionLabourCostPerKg;
    if (packingLabourCostPerKg !== undefined) update.packingLabourCostPerKg = packingLabourCostPerKg;
    await db.collection("recipes").updateOne({ _id: new ObjectId(id as string) }, { $set: update });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE recipe
export const handleDeleteRecipe: RequestHandler = async (req, res) => {
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

    const { id } = req.params;

    const result = await db
      .collection("recipes")
      .deleteOne({ _id: new ObjectId(id as string) });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Recipe not found" });
    }

    // Delete related data
    await db.collection("recipe_items").deleteMany({ recipeId: id });
    await db.collection("recipe_history").deleteMany({ recipeId: id });
    await db.collection("recipe_logs").deleteMany({ recipeId: id });

    res.json({
      success: true,
      message: "Recipe deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting recipe:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// GET recipe items
export const handleGetRecipeItems: RequestHandler = async (req, res) => {
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

    const { recipeId } = req.params;

    const items = await db
      .collection("recipe_items")
      .find({ recipeId })
      .toArray();

    res.json({ success: true, data: items });
  } catch (error) {
    console.error("Error fetching recipe items:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// GET recipe history
export const handleGetRecipeHistory: RequestHandler = async (req, res) => {
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

    const { recipeId } = req.params;

    const history = await db
      .collection("recipe_history")
      .find({ recipeId })
      .sort({ snapshotDate: -1 })
      .toArray();

    res.json({ success: true, data: history });
  } catch (error) {
    console.error("Error fetching recipe history:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE recipe history entry
export const handleDeleteRecipeHistory: RequestHandler = async (req, res) => {
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

    const { recipeId, historyId } = req.params;

    const result = await db
      .collection("recipe_history")
      .deleteOne({ _id: new ObjectId(historyId), recipeId });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "History entry not found" });
    }

    res.json({ success: true, message: "History entry deleted successfully" });
  } catch (error) {
    console.error("Error deleting recipe history:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// GET recipe logs
export const handleGetRecipeLogs: RequestHandler = async (req, res) => {
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

    const { recipeId } = req.params;

    const logs = await db
      .collection("recipe_logs")
      .find({ recipeId })
      .sort({ changeDate: -1 })
      .toArray();

    res.json({ success: true, data: logs });
  } catch (error) {
    console.error("Error fetching recipe logs:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Create recipe history snapshot (called when RM price changes globally)
export const handleCreateRecipeSnapshot: RequestHandler = async (req, res) => {
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

    const { recipeId, reason, changedBy } = req.body;

    // Get current recipe and items
    const recipe = await db
      .collection("recipes")
      .findOne({ _id: new ObjectId(recipeId) });

    if (!recipe) {
      return res
        .status(404)
        .json({ success: false, message: "Recipe not found" });
    }

    const items = await db
      .collection("recipe_items")
      .find({ recipeId })
      .toArray();

    // Create snapshot
    const snapshot: RecipeHistory = {
      recipeId,
      recipeCode: recipe.code,
      recipeName: recipe.name,
      snapshotDate: new Date(),
      totalRawMaterialCost: recipe.totalRawMaterialCost,
      pricePerUnit: recipe.pricePerUnit,
      items: items as RecipeItem[],
      createdReason: reason || "price_change",
      changedBy,
    };

    const result = await db.collection("recipe_history").insertOne(snapshot);

    res.status(201).json({
      success: true,
      message: "Recipe snapshot created",
      data: { ...snapshot, _id: result.insertedId },
    });
  } catch (error) {
    console.error("Error creating recipe snapshot:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Handle GET packaging costs for a recipe
export const handleGetPackagingCosts: RequestHandler = async (req, res) => {
  try {
    const { recipeId } = req.params;
    const db = getDB();
    if (!db) {
      return res.status(500).json({ success: false, message: "Database not connected" });
    }

    const packagingCost = await db.collection("recipe_packaging_costs").findOne({
      recipeId: recipeId,
    });

    if (!packagingCost) {
      return res.json({
        success: true,
        data: null,
      });
    }

    res.json({
      success: true,
      data: packagingCost,
    });
  } catch (error) {
    console.error("Error fetching packaging costs:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Handle POST packaging costs for a recipe
export const handleSavePackagingCosts: RequestHandler = async (req, res) => {
  try {
    const { recipeId } = req.params;
    const { inputs, results, totalPackagingHandlingCost } = req.body;
    const db = getDB();
    if (!db) {
      return res.status(500).json({ success: false, message: "Database not connected" });
    }

    // Validate required fields
    if (!recipeId || !inputs || !results) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields: recipeId, inputs, or results",
      });
    }

    const packagingCostData = {
      recipeId: recipeId,
      inputs: inputs,
      results: results,
      totalPackagingHandlingCost: totalPackagingHandlingCost || 0,
      updatedAt: new Date(),
    };

    const result = await db.collection("recipe_packaging_costs").updateOne(
      { recipeId: recipeId },
      { $set: packagingCostData },
      { upsert: true }
    );

    res.json({
      success: true,
      message: "Packaging costs saved successfully",
      data: packagingCostData,
    });
  } catch (error) {
    console.error("Error saving packaging costs:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};
