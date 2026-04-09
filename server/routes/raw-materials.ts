import { RequestHandler } from "express";
// multer and csv-parse are dynamically imported inside the upload handler
import { getDB, getConnectionStatus } from "../db";
import { ObjectId } from "mongodb";

export interface UnitConversion {
  fromUnitId: string;
  fromUnitName: string;
  toUnitId: string;
  toUnitName: string;
  conversionFactor: number; // multiplier: fromUnit * factor = toUnit
  addedAt: Date;
  addedBy: string;
}

export interface RawMaterial {
  _id?: ObjectId;
  code: string;
  name: string;
  categoryId: string;
  categoryName: string;
  subCategoryId: string;
  subCategoryName: string;
  unitId?: string;
  unitName?: string;
  brandId?: string;
  brandName?: string;
  hsnCode?: string;
  unitConversions?: UnitConversion[];
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  lastAddedPrice?: number;
  lastVendorName?: string;
  lastPriceDate?: Date;
}

export interface RMVendorPrice {
  _id?: ObjectId;
  rawMaterialId: string;
  vendorId: string;
  vendorName: string;
  quantity: number;
  unitId?: string;
  unitName?: string;
  price: number;
  addedDate: Date;
  createdBy: string;
  brandId?: string;
  brandName?: string;
}

export interface RMPriceLog {
  _id?: ObjectId;
  rawMaterialId: string;
  vendorId: string;
  vendorName: string;
  oldPrice: number;
  newPrice: number;
  quantity: number;
  unitId?: string;
  unitName?: string;
  changeDate: Date;
  changedBy: string;
}

export interface RawMaterialLog {
  _id?: ObjectId;
  rawMaterialId: string;
  actionType: string; // PRICE_UPDATE, VENDOR_UPDATE, UNIT_UPDATE, GST_UPDATE, RAW_MATERIAL_EDIT, RAW_MATERIAL_DELETE
  fieldName?: string; // name, categoryId, subCategoryId, unitId, hsnCode, etc.
  oldValue?: any;
  newValue?: any;
  changedByUserName: string;
  changedAt: Date;
  ipAddress?: string;
}

// Get next RM code
const getNextRMCode = async (db: any): Promise<string> => {
  const appData = await db
    .collection("app_data")
    .findOne({ key: "rm_counter" });

  let nextNumber = 1;
  if (appData && appData.value) {
    nextNumber = appData.value + 1;
  }

  await db
    .collection("app_data")
    .updateOne(
      { key: "rm_counter" },
      { $set: { value: nextNumber } },
      { upsert: true },
    );

  return `RM${String(nextNumber).padStart(5, "0")}`;
};

// GET all raw materials with pagination
export const handleGetRawMaterials: RequestHandler = async (req, res) => {
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
    const total = await db
      .collection("raw_materials")
      .countDocuments({ is_deleted: { $ne: true } });

    // Fetch paginated raw materials
    const rawMaterials = await db
      .collection("raw_materials")
      .find({ is_deleted: { $ne: true } })
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    res.json({
      success: true,
      data: rawMaterials,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching raw materials:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// POST create raw material
export const handleCreateRawMaterial: RequestHandler = async (req, res) => {
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
      categoryId,
      categoryName,
      subCategoryId,
      subCategoryName,
      unitId,
      unitName,
      brandId,
      brandName,
      hsnCode,
      createdBy,
    } = req.body;

    // Validate required fields
    if (!name || !categoryId) {
      return res.status(400).json({
        success: false,
        message: "Name and category are required",
      });
    }

    const code = await getNextRMCode(db);

    const newRM: RawMaterial = {
      code,
      name,
      categoryId,
      categoryName,
      subCategoryId,
      subCategoryName,
      unitId,
      unitName,
      brandId,
      brandName,
      hsnCode,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy,
    };

    const result = await db.collection("raw_materials").insertOne(newRM);

    res.status(201).json({
      success: true,
      message: "Raw material created successfully",
      data: { ...newRM, _id: result.insertedId },
    });
  } catch (error) {
    console.error("Error creating raw material:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// PUT update raw material
export const handleUpdateRawMaterial: RequestHandler = async (req, res) => {
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
      categoryId,
      categoryName,
      subCategoryId,
      subCategoryName,
      unitId,
      unitName,
      brandId,
      brandName,
      brandIds,
      brandNames,
      hsnCode,
    } = req.body;

    // Get the current raw material before updating
    const currentRM = await db
      .collection("raw_materials")
      .findOne({ _id: new ObjectId(id as string) });

    if (!currentRM) {
      return res
        .status(404)
        .json({ success: false, message: "Raw material not found" });
    }

    const updateData: any = {
      updatedAt: new Date(),
    };

    if (name) updateData.name = name;
    if (categoryId) updateData.categoryId = categoryId;
    if (categoryName) updateData.categoryName = categoryName;
    if (subCategoryId) updateData.subCategoryId = subCategoryId;
    if (subCategoryName) updateData.subCategoryName = subCategoryName;
    if (unitId) updateData.unitId = unitId;
    if (unitName) updateData.unitName = unitName;
    if (brandId) updateData.brandId = brandId;
    if (brandName) updateData.brandName = brandName;
    if (brandIds && Array.isArray(brandIds)) updateData.brandIds = brandIds;
    if (brandNames && Array.isArray(brandNames)) updateData.brandNames = brandNames;
    if (hsnCode !== undefined) updateData.hsnCode = hsnCode;

    const result = await db
      .collection("raw_materials")
      .updateOne({ _id: new ObjectId(id as string) }, { $set: updateData });

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Raw material not found" });
    }

    // Log each field change
    const changedByUserName = (req.body.changedBy || "admin") as string;

    if (name && currentRM.name !== name) {
      await db.collection("raw_material_logs").insertOne({
        rawMaterialId: id,
        actionType: "RAW_MATERIAL_EDIT",
        fieldName: "name",
        oldValue: currentRM.name,
        newValue: name,
        changedByUserName,
        changedAt: new Date(),
      });
    }

    if (categoryId && currentRM.categoryId !== categoryId) {
      await db.collection("raw_material_logs").insertOne({
        rawMaterialId: id,
        actionType: "RAW_MATERIAL_EDIT",
        fieldName: "categoryId",
        oldValue: currentRM.categoryName,
        newValue: categoryName,
        changedByUserName,
        changedAt: new Date(),
      });
    }

    if (subCategoryId && currentRM.subCategoryId !== subCategoryId) {
      await db.collection("raw_material_logs").insertOne({
        rawMaterialId: id,
        actionType: "RAW_MATERIAL_EDIT",
        fieldName: "subCategoryId",
        oldValue: currentRM.subCategoryName,
        newValue: subCategoryName,
        changedByUserName,
        changedAt: new Date(),
      });
    }

    if (unitId && currentRM.unitId !== unitId) {
      await db.collection("raw_material_logs").insertOne({
        rawMaterialId: id,
        actionType: "UNIT_UPDATE",
        fieldName: "unitId",
        oldValue: currentRM.unitName,
        newValue: unitName,
        changedByUserName,
        changedAt: new Date(),
      });
    }

    if (hsnCode !== undefined && currentRM.hsnCode !== hsnCode) {
      await db.collection("raw_material_logs").insertOne({
        rawMaterialId: id,
        actionType: "RAW_MATERIAL_EDIT",
        fieldName: "hsnCode",
        oldValue: currentRM.hsnCode,
        newValue: hsnCode,
        changedByUserName,
        changedAt: new Date(),
      });
    }

    res.json({
      success: true,
      message: "Raw material updated successfully",
    });
  } catch (error) {
    console.error("Error updating raw material:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE raw material (soft delete)
export const handleDeleteRawMaterial: RequestHandler = async (req, res) => {
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
    const changedByUserName = (req.body?.changedBy || "admin") as string;

    // Get the current raw material before deleting
    const currentRM = await db
      .collection("raw_materials")
      .findOne({ _id: new ObjectId(id as string) });

    if (!currentRM) {
      return res
        .status(404)
        .json({ success: false, message: "Raw material not found" });
    }

    // Soft delete: mark as deleted instead of hard delete
    const result = await db
      .collection("raw_materials")
      .updateOne(
        { _id: new ObjectId(id as string) },
        { $set: { is_deleted: true, updatedAt: new Date() } },
      );

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Raw material not found" });
    }

    // Log the deletion
    await db.collection("raw_material_logs").insertOne({
      rawMaterialId: id,
      actionType: "RAW_MATERIAL_DELETE",
      fieldName: "status",
      oldValue: "Active",
      newValue: "Deleted",
      changedByUserName,
      changedAt: new Date(),
    });

    res.json({
      success: true,
      message: "Raw material deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting raw material:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// CSV upload handler (bulk create / update)
export const handleUploadRawMaterials: RequestHandler = async (req, res) => {
  try {
    const { default: multer } = await import("multer");
    const { parse } = await import("csv-parse/sync");
    const upload = multer({ storage: multer.memoryStorage() });

    await new Promise<void>((resolve, reject) => {
      upload.single("file")(req as any, res as any, (err: any) => {
        if (err) return reject(err);
        resolve();
      });
    });

    const file = (req as any).file;
    if (!file) {
      return res
        .status(400)
        .json({ success: false, message: "No file provided" });
    }

    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const text = file.buffer.toString("utf-8");
    const records: any[] = parse(text, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
    });

    const results: { created: number; updated: number; skipped: Array<any> } = {
      created: 0,
      updated: 0,
      skipped: [],
    };

    for (let i = 0; i < records.length; i++) {
      const row = records[i];
      const rowIndex = i + 2; // header is line 1

      // Support multiple column name formats
      const name = (
        row.rawMaterialName ||
        row["Raw Material Name"] ||
        row.name ||
        ""
      )
        .toString()
        .trim();
      const categoryName = (row.category || row.Category || "")
        .toString()
        .trim();
      const subCategoryName = (
        row.subCategory ||
        row["Sub Category"] ||
        row["subCategory"] ||
        ""
      )
        .toString()
        .trim();
      const unitName = (row.unit || row.Unit || "").toString().trim();
      const hsnCode = (row.hsnCode || row["HSN Code"] || "").toString().trim();
      const id = row.id ? row.id.toString().trim() : undefined;

      if (!name || !categoryName || !subCategoryName) {
        results.skipped.push({
          row: rowIndex,
          reason: "Missing required field(s)",
          data: row,
        });
        continue;
      }

      // find or create category
      let category = await db
        .collection("categories")
        .findOne({ name: categoryName });

      if (!category) {
        // Auto-create category
        try {
          const categoryResult = await db.collection("categories").insertOne({
            name: categoryName,
            createdAt: new Date(),
            createdBy: "admin",
          });
          category = {
            _id: categoryResult.insertedId,
            name: categoryName,
          };
        } catch (error: any) {
          // Handle duplicate key error - try to find it again
          if (error.code === 11000 || error.message.includes("duplicate")) {
            category = await db
              .collection("categories")
              .findOne({ name: categoryName });
            if (!category) {
              throw error; // If still not found, this is a real error
            }
          } else {
            throw error;
          }
        }
      }

      // find or create sub-category
      let subcategory = await db.collection("subcategories").findOne({
        name: subCategoryName,
        categoryId: (category._id as any).toString(),
      });

      if (!subcategory) {
        // Auto-create sub-category
        try {
          const subCategoryResult = await db
            .collection("subcategories")
            .insertOne({
              name: subCategoryName,
              categoryId: (category._id as any).toString(),
              createdAt: new Date(),
              createdBy: "admin",
            });
          subcategory = {
            _id: subCategoryResult.insertedId,
            name: subCategoryName,
            categoryId: (category._id as any).toString(),
          };
        } catch (error: any) {
          // Handle duplicate key error - try to find it again
          if (error.code === 11000 || error.message.includes("duplicate")) {
            subcategory = await db.collection("subcategories").findOne({
              name: subCategoryName,
            });
            if (!subcategory) {
              // If still not found, use the name as fallback
              subcategory = {
                _id: new ObjectId(),
                name: subCategoryName,
                categoryId: (category._id as any).toString(),
              };
            }
          } else {
            throw error;
          }
        }
      }

      // find or create unit if specified
      let unit: any = null;
      if (unitName) {
        unit = await db.collection("units").findOne({ name: unitName });

        if (!unit) {
          // Auto-create unit with shortCode
          try {
            const shortCode = unitName
              .substring(0, 3)
              .toUpperCase()
              .padEnd(3, "X");
            const unitResult = await db.collection("units").insertOne({
              name: unitName,
              shortCode,
              createdAt: new Date(),
              createdBy: "admin",
              editLog: [],
            });
            unit = {
              _id: unitResult.insertedId,
              name: unitName,
              shortCode,
            };
          } catch (error: any) {
            // Handle duplicate key error - try to find it again
            if (error.code === 11000 || error.message.includes("duplicate")) {
              unit = await db.collection("units").findOne({ name: unitName });
            } else {
              throw error;
            }
          }
        }
      }

      // If id present -> update
      if (id) {
        try {
          const updateData: any = {
            name,
            categoryId: (category._id as any).toString(),
            categoryName: category.name,
            subCategoryName,
            updatedAt: new Date(),
          };

          if (subcategory)
            updateData.subCategoryId = (subcategory._id as any).toString();
          if (unit) {
            updateData.unitId = (unit._id as any).toString();
            updateData.unitName = unit.name;
          }
          if (hsnCode !== undefined) updateData.hsnCode = hsnCode;

          const { matchedCount } = await db
            .collection("raw_materials")
            .updateOne({ _id: new ObjectId(id) }, { $set: updateData });

          if (matchedCount === 0) {
            results.skipped.push({
              row: rowIndex,
              reason: `ID not found: ${id}`,
              data: row,
            });
            continue;
          }

          results.updated += 1;
        } catch (err) {
          results.skipped.push({
            row: rowIndex,
            reason: `Update error: ${String(err)}`,
            data: row,
          });
        }
      } else {
        // create
        try {
          const code = await getNextRMCode(db);
          const newRM: RawMaterial = {
            code,
            name,
            categoryId: (category._id as any).toString(),
            categoryName: category.name,
            subCategoryId: (subcategory
              ? (subcategory._id as any).toString()
              : undefined) as any,
            subCategoryName,
            unitId: unit ? (unit._id as any).toString() : undefined,
            unitName: unit ? unit.name : undefined,
            hsnCode: hsnCode || undefined,
            createdAt: new Date(),
            updatedAt: new Date(),
            createdBy: "admin",
          };

          await db.collection("raw_materials").insertOne(newRM);
          results.created += 1;
        } catch (err) {
          results.skipped.push({
            row: rowIndex,
            reason: `Create error: ${String(err)}`,
            data: row,
          });
        }
      }
    }

    res.json({ success: true, data: results });
  } catch (error) {
    console.error("Error processing CSV:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Unknown error processing CSV";
    res.status(500).json({
      success: false,
      message: `Error processing CSV: ${errorMessage}`,
    });
  }
};

// Export all raw materials as CSV
export const handleExportRawMaterials: RequestHandler = async (_req, res) => {
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

    const rawMaterials = await db
      .collection("raw_materials")
      .find({ is_deleted: { $ne: true } })
      .toArray();

    const headers = [
      "id",
      "code",
      "rawMaterialName",
      "category",
      "subCategory",
      "unit",
      "hsnCode",
    ];

    const lines = [headers.join(",")];
    for (const rm of rawMaterials) {
      const row = [
        rm._id?.toString() || "",
        (rm.code || "").replace(/"/g, '""'),
        (rm.name || "").replace(/"/g, '""'),
        (rm.categoryName || "").replace(/"/g, '""'),
        (rm.subCategoryName || "").replace(/"/g, '""'),
        (rm.unitName || "").replace(/"/g, '""'),
        (rm.hsnCode || "").toString().replace(/"/g, '""'),
      ].map((v) => (v && v.toString().includes(",") ? `"${v}"` : v));
      lines.push(row.join(","));
    }

    const csv = lines.join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="raw-materials-export.csv"`,
    );
    res.send(csv);
  } catch (error) {
    console.error("Error exporting CSV:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// POST add vendor price for raw material
export const handleAddRMVendorPrice: RequestHandler = async (req, res) => {
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
      rawMaterialId,
      vendorId,
      vendorName,
      quantity,
      unitId,
      unitName,
      price,
      brandId,
      brandName,
      createdBy,
    } = req.body;

    // Validate required fields
    if (
      !rawMaterialId ||
      !vendorId ||
      !quantity ||
      !price ||
      price < 0 ||
      quantity <= 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid input data",
      });
    }

    // Get the existing raw material to update last added price
    const rm = await db
      .collection("raw_materials")
      .findOne({ _id: new ObjectId(rawMaterialId) });

    if (!rm) {
      return res
        .status(404)
        .json({ success: false, message: "Raw material not found" });
    }

    // Check if this vendor already has a price for this RM
    const existingVendorPrice = await db
      .collection("rm_vendor_prices")
      .findOne({
        rawMaterialId: rawMaterialId,
        vendorId: vendorId,
      });

    let oldPrice = null;
    if (existingVendorPrice) {
      oldPrice = existingVendorPrice.price;
    }

    // Create price log if this vendor already had a price and it's different
    if (oldPrice !== null && oldPrice !== price) {
      const priceLog: RMPriceLog = {
        rawMaterialId,
        vendorId,
        vendorName,
        oldPrice,
        newPrice: price,
        quantity,
        unitId,
        unitName,
        changeDate: new Date(),
        changedBy: createdBy,
      };

      await db.collection("rm_price_logs").insertOne(priceLog);
    }

    // Create vendor price record
    const vendorPrice: RMVendorPrice = {
      rawMaterialId,
      vendorId,
      vendorName,
      quantity,
      unitId,
      unitName,
      price,
      addedDate: new Date(),
      createdBy,
      brandId,
      brandName,
    };

    const result = await db
      .collection("rm_vendor_prices")
      .insertOne(vendorPrice);

    // Update raw material with last added price
    await db.collection("raw_materials").updateOne(
      { _id: new ObjectId(rawMaterialId) },
      {
        $set: {
          lastAddedPrice: price,
          lastVendorName: vendorName,
          lastPriceDate: new Date(),
          updatedAt: new Date(),
        },
      },
    );

    // Propagate price change to recipes that include this raw material
    try {
      const affectedItems = await db
        .collection("recipe_items")
        .find({ rawMaterialId })
        .toArray();
      const recipeIds = Array.from(
        new Set(affectedItems.map((it: any) => it.recipeId)),
      );

      for (const recipeId of recipeIds) {
        const recipe = await db
          .collection("recipes")
          .findOne({ _id: new ObjectId(recipeId) });
        if (!recipe) continue;

        let anyChange = false;

        // Update each matching item in the recipe
        for (const it of affectedItems.filter(
          (a: any) => a.recipeId === recipeId,
        )) {
          const oldItemPrice = it.price;
          if (oldItemPrice !== price) {
            const newTotalPrice = (it.quantity || 0) * price;
            const newPricePerKg = it.yield
              ? newTotalPrice / it.yield
              : undefined;

            await db.collection("recipe_items").updateOne(
              { _id: it._id },
              {
                $set: {
                  price,
                  totalPrice: newTotalPrice,
                  pricePerKg: newPricePerKg,
                },
              },
            );

            // Log the change for this recipe
            await db.collection("recipe_logs").insertOne({
              recipeId,
              recipeItemId: it._id ? it._id.toString() : undefined,
              rawMaterialId,
              fieldChanged: "price",
              oldValue: oldItemPrice,
              newValue: price,
              changeDate: new Date(),
              changedBy: createdBy,
              recipeCode: recipe.code,
            });

            anyChange = true;
          }
        }

        // Recalculate recipe totals and create a history snapshot if any item changed
        if (anyChange) {
          const updatedItems = await db
            .collection("recipe_items")
            .find({ recipeId })
            .toArray();
          const totalRawMaterialCost = updatedItems.reduce(
            (sum: number, x: any) => sum + (x.totalPrice || 0),
            0,
          );
          const pricePerUnit =
            recipe.batchSize > 0 ? totalRawMaterialCost / recipe.batchSize : 0;

          await db.collection("recipes").updateOne(
            { _id: new ObjectId(recipeId) },
            {
              $set: {
                totalRawMaterialCost,
                pricePerUnit: parseFloat(pricePerUnit.toFixed(2)),
                updatedAt: new Date(),
              },
            },
          );

          const historySnapshot = {
            recipeId,
            recipeCode: recipe.code,
            recipeName: recipe.name,
            snapshotDate: new Date(),
            totalRawMaterialCost,
            pricePerUnit: parseFloat(pricePerUnit.toFixed(2)),
            items: updatedItems,
            createdReason: "price_change",
            changedBy: createdBy,
          };

          await db.collection("recipe_history").insertOne(historySnapshot);
        }
      }
    } catch (err) {
      console.error("Error propagating RM price to recipes:", err);
    }

    res.status(201).json({
      success: true,
      message: "Vendor price added successfully",
      data: { ...vendorPrice, _id: result.insertedId },
    });
  } catch (error) {
    console.error("Error adding vendor price:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// GET vendor prices for a raw material
export const handleGetRMVendorPrices: RequestHandler = async (req, res) => {
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

    const { rawMaterialId } = req.params;

    const prices = await db
      .collection("rm_vendor_prices")
      .find({ rawMaterialId })
      .sort({ addedDate: -1 })
      .toArray();

    res.json({ success: true, data: prices });
  } catch (error) {
    console.error("Error fetching vendor prices:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// GET price logs for a raw material
export const handleGetRMPriceLogs: RequestHandler = async (req, res) => {
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

    const { rawMaterialId } = req.params;

    const logs = await db
      .collection("rm_price_logs")
      .find({ rawMaterialId })
      .sort({ changeDate: -1 })
      .toArray();

    res.json({ success: true, data: logs });
  } catch (error) {
    console.error("Error fetching price logs:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};
// POST sync latest vendor price for a raw material and propagate to recipes
export const handleSyncLatestRMPrice: RequestHandler = async (req, res) => {
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

    const { rawMaterialId } = req.params;
    const { createdBy } = req.body || { createdBy: "system" };

    const rm = await db
      .collection("raw_materials")
      .findOne({ _id: new ObjectId(rawMaterialId as string) });

    if (!rm) {
      return res
        .status(404)
        .json({ success: false, message: "Raw material not found" });
    }

    // Find latest vendor price
    const latestPrice = await db
      .collection("rm_vendor_prices")
      .find({ rawMaterialId })
      .sort({ addedDate: -1 })
      .limit(1)
      .toArray();

    if (!latestPrice || latestPrice.length === 0) {
      return res.json({
        success: false,
        message: "No vendor prices found for this RM",
      });
    }

    const latest = latestPrice[0];
    const price = latest.price;
    const vendorName = latest.vendorName;

    // No change
    if (rm.lastAddedPrice === price) {
      return res.json({
        success: true,
        message: "No price change",
        data: { price },
      });
    }

    // Update raw material last price
    await db.collection("raw_materials").updateOne(
      { _id: new ObjectId(rawMaterialId as string) },
      {
        $set: {
          lastAddedPrice: price,
          lastVendorName: vendorName,
          lastPriceDate: new Date(),
          updatedAt: new Date(),
        },
      },
    );

    // Propagate to recipes
    const affectedItems = await db
      .collection("recipe_items")
      .find({ rawMaterialId })
      .toArray();
    const recipeIds = Array.from(
      new Set(affectedItems.map((it: any) => it.recipeId)),
    );
    const updatedRecipes: string[] = [];

    for (const recipeId of recipeIds) {
      const recipe = await db
        .collection("recipes")
        .findOne({ _id: new ObjectId(recipeId) });
      if (!recipe) continue;

      let anyChange = false;

      for (const it of affectedItems.filter(
        (a: any) => a.recipeId === recipeId,
      )) {
        const oldItemPrice = it.price;
        if (oldItemPrice !== price) {
          const newTotalPrice = (it.quantity || 0) * price;
          const newPricePerKg = it.yield ? newTotalPrice / it.yield : undefined;

          await db.collection("recipe_items").updateOne(
            { _id: it._id },
            {
              $set: {
                price,
                totalPrice: newTotalPrice,
                pricePerKg: newPricePerKg,
              },
            },
          );

          await db.collection("recipe_logs").insertOne({
            recipeId,
            recipeItemId: it._id ? it._id.toString() : undefined,
            rawMaterialId,
            fieldChanged: "price",
            oldValue: oldItemPrice,
            newValue: price,
            changeDate: new Date(),
            changedBy: createdBy || "system",
            recipeCode: recipe.code,
          });

          anyChange = true;
        }
      }

      if (anyChange) {
        const updatedItems = await db
          .collection("recipe_items")
          .find({ recipeId })
          .toArray();
        const totalRawMaterialCost = updatedItems.reduce(
          (sum: number, x: any) => sum + (x.totalPrice || 0),
          0,
        );
        const pricePerUnit =
          recipe.batchSize > 0 ? totalRawMaterialCost / recipe.batchSize : 0;

        await db.collection("recipes").updateOne(
          { _id: new ObjectId(recipeId) },
          {
            $set: {
              totalRawMaterialCost,
              pricePerUnit: parseFloat(pricePerUnit.toFixed(2)),
              updatedAt: new Date(),
            },
          },
        );

        const historySnapshot = {
          recipeId,
          recipeCode: recipe.code,
          recipeName: recipe.name,
          snapshotDate: new Date(),
          totalRawMaterialCost,
          pricePerUnit: parseFloat(pricePerUnit.toFixed(2)),
          items: updatedItems,
          createdReason: "price_change",
          changedBy: createdBy || "system",
        };

        await db.collection("recipe_history").insertOne(historySnapshot);
        updatedRecipes.push(recipeId);
      }
    }

    res.json({
      success: true,
      message: "Price synced and recipes updated",
      data: { price, updatedRecipes },
    });
  } catch (error) {
    console.error("Error syncing latest RM price:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE price log
export const handleDeleteRMPriceLog: RequestHandler = async (req, res) => {
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

    const { rawMaterialId, logId } = req.params;
    const rawMaterialIdStr = Array.isArray(rawMaterialId)
      ? rawMaterialId[0]
      : rawMaterialId;
    const logIdStr = Array.isArray(logId) ? logId[0] : logId;

    const result = await db.collection("rm_price_logs").deleteOne({
      _id: new ObjectId(logIdStr),
      rawMaterialId: new ObjectId(rawMaterialIdStr),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Price log not found" });
    }

    res.json({ success: true, message: "Price log deleted successfully" });
  } catch (error) {
    console.error("Error deleting price log:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// GET audit logs for a raw material
export const handleGetRawMaterialLogs: RequestHandler = async (req, res) => {
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

    const { rawMaterialId } = req.params;

    const logs = await db
      .collection("raw_material_logs")
      .find({ rawMaterialId: rawMaterialId as string })
      .sort({ changedAt: -1 })
      .toArray();

    res.json({ success: true, data: logs });
  } catch (error) {
    console.error("Error fetching raw material logs:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE all raw materials (soft delete)
export const handleClearAllRawMaterials: RequestHandler = async (req, res) => {
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

    // Hard delete: permanently remove all raw materials and associated data
    const rmDeleteResult = await db
      .collection("raw_materials")
      .deleteMany({});

    // Delete all vendor prices for raw materials
    await db
      .collection("rm_vendor_prices")
      .deleteMany({});

    // Delete all price logs
    await db
      .collection("rm_price_logs")
      .deleteMany({});

    // Delete all raw material logs
    await db
      .collection("raw_material_logs")
      .deleteMany({});

    // Remove RM items from all recipes
    await db
      .collection("recipes")
      .updateMany(
        { "items": { $exists: true } },
        { $set: { items: [] } }
      );

    res.json({
      success: true,
      message: `Permanently deleted ${rmDeleteResult.deletedCount} raw materials and all associated data`,
    });
  } catch (error) {
    console.error("Error clearing raw materials:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE all vendor prices
export const handleClearAllRMPrices: RequestHandler = async (req, res) => {
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

    // Delete all vendor prices
    const deleteResult = await db
      .collection("rm_vendor_prices")
      .deleteMany({});

    // Delete all price logs
    await db
      .collection("rm_price_logs")
      .deleteMany({});

    res.json({
      success: true,
      message: `Permanently deleted ${deleteResult.deletedCount} vendor prices and all associated price logs`,
    });
  } catch (error) {
    console.error("Error clearing prices:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// MIGRATION: Fix units missing shortCode (from vendors and rm upload data)
export const handleFixMissingUnitShortCodes: RequestHandler = async (
  req,
  res,
) => {
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

    // Find all units without shortCode
    const unitsWithoutShortCode = await db
      .collection("units")
      .find({
        $or: [
          { shortCode: { $exists: false } },
          { shortCode: null },
          { shortCode: "" },
        ],
      })
      .toArray();

    if (unitsWithoutShortCode.length === 0) {
      return res.json({
        success: true,
        message: "No units need fixing - all units have shortCode",
        updated: 0,
      });
    }

    let updated = 0;

    for (const unit of unitsWithoutShortCode) {
      // Generate shortCode from unit name
      const shortCode = unit.name.substring(0, 3).toUpperCase().padEnd(3, "X");

      await db.collection("units").updateOne(
        { _id: unit._id },
        {
          $set: {
            shortCode,
            updatedAt: new Date(),
          },
        },
      );

      updated += 1;
    }

    res.json({
      success: true,
      message: `Fixed ${updated} units with missing shortCode`,
      updated,
    });
  } catch (error) {
    console.error("Error fixing unit shortCodes:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// GET price history snapshots for a raw material (for RMC history view)
export const handleGetRMPriceHistory: RequestHandler = async (req, res) => {
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

    const { rawMaterialId } = req.params;

    // Get the RM details
    const rm = await db
      .collection("raw_materials")
      .findOne({ _id: new ObjectId(rawMaterialId as string) });

    if (!rm) {
      return res
        .status(404)
        .json({ success: false, message: "Raw material not found" });
    }

    // Get all vendor prices for this RM, sorted by date (newest first)
    const vendorPrices = await db
      .collection("rm_vendor_prices")
      .find({ rawMaterialId: rawMaterialId as string })
      .sort({ addedDate: -1 })
      .toArray();

    // Get all price logs for this RM
    const priceLogs = await db
      .collection("rm_price_logs")
      .find({ rawMaterialId: rawMaterialId as string })
      .sort({ changeDate: -1 })
      .toArray();

    // Create history snapshots by combining vendor prices and price logs
    const history = vendorPrices.map((vp: any, index: number) => {
      // Find any price change logs related to this price entry
      const relatedLogs = priceLogs.filter(
        (log: any) =>
          log.vendorId === vp.vendorId &&
          new Date(log.changeDate) <= new Date(vp.addedDate),
      );

      return {
        _id: vp._id,
        rawMaterialId: vp.rawMaterialId,
        rawMaterialCode: rm.code,
        rawMaterialName: rm.name,
        vendorId: vp.vendorId,
        vendorName: vp.vendorName,
        price: vp.price,
        quantity: vp.quantity,
        unitName: vp.unitName,
        addedDate: vp.addedDate,
        createdBy: vp.createdBy,
        // Check if this is a price change from previous entry
        isPriceChange:
          index < vendorPrices.length - 1 &&
          vendorPrices[index + 1].vendorId === vp.vendorId &&
          vendorPrices[index + 1].price !== vp.price,
        previousPrice:
          index < vendorPrices.length - 1 &&
          vendorPrices[index + 1].vendorId === vp.vendorId
            ? vendorPrices[index + 1].price
            : undefined,
        changedFrom:
          relatedLogs.length > 0 ? relatedLogs[0].oldPrice : undefined,
      };
    });

    res.json({ success: true, data: history });
  } catch (error) {
    console.error("Error fetching RM price history:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Reset RM counter to start from RM0001
export const handleResetRMCounter: RequestHandler = async (_req, res) => {
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

    // Reset the counter to 0 (next code will be RM00001)
    await db.collection("app_data").updateOne(
      { key: "rm_counter" },
      { $set: { value: 0 } },
      { upsert: true }
    );

    res.json({
      success: true,
      message: "RM counter reset successfully. Next material will be RM00001",
    });
  } catch (error) {
    console.error("Error resetting RM counter:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Migrate all raw materials to new code format (RM00001, RM00002, etc.)
export const handleMigrateRMCodes: RequestHandler = async (_req, res) => {
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

    // Get all raw materials sorted by creation date
    const rawMaterials = await db
      .collection("raw_materials")
      .find({})
      .sort({ createdAt: 1 })
      .toArray();

    if (rawMaterials.length === 0) {
      return res.json({
        success: true,
        message: "No raw materials to migrate",
        migrated: 0,
      });
    }

    // Prepare bulk operations
    const bulkOps = [];
    const oldCodesMap: { [key: string]: string } = {}; // old code -> new code mapping

    for (let i = 0; i < rawMaterials.length; i++) {
      const newCode = `RM${String(i + 1).padStart(5, "0")}`;
      const oldCode = rawMaterials[i].code;
      oldCodesMap[oldCode] = newCode;

      bulkOps.push({
        updateOne: {
          filter: { _id: rawMaterials[i]._id },
          update: { $set: { code: newCode, updatedAt: new Date() } },
        },
      });
    }

    // Execute bulk update
    if (bulkOps.length > 0) {
      await db.collection("raw_materials").bulkWrite(bulkOps);
    }

    // Reset the counter in app_data
    await db.collection("app_data").updateOne(
      { key: "rm_counter" },
      { $set: { value: rawMaterials.length } },
      { upsert: true }
    );

    console.log(`Successfully migrated ${rawMaterials.length} raw materials to new code format`);
    console.log("Sample migration mapping:", Object.entries(oldCodesMap).slice(0, 5));

    res.json({
      success: true,
      message: `Successfully migrated ${rawMaterials.length} raw materials to new code format (RM00001, RM00002, ...)`,
      migrated: rawMaterials.length,
    });
  } catch (error) {
    console.error("Error migrating RM codes:", error);
    res.status(500).json({ success: false, message: "Server error during migration" });
  }
};

// DELETE raw materials by code range (temporary for cleanup)
export const handleDeleteRMByCodeRange: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  try {
    const { startCode, endCode } = req.body;

    if (!startCode || !endCode) {
      return res
        .status(400)
        .json({ success: false, message: "startCode and endCode required" });
    }

    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    // Extract numbers from codes (e.g., "RM00001" -> 1, "RM02906" -> 2906)
    const startNum = parseInt(startCode.replace("RM", ""));
    const endNum = parseInt(endCode.replace("RM", ""));

    // Generate array of codes to delete
    const codesToDelete = [];
    for (let i = startNum; i <= endNum; i++) {
      codesToDelete.push(`RM${String(i).padStart(5, "0")}`);
    }

    // Delete raw materials with these codes
    const result = await db
      .collection("raw_materials")
      .deleteMany({
        code: { $in: codesToDelete },
      });

    res.json({
      success: true,
      message: `Deleted ${result.deletedCount} raw materials from ${startCode} to ${endCode}`,
      deletedCount: result.deletedCount,
    });
  } catch (error) {
    console.error("Error deleting RM by code range:", error);
    res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : "Server error",
    });
  }
};

// CSV upload handler for vendor prices
export const handleUploadRMPrices: RequestHandler = async (req, res) => {
  try {
    const { default: multer } = await import("multer");
    const { parse } = await import("csv-parse/sync");
    const upload = multer({ storage: multer.memoryStorage() });

    await new Promise<void>((resolve, reject) => {
      upload.single("file")(req as any, res as any, (err: any) => {
        if (err) return reject(err);
        resolve();
      });
    });

    const file = (req as any).file;
    if (!file) {
      return res
        .status(400)
        .json({ success: false, message: "No file provided" });
    }

    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const text = file.buffer.toString("utf-8");
    const records: any[] = parse(text, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
    });

    const results = { created: 0, updated: 0, skipped: [] as any[] };

    // OPTIMIZATION: Load all raw materials and vendors into memory ONCE
    // This avoids N+1 database queries
    const allRawMaterials = await db
      .collection("raw_materials")
      .find({ is_deleted: { $ne: true } })
      .toArray();

    const allVendors = await db
      .collection("vendors")
      .find({ is_deleted: { $ne: true } })
      .toArray();

    // Create lookup maps for O(1) access
    const rmByCode = new Map(allRawMaterials.map(rm => [rm.code.toLowerCase(), rm]));
    const rmByName = new Map(allRawMaterials.map(rm => [rm.name.toLowerCase(), rm]));
    const vendorByName = new Map(allVendors.map(v => [v.name.toLowerCase(), v]));

    // OPTIMIZATION: Batch insert and update operations
    const priceInserts: any[] = [];
    const rmUpdates: Array<{ _id: any; data: any }> = [];

    for (let i = 0; i < records.length; i++) {
      const row = records[i];
      const rowIndex = i + 2;

      const rmCode = (row.rawMaterialCode || row["RM Code"] || "")
        .toString()
        .trim();
      const rmName = (row.rawMaterialName || row["Raw Material Name"] || row.name || "")
        .toString()
        .trim();
      const vendorName = (row.vendorName || row["Vendor Name"] || "")
        .toString()
        .trim();
      const quantity = parseFloat(row.quantity || "0");
      const unitName = (row.unitName || row["Unit Name"] || row.unit || "")
        .toString()
        .trim();
      const price = parseFloat(row.price || "0");

      // Parse date from CSV (supports: addedDate, Added Date, createdAt, Created At, date, Date, purchaseDate, Purchase Date)
      let addedDate = new Date();
      const dateString = (row.addedDate || row["Added Date"] || row.createdAt || row["Created At"] || row.date || row.Date || row.purchaseDate || row["Purchase Date"] || "")
        .toString()
        .trim();

      if (dateString) {
        const parsedDate = new Date(dateString);
        // Only use the parsed date if it's a valid date
        if (!isNaN(parsedDate.getTime())) {
          addedDate = parsedDate;
        }
      }

      if ((!rmCode && !rmName) || !vendorName || !quantity || !unitName || !price) {
        results.skipped.push({
          row: rowIndex,
          reason: "Missing required field(s): (rawMaterialCode OR rawMaterialName), vendorName, quantity, unitName, price",
          data: row,
        });
        continue;
      }

      if (quantity <= 0 || price < 0) {
        results.skipped.push({
          row: rowIndex,
          reason: "Quantity must be > 0 and price must be >= 0",
          data: row,
        });
        continue;
      }

      // OPTIMIZATION: Use in-memory maps instead of database queries
      let rawMaterial = null;

      if (rmCode) {
        rawMaterial = rmByCode.get(rmCode.toLowerCase());
      }

      if (!rawMaterial && rmName) {
        rawMaterial = rmByName.get(rmName.toLowerCase());
      }

      if (!rawMaterial) {
        const searchInfo = rmCode ? `code ${rmCode}` : `name ${rmName}`;
        results.skipped.push({
          row: rowIndex,
          reason: `Raw material with ${searchInfo} not found`,
          data: row,
        });
        continue;
      }

      // OPTIMIZATION: Use in-memory vendor map instead of database query
      const vendor = vendorByName.get(vendorName.toLowerCase());

      if (!vendor) {
        results.skipped.push({
          row: rowIndex,
          reason: `Vendor ${vendorName} not found`,
          data: row,
        });
        continue;
      }

      // Collect insert and update operations for batch processing
      priceInserts.push({
        rawMaterialId: (rawMaterial._id as any).toString(),
        vendorId: (vendor._id as any).toString(),
        vendorName: vendor.name,
        quantity,
        unitName,
        price,
        addedDate: addedDate,
        createdBy: "csv_import",
      });

      rmUpdates.push({
        _id: rawMaterial._id,
        data: {
          lastAddedPrice: price,
          lastVendorName: vendor.name,
          lastPriceDate: addedDate,
          updatedAt: new Date(),
        },
      });

      results.created++;
    }

    // OPTIMIZATION: Batch insert all prices at once
    if (priceInserts.length > 0) {
      await db.collection("rm_vendor_prices").insertMany(priceInserts);
    }

    // OPTIMIZATION: Batch update all raw materials at once
    if (rmUpdates.length > 0) {
      const bulkOps = rmUpdates.map((update) => ({
        updateOne: {
          filter: { _id: update._id },
          update: { $set: update.data },
        },
      }));
      await db.collection("raw_materials").bulkWrite(bulkOps);
    }

    res.json({
      success: true,
      message: `Price upload complete! Created: ${results.created}, Updated: ${results.updated}, Skipped: ${results.skipped.length}`,
      data: results,
    });
  } catch (error) {
    console.error("Error uploading prices:", error);
    res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : "Server error during upload",
    });
  }
};

// Add unit conversion
export const handleAddUnitConversion: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  try {
    const { rawMaterialId, fromUnitId, fromUnitName, toUnitId, toUnitName, conversionFactor } = req.body;
    const username = (req as any).username || "system";

    if (!rawMaterialId || !fromUnitId || !toUnitId || conversionFactor <= 0) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields or invalid conversion factor",
      });
    }

    const db = getDB();
    if (!db) return res.status(503).json({ success: false, message: "Database error" });

    const conversion: UnitConversion = {
      fromUnitId,
      fromUnitName,
      toUnitId,
      toUnitName,
      conversionFactor,
      addedAt: new Date(),
      addedBy: username,
    };

    const result = await (db.collection("raw_materials") as any).updateOne(
      { _id: new ObjectId(rawMaterialId) },
      {
        $push: { unitConversions: conversion },
        $set: { updatedAt: new Date() },
      },
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Raw material not found",
      });
    }

    res.json({
      success: true,
      message: "Unit conversion added successfully",
      data: conversion,
    });
  } catch (error) {
    console.error("Error adding unit conversion:", error);
    res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : "Server error",
    });
  }
};

// GET single raw material by ID
export const handleGetRawMaterialById: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  try {
    const { id } = req.params;
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    // Validate ObjectId
    if (!id || !id.match(/^[0-9a-f]{24}$/i)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid raw material ID" });
    }

    const rawMaterial = await db
      .collection("raw_materials")
      .findOne({ _id: new ObjectId(id as string), is_deleted: { $ne: true } });

    if (!rawMaterial) {
      return res
        .status(404)
        .json({ success: false, message: "Raw material not found" });
    }

    res.json({ success: true, data: rawMaterial });
  } catch (error) {
    console.error("Error fetching raw material:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Delete unit conversion
export const handleDeleteUnitConversion: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  try {
    const { rawMaterialId, conversionIndex } = req.body;

    if (!rawMaterialId || conversionIndex === undefined) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields",
      });
    }

    const db = getDB();
    if (!db) return res.status(503).json({ success: false, message: "Database error" });

    // Get the conversion to delete
    const rm = await db.collection("raw_materials").findOne({ _id: new ObjectId(rawMaterialId) });
    if (!rm || !rm.unitConversions || !rm.unitConversions[conversionIndex]) {
      return res.status(404).json({
        success: false,
        message: "Conversion not found",
      });
    }

    // Remove the conversion from the array
    const result = await db.collection("raw_materials").updateOne(
      { _id: new ObjectId(rawMaterialId) },
      {
        $unset: { [`unitConversions.${conversionIndex}`]: 1 as any },
        $set: { updatedAt: new Date() },
      },
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Raw material not found",
      });
    }

    // Clean up the array by removing null values
    await (db.collection("raw_materials") as any).updateOne(
      { _id: new ObjectId(rawMaterialId) },
      {
        $pull: { unitConversions: null },
      },
    );

    res.json({
      success: true,
      message: "Unit conversion deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting unit conversion:", error);
    res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : "Server error",
    });
  }
};
