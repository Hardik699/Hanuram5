import { RequestHandler } from "express";
import { getDB, getConnectionStatus } from "../db";
import { ObjectId } from "mongodb";

export interface SubCategory {
  _id?: ObjectId;
  categoryId: string;
  categoryName?: string;
  name: string;
  status: "active" | "inactive";
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  editLog: Array<{
    timestamp: Date;
    editedBy: string;
    changes: Record<string, any>;
  }>;
}

// GET all subcategories
export const handleGetSubCategories: RequestHandler = async (_req, res) => {
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

    const subcategories = await db
      .collection("subcategories")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, data: subcategories });
  } catch (error) {
    console.error("Error fetching subcategories:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// POST create subcategory
export const handleCreateSubCategory: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { categoryId, name, status } = req.body;
  const username = "admin";

  if (!categoryId) {
    return res
      .status(400)
      .json({ success: false, message: "Category is required" });
  }

  if (!name || !name.trim()) {
    return res
      .status(400)
      .json({ success: false, message: "Sub Category name is required" });
  }

  if (!status || !["active", "inactive"].includes(status)) {
    return res.status(400).json({ success: false, message: "Invalid status" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    // Check if category exists
    const category = await db
      .collection("categories")
      .findOne({ _id: new ObjectId(categoryId) });
    if (!category) {
      return res
        .status(400)
        .json({ success: false, message: "Category not found" });
    }

    // Check for duplicate name
    const existing = await db
      .collection("subcategories")
      .findOne({ name: name.trim() });
    if (existing) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Sub Category with this name already exists",
        });
    }

    const newSubCategory: SubCategory = {
      categoryId,
      categoryName: category.name,
      name: name.trim(),
      status,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: username,
      editLog: [],
    };

    const result = await db
      .collection("subcategories")
      .insertOne(newSubCategory);
    res.json({
      success: true,
      message: "Sub Category created successfully",
      data: { _id: result.insertedId, ...newSubCategory },
    });
  } catch (error) {
    console.error("Error creating subcategory:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// PUT update subcategory
export const handleUpdateSubCategory: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;
  const { categoryId, name, status } = req.body;
  const username = "admin";

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "SubCategory ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const existing = await db
      .collection("subcategories")
      .findOne({ _id: objectId });

    if (!existing) {
      return res
        .status(404)
        .json({ success: false, message: "SubCategory not found" });
    }

    // Check for duplicate name
    if (name && name !== existing.name) {
      const duplicate = await db
        .collection("subcategories")
        .findOne({ name: name.trim() });
      if (duplicate) {
        return res
          .status(400)
          .json({
            success: false,
            message: "Sub Category with this name already exists",
          });
      }
    }

    const changes: Record<string, any> = {};
    if (name && name !== existing.name)
      changes.name = { from: existing.name, to: name };
    if (status && status !== existing.status)
      changes.status = { from: existing.status, to: status };

    const updateData: Partial<SubCategory> = {
      updatedAt: new Date(),
    };

    if (name) updateData.name = name.trim();
    if (status) updateData.status = status;

    const editLogEntry = {
      timestamp: new Date(),
      editedBy: username,
      changes,
    };

    const result = await db.collection("subcategories").findOneAndUpdate(
      { _id: objectId },
      {
        $set: updateData,
        $push: { editLog: editLogEntry } as any,
      },
      { returnDocument: "after" },
    );

    res.json({
      success: true,
      message: "Sub Category updated successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error updating subcategory:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE subcategory
export const handleDeleteSubCategory: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "SubCategory ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const result = await db
      .collection("subcategories")
      .deleteOne({ _id: objectId });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "SubCategory not found" });
    }

    res.json({ success: true, message: "Sub Category deleted successfully" });
  } catch (error) {
    console.error("Error deleting subcategory:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE all subcategories (hard delete)
export const handleClearAllSubCategories: RequestHandler = async (req, res) => {
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

    // Hard delete: permanently remove all subcategories
    const result = await db
      .collection("subcategories")
      .deleteMany({});

    res.json({
      success: true,
      message: `Permanently deleted ${result.deletedCount} subcategories`,
    });
  } catch (error) {
    console.error("Error clearing subcategories:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

