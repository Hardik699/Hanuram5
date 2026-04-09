import { RequestHandler } from "express";
import { getDB, getConnectionStatus } from "../db";
import { ObjectId } from "mongodb";

export interface Category {
  _id?: ObjectId;
  name: string;
  description?: string;
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

// GET all categories
export const handleGetCategories: RequestHandler = async (_req, res) => {
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

    const categories = await db
      .collection("categories")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, data: categories });
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// POST create category
export const handleCreateCategory: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { name, description, status } = req.body;
  const username = "admin";

  // Validation
  if (!name || !name.trim()) {
    return res
      .status(400)
      .json({ success: false, message: "Category name is required" });
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

    // Check for duplicate name
    const existing = await db
      .collection("categories")
      .findOne({ name: name.trim() });
    if (existing) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Category with this name already exists",
        });
    }

    const newCategory: Category = {
      name: name.trim(),
      description: description?.trim() || "",
      status,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: username,
      editLog: [],
    };

    const result = await db.collection("categories").insertOne(newCategory);
    res.json({
      success: true,
      message: "Category created successfully",
      data: { _id: result.insertedId, ...newCategory },
    });
  } catch (error) {
    console.error("Error creating category:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// PUT update category
export const handleUpdateCategory: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;
  const { name, description, status } = req.body;
  const username = "admin";

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "Category ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const existing = await db
      .collection("categories")
      .findOne({ _id: objectId });

    if (!existing) {
      return res
        .status(404)
        .json({ success: false, message: "Category not found" });
    }

    // Check for duplicate name (if name is changed)
    if (name && name !== existing.name) {
      const duplicate = await db
        .collection("categories")
        .findOne({ name: name.trim() });
      if (duplicate) {
        return res
          .status(400)
          .json({
            success: false,
            message: "Category with this name already exists",
          });
      }
    }

    // Track changes for edit log
    const changes: Record<string, any> = {};
    if (name && name !== existing.name)
      changes.name = { from: existing.name, to: name };
    if (description !== undefined && description !== existing.description)
      changes.description = { from: existing.description, to: description };
    if (status && status !== existing.status)
      changes.status = { from: existing.status, to: status };

    const updateData: Partial<Category> = {
      updatedAt: new Date(),
    };

    if (name) updateData.name = name.trim();
    if (description !== undefined)
      updateData.description = description?.trim() || "";
    if (status) updateData.status = status;

    // Add to edit log
    const editLogEntry = {
      timestamp: new Date(),
      editedBy: username,
      changes,
    };

    const result = await db.collection("categories").findOneAndUpdate(
      { _id: objectId },
      {
        $set: updateData,
        $push: { editLog: editLogEntry } as any,
      },
      { returnDocument: "after" },
    );

    res.json({
      success: true,
      message: "Category updated successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error updating category:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE category
export const handleDeleteCategory: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "Category ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const result = await db
      .collection("categories")
      .deleteOne({ _id: objectId });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Category not found" });
    }

    res.json({ success: true, message: "Category deleted successfully" });
  } catch (error) {
    console.error("Error deleting category:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE all categories (hard delete)
export const handleClearAllCategories: RequestHandler = async (req, res) => {
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

    // Hard delete: permanently remove all categories
    const result = await db
      .collection("categories")
      .deleteMany({});

    // Also delete all subcategories related to these categories
    await db
      .collection("subcategories")
      .deleteMany({});

    res.json({
      success: true,
      message: `Permanently deleted ${result.deletedCount} categories and all related subcategories`,
    });
  } catch (error) {
    console.error("Error clearing categories:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

