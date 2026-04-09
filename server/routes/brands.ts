import { RequestHandler } from "express";
import { getDB, getConnectionStatus } from "../db";
import { ObjectId } from "mongodb";

export interface Brand {
  _id?: ObjectId;
  name: string;
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  editLog: Array<{
    timestamp: Date;
    editedBy: string;
    changes: Record<string, any>;
  }>;
}

// GET all brands
export const handleGetBrands: RequestHandler = async (_req, res) => {
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

    const brands = await db
      .collection("brands")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, data: brands });
  } catch (error) {
    console.error("Error fetching brands:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// POST create brand
export const handleCreateBrand: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { name } = req.body;
  const username = "admin";

  if (!name || !name.trim()) {
    return res
      .status(400)
      .json({ success: false, message: "Brand name is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    // Check for duplicate name
    const existing = await db
      .collection("brands")
      .findOne({ name: name.trim() });
    if (existing) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Brand with this name already exists",
        });
    }

    const newBrand: Brand = {
      name: name.trim(),
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: username,
      editLog: [],
    };

    const result = await db.collection("brands").insertOne(newBrand);
    res.json({
      success: true,
      message: "Brand created successfully",
      data: { _id: result.insertedId, ...newBrand },
    });
  } catch (error) {
    console.error("Error creating brand:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// PUT update brand
export const handleUpdateBrand: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;
  const { name } = req.body;
  const username = "admin";

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "Brand ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const existing = await db.collection("brands").findOne({ _id: objectId });

    if (!existing) {
      return res
        .status(404)
        .json({ success: false, message: "Brand not found" });
    }

    // Check for duplicate name
    if (name && name !== existing.name) {
      const duplicate = await db
        .collection("brands")
        .findOne({ name: name.trim() });
      if (duplicate) {
        return res
          .status(400)
          .json({
            success: false,
            message: "Brand with this name already exists",
          });
      }
    }

    const changes: Record<string, any> = {};
    if (name && name !== existing.name)
      changes.name = { from: existing.name, to: name };

    const updateData: Partial<Brand> = {
      updatedAt: new Date(),
    };

    if (name) updateData.name = name.trim();

    const editLogEntry = {
      timestamp: new Date(),
      editedBy: username,
      changes,
    };

    const result = await db.collection("brands").findOneAndUpdate(
      { _id: objectId },
      {
        $set: updateData,
        $push: { editLog: editLogEntry } as any,
      },
      { returnDocument: "after" },
    );

    res.json({
      success: true,
      message: "Brand updated successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error updating brand:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE brand
export const handleDeleteBrand: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "Brand ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const result = await db.collection("brands").deleteOne({ _id: objectId });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Brand not found" });
    }

    res.json({ success: true, message: "Brand deleted successfully" });
  } catch (error) {
    console.error("Error deleting brand:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE all brands (hard delete)
export const handleClearAllBrands: RequestHandler = async (req, res) => {
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

    // Hard delete: permanently remove all brands
    const result = await db.collection("brands").deleteMany({});

    res.json({
      success: true,
      message: `Permanently deleted ${result.deletedCount} brands`,
    });
  } catch (error) {
    console.error("Error clearing brands:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

