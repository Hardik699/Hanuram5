import { RequestHandler } from "express";
import { getDB, getConnectionStatus } from "../db";
import { ObjectId } from "mongodb";

export interface Unit {
  _id?: ObjectId;
  name: string;
  shortCode: string;
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

// GET all units
export const handleGetUnits: RequestHandler = async (_req, res) => {
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

    const units = await db
      .collection("units")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, data: units });
  } catch (error) {
    console.error("Error fetching units:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// POST create unit
export const handleCreateUnit: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { name, shortCode } = req.body;
  const username = "admin";

  if (!name || !name.trim()) {
    return res
      .status(400)
      .json({ success: false, message: "Unit name is required" });
  }

  if (!shortCode || !shortCode.trim()) {
    return res
      .status(400)
      .json({ success: false, message: "Unit short code is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    // Check for duplicate name
    const existing = await db
      .collection("units")
      .findOne({ name: name.trim() });
    if (existing) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Unit with this name already exists",
        });
    }

    const newUnit: Unit = {
      name: name.trim(),
      shortCode: shortCode.trim().toUpperCase(),
      status: "active",
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: username,
      editLog: [],
    };

    const result = await db.collection("units").insertOne(newUnit);
    res.json({
      success: true,
      message: "Unit created successfully",
      data: { _id: result.insertedId, ...newUnit },
    });
  } catch (error) {
    console.error("Error creating unit:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// PUT update unit
export const handleUpdateUnit: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;
  const { name, shortCode } = req.body;
  const username = "admin";

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "Unit ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const existing = await db.collection("units").findOne({ _id: objectId });

    if (!existing) {
      return res
        .status(404)
        .json({ success: false, message: "Unit not found" });
    }

    // Check for duplicate name
    if (name && name !== existing.name) {
      const duplicate = await db
        .collection("units")
        .findOne({ name: name.trim() });
      if (duplicate) {
        return res
          .status(400)
          .json({
            success: false,
            message: "Unit with this name already exists",
          });
      }
    }

    const changes: Record<string, any> = {};
    if (name && name !== existing.name)
      changes.name = { from: existing.name, to: name };
    if (shortCode && shortCode !== existing.shortCode)
      changes.shortCode = { from: existing.shortCode, to: shortCode };

    const updateData: Partial<Unit> = {
      updatedAt: new Date(),
    };

    if (name) updateData.name = name.trim();
    if (shortCode) updateData.shortCode = shortCode.trim().toUpperCase();

    const editLogEntry = {
      timestamp: new Date(),
      editedBy: username,
      changes,
    };

    const result = await db.collection("units").findOneAndUpdate(
      { _id: objectId },
      {
        $set: updateData,
        $push: { editLog: editLogEntry } as any,
      },
      { returnDocument: "after" },
    );

    res.json({
      success: true,
      message: "Unit updated successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error updating unit:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE unit
export const handleDeleteUnit: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "Unit ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const result = await db.collection("units").deleteOne({ _id: objectId });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Unit not found" });
    }

    res.json({ success: true, message: "Unit deleted successfully" });
  } catch (error) {
    console.error("Error deleting unit:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE all units (hard delete)
export const handleClearAllUnits: RequestHandler = async (req, res) => {
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

    // Hard delete: permanently remove all units
    const result = await db
      .collection("units")
      .deleteMany({});

    res.json({
      success: true,
      message: `Permanently deleted ${result.deletedCount} units`,
    });
  } catch (error) {
    console.error("Error clearing units:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

