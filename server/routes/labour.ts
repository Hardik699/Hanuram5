import { RequestHandler } from "express";
import { ObjectId } from "mongodb";
import { getDB } from "../db";

// Generate unique labour ID (EP001, EP002, etc.)
async function generateLabourId(): Promise<string> {
  const db = getDB();
  if (!db) throw new Error("Database connection failed");

  const lastLabour = await db
    .collection("labour")
    .findOne({}, { sort: { code: -1 } });

  if (!lastLabour) {
    return "EP001";
  }

  const lastCode = lastLabour.code as string;
  const numberPart = parseInt(lastCode.substring(2), 10);
  const newNumber = (numberPart + 1).toString().padStart(3, "0");
  return `EP${newNumber}`;
}

export const handleGetLabour: RequestHandler = async (_req, res) => {
  try {
    const db = getDB();
    if (!db) {
      return res.status(503).json({ success: false, message: "Database connection failed" });
    }

    const labourList = await db
      .collection("labour")
      .find({})
      .sort({ code: 1 })
      .toArray();

    return res.json({
      success: true,
      data: labourList.map((item) => ({
        ...item,
        id: item._id.toString(),
      })),
    });
  } catch (error) {
    console.error("Error fetching labour:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch labour" });
  }
};

export const handleGetLabourById: RequestHandler = async (req, res) => {
  try {
    const db = getDB();
    if (!db) {
      return res.status(503).json({ success: false, message: "Database connection failed" });
    }

    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid labour ID" });
    }

    const labour = await db.collection("labour").findOne({ _id: new ObjectId(id) });

    if (!labour) {
      return res.status(404).json({ success: false, message: "Labour not found" });
    }

    return res.json({
      success: true,
      data: { ...labour, id: labour._id.toString() },
    });
  } catch (error) {
    console.error("Error fetching labour by id:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch labour" });
  }
};

export const handleCreateLabour: RequestHandler = async (req, res) => {
  try {
    const db = getDB();
    if (!db) {
      return res.status(503).json({ success: false, message: "Database connection failed" });
    }

    const { name, department, salaryPerDay } = req.body;

    // Validation
    if (!name || !department || !salaryPerDay) {
      return res
        .status(400)
        .json({ success: false, message: "Name, department, and salary are required" });
    }

    const code = await generateLabourId();

    const labourData = {
      code,
      name,
      department,
      salaryPerDay: parseFloat(salaryPerDay),
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: "admin",
      editLog: [],
    };

    const result = await db.collection("labour").insertOne(labourData);

    return res.status(201).json({
      success: true,
      data: {
        ...labourData,
        id: result.insertedId.toString(),
        _id: result.insertedId,
      },
    });
  } catch (error) {
    console.error("Error creating labour:", error);
    return res.status(500).json({ success: false, message: "Failed to create labour" });
  }
};

export const handleUpdateLabour: RequestHandler = async (req, res) => {
  try {
    const db = getDB();
    if (!db) {
      return res.status(503).json({ success: false, message: "Database connection failed" });
    }

    const { id } = req.params;
    const { name, department, salaryPerDay } = req.body;
    const username = req.body.editedBy || "admin";

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid labour ID" });
    }

    const existing = await db.collection("labour").findOne({ _id: new ObjectId(id) });
    if (!existing) {
      return res.status(404).json({ success: false, message: "Labour not found" });
    }

    // Track changes
    const changes: Record<string, any> = {};
    if (name && name !== existing.name) changes.name = { from: existing.name, to: name };
    if (department && department !== existing.department) changes.department = { from: existing.department, to: department };
    if (salaryPerDay && parseFloat(salaryPerDay) !== existing.salaryPerDay)
      changes.salaryPerDay = { from: existing.salaryPerDay, to: parseFloat(salaryPerDay) };

    const updateData: any = { updatedAt: new Date() };
    if (name) updateData.name = name;
    if (department) updateData.department = department;
    if (salaryPerDay) updateData.salaryPerDay = parseFloat(salaryPerDay);

    const editLogEntry = { timestamp: new Date(), editedBy: username, changes };

    const result = await db.collection("labour").findOneAndUpdate(
      { _id: new ObjectId(id) },
      {
        $set: updateData,
        $push: { editLog: editLogEntry } as any,
      },
      { returnDocument: "after" },
    );

    if (!result) {
      return res.status(404).json({ success: false, message: "Labour not found" });
    }

    return res.json({
      success: true,
      data: { ...result, id: result._id.toString() },
    });
  } catch (error) {
    console.error("Error updating labour:", error);
    return res.status(500).json({ success: false, message: "Failed to update labour" });
  }
};

export const handleDeleteLabour: RequestHandler = async (req, res) => {
  try {
    const db = getDB();
    if (!db) {
      return res.status(503).json({ success: false, message: "Database connection failed" });
    }

    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid labour ID" });
    }

    const result = await db
      .collection("labour")
      .deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Labour not found" });
    }

    // Also delete any recipe labour associations
    await db
      .collection("recipe_labour")
      .deleteMany({ labourId: new ObjectId(id) });

    return res.json({
      success: true,
      message: "Labour deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting labour:", error);
    return res.status(500).json({ success: false, message: "Failed to delete labour" });
  }
};

export const handleGetRecipeLabour: RequestHandler = async (req, res) => {
  try {
    const db = getDB();
    if (!db) {
      return res.status(503).json({ success: false, message: "Database connection failed" });
    }

    const { recipeId } = req.params;
    const { type } = req.query; // 'production' or 'packing'

    if (!ObjectId.isValid(recipeId)) {
      return res.status(400).json({ success: false, message: "Invalid recipe ID" });
    }

    const query: any = { recipeId: new ObjectId(recipeId) };
    if (type) {
      query.type = type; // 'production' or 'packing'
    }

    const recipeLabour = await db
      .collection("recipe_labour")
      .aggregate([
        { $match: query },
        {
          $lookup: {
            from: "labour",
            localField: "labourId",
            foreignField: "_id",
            as: "labour",
          },
        },
        { $unwind: "$labour" },
      ])
      .toArray();

    return res.json({
      success: true,
      data: recipeLabour.map((item) => ({
        ...item,
        id: item._id.toString(),
      })),
    });
  } catch (error) {
    console.error("Error fetching recipe labour:", error);
    return res
      .status(500)
      .json({ success: false, message: "Failed to fetch recipe labour" });
  }
};

export const handleAddRecipeLabour: RequestHandler = async (req, res) => {
  try {
    const db = getDB();
    if (!db) {
      return res.status(503).json({ success: false, message: "Database connection failed" });
    }

    const { recipeId, labourId, type } = req.body;

    // Validation
    if (!recipeId || !labourId || !type) {
      return res.status(400).json({
        success: false,
        message: "recipeId, labourId, and type (production/packing) are required",
      });
    }

    if (!ObjectId.isValid(recipeId) || !ObjectId.isValid(labourId)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid recipe or labour ID" });
    }

    if (type !== "production" && type !== "packing") {
      return res
        .status(400)
        .json({ success: false, message: "Type must be 'production' or 'packing'" });
    }

    // Check if labour already exists for this recipe and type
    const existingLabour = await db
      .collection("recipe_labour")
      .findOne({
        recipeId: new ObjectId(recipeId),
        labourId: new ObjectId(labourId),
        type,
      });

    if (existingLabour) {
      return res.status(400).json({
        success: false,
        message: "This labour is already added to the recipe",
      });
    }

    // Get labour details
    const labour = await db
      .collection("labour")
      .findOne({ _id: new ObjectId(labourId) });

    if (!labour) {
      return res.status(404).json({ success: false, message: "Labour not found" });
    }

    const recipeLabourData = {
      recipeId: new ObjectId(recipeId),
      labourId: new ObjectId(labourId),
      type,
      labourName: labour.name,
      department: labour.department,
      salaryPerDay: labour.salaryPerDay,
      createdAt: new Date(),
    };

    const result = await db
      .collection("recipe_labour")
      .insertOne(recipeLabourData);

    return res.status(201).json({
      success: true,
      data: {
        ...recipeLabourData,
        id: result.insertedId.toString(),
        _id: result.insertedId,
      },
    });
  } catch (error) {
    console.error("Error adding recipe labour:", error);
    return res.status(500).json({ success: false, message: "Failed to add recipe labour" });
  }
};

export const handleDeleteRecipeLabour: RequestHandler = async (req, res) => {
  try {
    const db = getDB();
    if (!db) {
      return res.status(503).json({ success: false, message: "Database connection failed" });
    }

    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid recipe labour ID" });
    }

    const result = await db
      .collection("recipe_labour")
      .deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Recipe labour not found" });
    }

    return res.json({
      success: true,
      message: "Recipe labour deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting recipe labour:", error);
    return res
      .status(500)
      .json({ success: false, message: "Failed to delete recipe labour" });
  }
};
