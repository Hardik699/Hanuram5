import { RequestHandler } from "express";
import { getDB, getConnectionStatus } from "../db";
import { ObjectId } from "mongodb";
import * as XLSX from "xlsx";

export interface Vendor {
  _id?: ObjectId;
  name: string;
  personName: string;
  mobileNumber: string;
  email?: string;
  location: string;
  gstNumber?: string;
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  editLog: Array<{
    timestamp: Date;
    editedBy: string;
    changes: Record<string, any>;
  }>;
}

// GET all vendors
export const handleGetVendors: RequestHandler = async (_req, res) => {
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

    const vendors = await db
      .collection("vendors")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ success: true, data: vendors });
  } catch (error) {
    console.error("Error fetching vendors:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// POST create vendor
export const handleCreateVendor: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { name, personName, mobileNumber, email, location, gstNumber } =
    req.body;
  const username = "admin";

  if (!name || !name.trim()) {
    return res
      .status(400)
      .json({ success: false, message: "Vendor name is required" });
  }

  if (!personName || !personName.trim()) {
    return res
      .status(400)
      .json({ success: false, message: "Person name is required" });
  }

  if (!mobileNumber || !mobileNumber.trim()) {
    return res
      .status(400)
      .json({ success: false, message: "Mobile number is required" });
  }

  if (!location || !location.trim()) {
    return res
      .status(400)
      .json({ success: false, message: "Location/Address is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    // Check for duplicate name
    const existing = await db
      .collection("vendors")
      .findOne({ name: name.trim() });
    if (existing) {
      return res.status(400).json({
        success: false,
        message: "Vendor with this name already exists",
      });
    }

    const newVendor: Vendor = {
      name: name.trim(),
      personName: personName.trim(),
      mobileNumber: mobileNumber.trim(),
      email: email?.trim() || "",
      location: location.trim(),
      gstNumber: gstNumber?.trim() || "",
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: username,
      editLog: [],
    };

    const result = await db.collection("vendors").insertOne(newVendor);
    res.json({
      success: true,
      message: "Vendor created successfully",
      data: { _id: result.insertedId, ...newVendor },
    });
  } catch (error) {
    console.error("Error creating vendor:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// PUT update vendor
export const handleUpdateVendor: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;
  const { name, personName, mobileNumber, email, location, gstNumber } =
    req.body;
  const username = "admin";

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "Vendor ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const existing = await db.collection("vendors").findOne({ _id: objectId });

    if (!existing) {
      return res
        .status(404)
        .json({ success: false, message: "Vendor not found" });
    }

    // Check for duplicate name
    if (name && name !== existing.name) {
      const duplicate = await db
        .collection("vendors")
        .findOne({ name: name.trim() });
      if (duplicate) {
        return res.status(400).json({
          success: false,
          message: "Vendor with this name already exists",
        });
      }
    }

    const changes: Record<string, any> = {};
    if (name && name !== existing.name)
      changes.name = { from: existing.name, to: name };
    if (personName && personName !== existing.personName)
      changes.personName = { from: existing.personName, to: personName };
    if (mobileNumber && mobileNumber !== existing.mobileNumber)
      changes.mobileNumber = { from: existing.mobileNumber, to: mobileNumber };
    if (email !== undefined && email !== existing.email)
      changes.email = { from: existing.email, to: email };
    if (location && location !== existing.location)
      changes.location = { from: existing.location, to: location };
    if (gstNumber !== undefined && gstNumber !== existing.gstNumber)
      changes.gstNumber = { from: existing.gstNumber, to: gstNumber };

    const updateData: Partial<Vendor> = {
      updatedAt: new Date(),
    };

    if (name) updateData.name = name.trim();
    if (personName) updateData.personName = personName.trim();
    if (mobileNumber) updateData.mobileNumber = mobileNumber.trim();
    if (email !== undefined) updateData.email = email?.trim() || "";
    if (location) updateData.location = location.trim();
    if (gstNumber !== undefined) updateData.gstNumber = gstNumber?.trim() || "";

    const editLogEntry = {
      timestamp: new Date(),
      editedBy: username,
      changes,
    };

    const result = await db.collection("vendors").findOneAndUpdate(
      { _id: objectId },
      {
        $set: updateData,
        $push: { editLog: editLogEntry } as any,
      },
      { returnDocument: "after" },
    );

    res.json({
      success: true,
      message: "Vendor updated successfully",
      data: result,
    });
  } catch (error) {
    console.error("Error updating vendor:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE vendor
export const handleDeleteVendor: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  const { id } = req.params;

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "Vendor ID is required" });
  }

  try {
    const db = getDB();
    if (!db)
      return res
        .status(503)
        .json({ success: false, message: "Database error" });

    const objectId = new ObjectId(id as string);
    const result = await db.collection("vendors").deleteOne({ _id: objectId });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Vendor not found" });
    }

    res.json({ success: true, message: "Vendor deleted successfully" });
  } catch (error) {
    console.error("Error deleting vendor:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// DELETE all vendors
export const handleClearAllVendors: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  try {
    const db = getDB();
    if (!db) {
      return res
        .status(503)
        .json({ success: false, message: "Database error" });
    }

    const result = await db.collection("vendors").deleteMany({});

    return res.status(200).json({
      success: true,
      message: `All vendors cleared successfully. ${result.deletedCount} vendors deleted.`,
      deletedCount: result.deletedCount,
    });
  } catch (error) {
    console.error("Error clearing vendors:", error);
    return res
      .status(500)
      .json({ success: false, message: "Server error" });
  }
};

// UPLOAD vendors from Excel file
export const handleUploadVendorsExcel: RequestHandler = async (req, res) => {
  if (getConnectionStatus() !== "connected") {
    return res
      .status(503)
      .json({ success: false, message: "Database not connected" });
  }

  try {
    const db = getDB();
    if (!db) {
      return res
        .status(503)
        .json({ success: false, message: "Database error" });
    }

    const file = (req as any).file;
    if (!file) {
      return res
        .status(400)
        .json({ success: false, message: "No file uploaded" });
    }

    // Parse Excel file
    const workbook = XLSX.read(file.buffer, { type: "buffer" });
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const rows = XLSX.utils.sheet_to_json(sheet) as Record<string, any>[];

    if (rows.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "Excel file is empty" });
    }

    // Column mapping - adjust based on your Excel headers
    const columnMap: Record<string, string> = {
      "Vendor Name": "name",
      "Contact Person": "personName",
      "Mobile Number": "mobileNumber",
      "Phone": "mobileNumber",
      Email: "email",
      Location: "location",
      Address: "location",
      "GST Number": "gstNumber",
      GST: "gstNumber",
    };

    const created: Vendor[] = [];
    const skipped: Array<{
      row: number;
      reason: string;
      data: Record<string, any>;
    }> = [];

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const rowNum = i + 2; // +2 because Excel is 1-indexed and includes header

      try {
        // Map Excel columns to vendor fields
        let vendorData: Partial<Vendor> = {
          createdAt: new Date(),
          updatedAt: new Date(),
          createdBy: "admin",
          editLog: [],
        };

        // Find and map column values
        for (const [excelCol, dbField] of Object.entries(columnMap)) {
          if (row[excelCol] !== undefined && row[excelCol] !== null) {
            (vendorData as any)[dbField] = String(row[excelCol]).trim();
          }
        }

        // Also check for exact field name matches
        if (row.name !== undefined && !vendorData.name) {
          vendorData.name = String(row.name).trim();
        }
        if (row.personName !== undefined && !vendorData.personName) {
          vendorData.personName = String(row.personName).trim();
        }
        if (row.mobileNumber !== undefined && !vendorData.mobileNumber) {
          vendorData.mobileNumber = String(row.mobileNumber).trim();
        }
        if (row.email !== undefined && !vendorData.email) {
          vendorData.email = String(row.email).trim();
        }
        if (row.location !== undefined && !vendorData.location) {
          vendorData.location = String(row.location).trim();
        }
        if (row.gstNumber !== undefined && !vendorData.gstNumber) {
          vendorData.gstNumber = String(row.gstNumber).trim();
        }

        // Validate required fields
        const errors: string[] = [];
        if (!vendorData.name) errors.push("Vendor name is required");
        if (!vendorData.personName) errors.push("Contact person is required");
        if (!vendorData.mobileNumber)
          errors.push("Mobile number is required");
        if (!vendorData.location) errors.push("Location is required");

        if (errors.length > 0) {
          skipped.push({
            row: rowNum,
            reason: errors.join("; "),
            data: row,
          });
          continue;
        }

        // Check for duplicate
        const existingVendor = await db
          .collection("vendors")
          .findOne({ name: vendorData.name });
        if (existingVendor) {
          skipped.push({
            row: rowNum,
            reason: "Vendor with this name already exists",
            data: row,
          });
          continue;
        }

        // Insert vendor
        const result = await db.collection("vendors").insertOne(vendorData as Vendor);
        created.push({
          _id: result.insertedId,
          ...vendorData,
        } as Vendor);
      } catch (rowError) {
        skipped.push({
          row: rowNum,
          reason: rowError instanceof Error ? rowError.message : "Unknown error",
          data: row,
        });
      }
    }

    return res.status(200).json({
      success: true,
      message: `Vendor upload completed. Created: ${created.length}, Skipped: ${skipped.length}`,
      created: created.length,
      skipped: skipped.length,
      skippedRows: skipped,
    });
  } catch (error) {
    console.error("Error uploading vendors:", error);
    return res
      .status(500)
      .json({
        success: false,
        message: error instanceof Error ? error.message : "Server error",
      });
  }
};

