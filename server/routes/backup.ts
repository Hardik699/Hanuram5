import { Request, Response } from "express";
import { MongoClient } from "mongodb";
import { getDB } from "../db.js";

const BACKUP_URI =
  "mongodb+srv://Hardik:Hardik3758@cluster0.tdwjqmk.mongodb.net/?appName=Cluster0";

// In-memory progress store keyed by jobId
const progressStore = new Map<string, {
  percent: number;
  message: string;
  done: boolean;
  success?: boolean;
  finalMessage?: string;
}>();

export async function handleBackupStart(req: Request, res: Response) {
  const jobId = Date.now().toString();
  progressStore.set(jobId, { percent: 0, message: "Connecting...", done: false });

  // Start backup in background
  runBackup(jobId);

  res.json({ jobId });
}

export async function handleBackupProgress(req: Request, res: Response) {
  const { jobId } = req.params;
  const progress = progressStore.get(jobId);
  if (!progress) {
    return res.status(404).json({ error: "Job not found" });
  }
  res.json(progress);
  // Clean up after done
  if (progress.done) {
    progressStore.delete(jobId);
  }
}

async function runBackup(jobId: string) {
  const sourceDb = getDB();
  if (!sourceDb) {
    progressStore.set(jobId, { percent: 0, message: "Source DB not connected", done: true, success: false, finalMessage: "Source DB not connected" });
    return;
  }

  let backupClient: MongoClient | null = null;

  try {
    progressStore.set(jobId, { percent: 0, message: "Connecting to backup DB...", done: false });

    backupClient = new MongoClient(BACKUP_URI);
    await backupClient.connect();

    const backupDbName = sourceDb.databaseName || "hanuram_backup";
    const backupDb = backupClient.db(backupDbName);

    const collections = await sourceDb.listCollections().toArray();
    const total = collections.length;
    let done = 0;
    let totalDocs = 0;

    progressStore.set(jobId, { percent: 2, message: `Found ${total} collections`, done: false });

    for (const colInfo of collections) {
      const colName = colInfo.name;
      progressStore.set(jobId, {
        percent: Math.round((done / total) * 95) + 2,
        message: `Backing up: ${colName}`,
        done: false,
      });

      const sourceColl = sourceDb.collection(colName);
      const backupColl = backupDb.collection(colName);
      const docs = await sourceColl.find({}).toArray();

      if (docs.length > 0) {
        await backupColl.drop().catch(() => {});
        await backupColl.insertMany(docs);
        totalDocs += docs.length;
      }

      done++;
      const percent = Math.round((done / total) * 95) + 2;
      progressStore.set(jobId, {
        percent,
        message: `✓ ${colName} (${docs.length} docs)`,
        done: false,
      });
    }

    progressStore.set(jobId, {
      percent: 100,
      message: "Backup complete!",
      done: true,
      success: true,
      finalMessage: `Backup complete! ${totalDocs} documents across ${total} collections.`,
    });
  } catch (err: any) {
    console.error("Backup error:", err);
    progressStore.set(jobId, {
      percent: 0,
      message: err?.message || "Backup failed",
      done: true,
      success: false,
      finalMessage: err?.message || "Backup failed",
    });
  } finally {
    if (backupClient) await backupClient.close().catch(() => {});
  }
}
