import fs from 'fs';
import { MongoClient } from 'mongodb';

const filePath = process.argv[2] || './Suppliers_List.csv';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://Hardik:Hardik1@cluster0.ezeb8ew.mongodb.net/?appName=Cluster0';

function parseCSV(content) {
  const lines = content.split(/\r?\n/).filter(Boolean);
  if (lines.length === 0) return [];
  const header = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    // naive CSV parse: split on comma, trim quotes
    const cols = line.split(',').map(c => c.trim().replace(/^"|"$/g, ''));
    const row = {};
    for (let j = 0; j < header.length; j++) {
      row[header[j]] = cols[j] ?? '';
    }
    rows.push(row);
  }
  return rows;
}

try {
  if (!fs.existsSync(filePath)) {
    console.error('CSV file not found:', filePath);
    process.exit(1);
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const data = parseCSV(content);
  if (data.length === 0) {
    console.log('No rows found in CSV');
    process.exit(0);
  }

  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(process.env.MONGODB_DB || 'faction_app');

  let upserted = 0;
  for (const r of data) {
    // Try to map common column names
    const name = r.name || r.Name || r['Vendor'] || r['Supplier'] || r['Vendor Name'] || r['Supplier Name'];
    const personName = r.personName || r.contact || r['Contact Person'] || r['Person'] || r.Person;
    const mobileNumber = r.mobile || r.mobileNumber || r['Mobile'] || r['Phone'] || r['Phone Number'];
    const email = r.email || r['Email'] || r.Email;
    const location = r.location || r.address || r.Address || r['Location'];

    if (!name) continue;

    const vendorDoc = {
      name: name.trim(),
      personName: (personName || '').trim(),
      mobileNumber: (mobileNumber || '').trim(),
      email: (email || '').trim(),
      location: (location || '').trim(),
      updatedAt: new Date(),
    };

    await db.collection('vendors').updateOne({ name: vendorDoc.name }, { $set: vendorDoc, $setOnInsert: { createdAt: new Date(), createdBy: 'import' } }, { upsert: true });
    upserted++;
  }

  console.log('Import complete. Upserted vendors:', upserted);
  await client.close();
  process.exit(0);
} catch (err) {
  console.error('Error importing suppliers:', err);
  process.exit(2);
}
