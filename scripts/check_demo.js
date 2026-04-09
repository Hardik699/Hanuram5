const { MongoClient } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://Hardik:Hardik1@cluster0.ezeb8ew.mongodb.net/?appName=Cluster0';
(async () => {
  const client = new MongoClient(MONGODB_URI);
  try {
    await client.connect();
    const db = client.db('faction_app');

    const recipes = await db.collection('recipes').find({ name: { $in: ['Fulwadi', 'Kaju Katli', 'Methi Mathri'] } }).toArray();
    console.log('Found recipes:', recipes.map(r => r.name));

    const rms = await db.collection('raw_materials').find({ name: { $in: ['Besan (Gram Flour)', 'Ghee', 'Sugar', 'Cashew (Kaju)', 'Maida (All-purpose Flour)', 'Dried Methi (Fenugreek)', 'Edible Oil'] } }).toArray();
    console.log('Found raw materials:', rms.map(r => r.name));

    const vendorPrices = await db.collection('rm_vendor_prices').find({}).limit(5).toArray();
    console.log('Some vendor prices:', vendorPrices.map(p => ({ rm: p.rawMaterialId, price: p.price })));

  } catch (err) {
    console.error('Error checking demo data:', err);
  } finally {
    await client.close();
  }
})();