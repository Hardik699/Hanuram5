import { MongoClient } from 'mongodb';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://Hardik:Hardik1@cluster0.ezeb8ew.mongodb.net/?appName=Cluster0';

const client = new MongoClient(MONGODB_URI);
try {
  await client.connect();
  const db = client.db('faction_app');

  // Check idempotency
  const existing = await db.collection('recipes').findOne({ name: { $in: ['Fulwadi', 'Kaju Katli', 'Methi Mathri'] } });
  if (existing) {
    console.log('Sample data already present');
    process.exit(0);
  }

  // Units
  const units = ['kg', 'g', 'nos'];
  for (const name of units) {
    await db.collection('units').updateOne({ name }, { $setOnInsert: { name } }, { upsert: true });
  }
  const unitKg = await db.collection('units').findOne({ name: 'kg' });

  // Category & subcategories
  const category = { name: 'Snacks & Sweets' };
  await db.collection('categories').updateOne({ name: category.name }, { $setOnInsert: category }, { upsert: true });
  const catDoc = await db.collection('categories').findOne({ name: category.name });

  const subcategories = [
    { name: 'Namkeen', categoryId: catDoc._id.toString() },
    { name: 'Mithai', categoryId: catDoc._id.toString() },
  ];
  for (const s of subcategories) {
    await db.collection('subcategories').updateOne({ name: s.name }, { $setOnInsert: { ...s } }, { upsert: true });
  }
  const subNamkeen = await db.collection('subcategories').findOne({ name: 'Namkeen' });
  const subMithai = await db.collection('subcategories').findOne({ name: 'Mithai' });

  // Vendors
  const vendors = ['Local Supplier A', 'Cashew Supplier'];
  for (const v of vendors) {
    await db.collection('vendors').updateOne({ name: v }, { $setOnInsert: { name: v } }, { upsert: true });
  }
  const vendorA = await db.collection('vendors').findOne({ name: 'Local Supplier A' });
  const vendorCashew = await db.collection('vendors').findOne({ name: 'Cashew Supplier' });

  // Raw materials
  const rawMaterials = [
    { name: 'Besan (Gram Flour)', subCategoryId: subNamkeen._id.toString(), subCategoryName: subNamkeen.name },
    { name: 'Ghee', subCategoryId: subMithai._id.toString(), subCategoryName: subMithai.name },
    { name: 'Sugar', subCategoryId: subMithai._id.toString(), subCategoryName: subMithai.name },
    { name: 'Cashew (Kaju)', subCategoryId: subMithai._id.toString(), subCategoryName: subMithai.name },
    { name: 'Maida (All-purpose Flour)', subCategoryId: subNamkeen._id.toString(), subCategoryName: subNamkeen.name },
    { name: 'Dried Methi (Fenugreek)', subCategoryId: subNamkeen._id.toString(), subCategoryName: subNamkeen.name },
    { name: 'Edible Oil', subCategoryId: subNamkeen._id.toString(), subCategoryName: subNamkeen.name },
  ];

  const insertedRMs = [];
  for (const rm of rawMaterials) {
    await db.collection('raw_materials').updateOne(
      { name: rm.name },
      { $setOnInsert: { ...rm, code: rm.name.slice(0, 3).toUpperCase(), categoryId: catDoc._id.toString(), categoryName: catDoc.name, unitId: unitKg._id.toString(), unitName: unitKg.name, createdAt: new Date(), updatedAt: new Date(), createdBy: 'demo' } },
      { upsert: true }
    );
    const doc = await db.collection('raw_materials').findOne({ name: rm.name });
    insertedRMs.push(doc);
  }

  // Vendor prices
  const prices = [
    { rmName: 'Besan (Gram Flour)', vendor: vendorA, quantity: 25, pricePerUnit: 120 },
    { rmName: 'Ghee', vendor: vendorA, quantity: 25, pricePerUnit: 700 },
    { rmName: 'Sugar', vendor: vendorA, quantity: 25, pricePerUnit: 40 },
    { rmName: 'Cashew (Kaju)', vendor: vendorCashew, quantity: 25, pricePerUnit: 2000 },
    { rmName: 'Maida (All-purpose Flour)', vendor: vendorA, quantity: 25, pricePerUnit: 60 },
    { rmName: 'Dried Methi (Fenugreek)', vendor: vendorA, quantity: 25, pricePerUnit: 250 },
    { rmName: 'Edible Oil', vendor: vendorA, quantity: 25, pricePerUnit: 120 },
  ];

  for (const p of prices) {
    const rmDoc = insertedRMs.find((x) => x.name === p.rmName);
    if (!rmDoc) continue;

    const vendorPrice = {
      rawMaterialId: rmDoc._id.toString(),
      vendorId: p.vendor._id.toString(),
      vendorName: p.vendor.name,
      quantity: p.quantity,
      unitId: unitKg._id.toString(),
      unitName: unitKg.name,
      price: p.pricePerUnit,
      addedDate: new Date(),
      createdBy: 'demo',
    };

    await db.collection('rm_vendor_prices').insertOne(vendorPrice);

    await db.collection('raw_materials').updateOne(
      { _id: rmDoc._id },
      { $set: { lastAddedPrice: p.pricePerUnit, lastVendorName: p.vendor.name, lastPriceDate: new Date(), updatedAt: new Date() } }
    );
  }

  // Recipes
  const findRM = (name) => insertedRMs.find(x => x.name === name);
  const besan = findRM('Besan (Gram Flour)');
  const ghee = findRM('Ghee');
  const sugar = findRM('Sugar');
  const kaju = findRM('Cashew (Kaju)');
  const maida = findRM('Maida (All-purpose Flour)');
  const methi = findRM('Dried Methi (Fenugreek)');
  const oil = findRM('Edible Oil');

  const recipesToCreate = [
    {
      name: 'Fulwadi',
      batchSize: 10,
      unitId: unitKg._id.toString(),
      unitName: unitKg.name,
      items: [
        { rawMaterialId: besan._id.toString(), rawMaterialName: besan.name, rawMaterialCode: besan.code, quantity: 6, unitId: unitKg._id.toString(), unitName: unitKg.name, price: besan.lastAddedPrice, totalPrice: 6 * besan.lastAddedPrice, yield: 6 },
        { rawMaterialId: ghee._id.toString(), rawMaterialName: ghee.name, rawMaterialCode: ghee.code, quantity: 1, unitId: unitKg._id.toString(), unitName: unitKg.name, price: ghee.lastAddedPrice, totalPrice: 1 * ghee.lastAddedPrice, yield: 1 },
        { rawMaterialId: sugar._id.toString(), rawMaterialName: sugar.name, rawMaterialCode: sugar.code, quantity: 1, unitId: unitKg._id.toString(), unitName: unitKg.name, price: sugar.lastAddedPrice, totalPrice: 1 * sugar.lastAddedPrice, yield: 1 },
      ],
    },
    {
      name: 'Kaju Katli',
      batchSize: 10,
      unitId: unitKg._id.toString(),
      unitName: unitKg.name,
      items: [
        { rawMaterialId: kaju._id.toString(), rawMaterialName: kaju.name, rawMaterialCode: kaju.code, quantity: 6, unitId: unitKg._id.toString(), unitName: unitKg.name, price: kaju.lastAddedPrice, totalPrice: 6 * kaju.lastAddedPrice, yield: 6 },
        { rawMaterialId: sugar._id.toString(), rawMaterialName: sugar.name, rawMaterialCode: sugar.code, quantity: 3, unitId: unitKg._id.toString(), unitName: unitKg.name, price: sugar.lastAddedPrice, totalPrice: 3 * sugar.lastAddedPrice, yield: 3 },
        { rawMaterialId: ghee._id.toString(), rawMaterialName: ghee.name, rawMaterialCode: ghee.code, quantity: 0.5, unitId: unitKg._id.toString(), unitName: unitKg.name, price: ghee.lastAddedPrice, totalPrice: 0.5 * ghee.lastAddedPrice, yield: 0.5 },
      ],
    },
    {
      name: 'Methi Mathri',
      batchSize: 10,
      unitId: unitKg._id.toString(),
      unitName: unitKg.name,
      items: [
        { rawMaterialId: maida._id.toString(), rawMaterialName: maida.name, rawMaterialCode: maida.code, quantity: 6, unitId: unitKg._id.toString(), unitName: unitKg.name, price: maida.lastAddedPrice, totalPrice: 6 * maida.lastAddedPrice, yield: 6 },
        { rawMaterialId: methi._id.toString(), rawMaterialName: methi.name, rawMaterialCode: methi.code, quantity: 0.2, unitId: unitKg._id.toString(), unitName: unitKg.name, price: methi.lastAddedPrice, totalPrice: 0.2 * methi.lastAddedPrice, yield: 0.2 },
        { rawMaterialId: oil._id.toString(), rawMaterialName: oil.name, rawMaterialCode: oil.code, quantity: 1, unitId: unitKg._id.toString(), unitName: unitKg.name, price: oil.lastAddedPrice, totalPrice: 1 * oil.lastAddedPrice, yield: 1 },
      ],
    }
  ];

  for (const r of recipesToCreate) {
    const totalRawMaterialCost = r.items.reduce((sum, it) => sum + (it.totalPrice || 0), 0);
    const pricePerUnit = r.batchSize > 0 ? totalRawMaterialCost / r.batchSize : 0;

    const recipeDoc = {
      code: `RES${Math.floor(Math.random() * 10000)}`,
      name: r.name,
      batchSize: r.batchSize,
      unitId: r.unitId,
      unitName: r.unitName,
      totalRawMaterialCost,
      pricePerUnit: parseFloat(pricePerUnit.toFixed(2)),
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: 'demo',
    };

    const recipeResult = await db.collection('recipes').insertOne(recipeDoc);
    const recipeId = recipeResult.insertedId.toString();
    const itemsWithRecipeId = r.items.map((it) => ({ ...it, recipeId }));
    await db.collection('recipe_items').insertMany(itemsWithRecipeId);

    const historySnapshot = {
      recipeId,
      recipeCode: recipeDoc.code,
      recipeName: recipeDoc.name,
      snapshotDate: new Date(),
      totalRawMaterialCost,
      pricePerUnit: recipeDoc.pricePerUnit,
      items: r.items,
      createdReason: 'initial_creation',
      changedBy: 'demo',
    };
    await db.collection('recipe_history').insertOne(historySnapshot);
  }

  console.log('Sample data populated');
} catch (err) {
  console.error('Error populating sample data:', err);
} finally {
  await client.close();
}
