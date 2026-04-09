# Check Labour Cost Values in Database

## Quick Check - MongoDB Query

### Step 1: Access MongoDB Atlas
1. Go to https://cloud.mongodb.com
2. Login with your credentials
3. Go to your cluster
4. Click "Browse Collections"

### Step 2: Find the Recipe
1. Select database: `faction_app`
2. Select collection: `recipes`
3. Search for recipe code: `RES048`

### Step 3: Look for These Fields

In the recipe document, you should see:

```json
{
  "_id": ObjectId("..."),
  "code": "RES048",
  "name": "BADAM KATLI",
  "batchSize": 1.7,
  "unitId": "...",
  "unitName": "kg",
  "yield": 1.6,
  "totalRawMaterialCost": 883.34,
  "pricePerUnit": 552.08,
  
  // LABOUR COSTS SHOULD BE HERE:
  "productionLabourCostPerKg": 508,
  "packingLabourCostPerKg": 1,
  
  "createdAt": ISODate("..."),
  "updatedAt": ISODate("..."),
  "items": [...]
}
```

---

## If Using MongoDB Compass (Desktop App)

### Step 1: Connect
1. Open MongoDB Compass
2. Connect to your MongoDB URI
3. Select database: `faction_app`
4. Select collection: `recipes`

### Step 2: Search
1. Click "Filter" button
2. Enter: `{ "code": "RES048" }`
3. Click "Apply"

### Step 3: View Document
1. Click on the recipe document
2. Scroll down to find:
   - `productionLabourCostPerKg`
   - `packingLabourCostPerKg`

---

## If Using MongoDB Shell

### Command to Run

```bash
# Connect to MongoDB
mongosh "mongodb+srv://username:password@cluster.mongodb.net/faction_app"

# Find the recipe
db.recipes.findOne({ code: "RES048" })

# You should see output like:
{
  _id: ObjectId("..."),
  code: 'RES048',
  name: 'BADAM KATLI',
  productionLabourCostPerKg: 508,
  packingLabourCostPerKg: 1,
  ... other fields ...
}
```

---

## Expected Output

If labour costs are saved, you'll see:

```json
{
  "productionLabourCostPerKg": 508,
  "packingLabourCostPerKg": 1
}
```

### If NOT Saved

If labour costs are NOT saved, you'll see:

```json
{
  // These fields will be MISSING or have value 0
  "productionLabourCostPerKg": 0,
  "packingLabourCostPerKg": 0
}
```

Or the fields won't exist at all.

---

## What Each Value Means

| Field | Value | Meaning |
|-------|-------|---------|
| `productionLabourCostPerKg` | 508 | Production labour cost per kg is ₹508 |
| `packingLabourCostPerKg` | 1 | Packing labour cost per kg is ₹1 |

---

## Collection Structure

The `recipes` collection in `faction_app` database contains:

```
faction_app
└── recipes (collection)
    └── RES048 (document)
        ├── _id
        ├── code: "RES048"
        ├── name: "BADAM KATLI"
        ├── batchSize: 1.7
        ├── unitId
        ├── unitName: "kg"
        ├── yield: 1.6
        ├── totalRawMaterialCost: 883.34
        ├── pricePerUnit: 552.08
        ├── productionLabourCostPerKg: 508  ← LABOUR COST
        ├── packingLabourCostPerKg: 1       ← LABOUR COST
        ├── createdAt
        ├── updatedAt
        └── items: [...]
```

---

## Step-by-Step Verification

### 1. Go to MongoDB Atlas
- URL: https://cloud.mongodb.com
- Login

### 2. Select Your Cluster
- Click on your cluster name

### 3. Click "Browse Collections"
- Or go to Collections tab

### 4. Navigate to Database
- Database: `faction_app`
- Collection: `recipes`

### 5. Search for Recipe
- Click Filter/Search
- Enter: `{ "code": "RES048" }`
- Press Enter

### 6. View the Document
- Click on the recipe
- Expand the document
- Look for `productionLabourCostPerKg` and `packingLabourCostPerKg`

### 7. Check Values
- If you see `508` and `1`, they're saved ✅
- If you see `0` or missing, they're not saved ❌

---

## Database Location Summary

**Database**: `faction_app`
**Collection**: `recipes`
**Document**: Recipe with code `RES048`
**Fields**: 
- `productionLabourCostPerKg` (should be 508)
- `packingLabourCostPerKg` (should be 1)

---

## Troubleshooting

### Can't find the fields?
1. Make sure you're looking at the right recipe (code: RES048)
2. Make sure you're in the right database (faction_app)
3. Make sure you're in the right collection (recipes)
4. Try refreshing the page

### Fields show 0?
1. Labour costs might not have been saved
2. Check browser console for errors
3. Check if "Save Costs" button was clicked
4. Try saving again

### Can't connect to MongoDB?
1. Check your connection string
2. Verify username and password
3. Check if IP is whitelisted
4. Check if cluster is running

---

## Quick Reference

**To find labour costs in database:**

```
MongoDB Atlas → faction_app → recipes → RES048 → productionLabourCostPerKg & packingLabourCostPerKg
```

**Expected values:**
- productionLabourCostPerKg: 508
- packingLabourCostPerKg: 1

**If you see these values, labour costs ARE saved in the database!** ✅
