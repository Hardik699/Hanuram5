# Labour Cost Database Location - Visual Guide

## 📍 Exact Location in Database

```
┌─────────────────────────────────────────────────────────────────┐
│                    MONGODB ATLAS                                │
│                  (Cloud Database)                               │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DATABASE: faction_app                        │
│                                                                 │
│  This is where all your application data is stored             │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                  COLLECTION: recipes                            │
│                                                                 │
│  This collection contains all recipe documents                 │
│  (Each recipe is a separate document)                          │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              DOCUMENT: RES048 (BADAM KATLI)                    │
│                                                                 │
│  {                                                              │
│    "_id": ObjectId("..."),                                     │
│    "code": "RES048",                                           │
│    "name": "BADAM KATLI",                                      │
│    "batchSize": 1.7,                                           │
│    "unitId": "...",                                            │
│    "unitName": "kg",                                           │
│    "yield": 1.6,                                               │
│    "totalRawMaterialCost": 883.34,                             │
│    "pricePerUnit": 552.08,                                     │
│                                                                 │
│    ┌─────────────────────────────────────────────────────────┐ │
│    │ LABOUR COSTS SAVED HERE:                                │ │
│    │                                                         │ │
│    │ "productionLabourCostPerKg": 508,  ← PRODUCTION COST   │ │
│    │ "packingLabourCostPerKg": 1,       ← PACKING COST      │ │
│    │                                                         │ │
│    └─────────────────────────────────────────────────────────┘ │
│                                                                 │
│    "createdAt": ISODate("2024-01-15T10:30:00Z"),              │
│    "updatedAt": ISODate("2024-01-20T15:45:00Z"),              │
│    "items": [...]                                              │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔍 How to Find It

### Method 1: MongoDB Atlas Web Interface

**Step 1**: Go to https://cloud.mongodb.com

**Step 2**: Click on your cluster
```
┌─────────────────────────────────────────┐
│  My Cluster                             │
│  ├─ Browse Collections                  │ ← Click here
│  ├─ Metrics                             │
│  └─ ...                                 │
└─────────────────────────────────────────┘
```

**Step 3**: Navigate to the database
```
┌─────────────────────────────────────────┐
│  faction_app (database)                 │
│  ├─ recipes (collection)                │ ← Click here
│  ├─ raw_materials                       │
│  ├─ quotations                          │
│  └─ ...                                 │
└─────────────────────────────────────────┘
```

**Step 4**: Find the recipe
```
┌─────────────────────────────────────────┐
│  recipes collection                     │
│  ├─ RES001 (RECIPE 1)                   │
│  ├─ RES002 (RECIPE 2)                   │
│  ├─ RES048 (BADAM KATLI)                │ ← Click here
│  └─ ...                                 │
└─────────────────────────────────────────┘
```

**Step 5**: View the document
```
┌─────────────────────────────────────────┐
│  RES048 Document                        │
│  ├─ _id: ObjectId(...)                  │
│  ├─ code: "RES048"                      │
│  ├─ name: "BADAM KATLI"                 │
│  ├─ batchSize: 1.7                      │
│  ├─ ...                                 │
│  ├─ productionLabourCostPerKg: 508      │ ← HERE
│  ├─ packingLabourCostPerKg: 1           │ ← HERE
│  └─ ...                                 │
└─────────────────────────────────────────┘
```

---

## 📊 Data Structure

### Complete Recipe Document Structure

```javascript
{
  // Unique identifier
  "_id": ObjectId("507f1f77bcf86cd799439011"),
  
  // Recipe basic info
  "code": "RES048",
  "name": "BADAM KATLI",
  "recipeType": "master",
  
  // Batch and yield info
  "batchSize": 1.7,
  "unitId": "507f1f77bcf86cd799439012",
  "unitName": "kg",
  "yield": 1.6,
  "moisturePercentage": 0,
  
  // Cost information
  "totalRawMaterialCost": 883.34,
  "pricePerUnit": 552.08,
  
  // ⭐ LABOUR COSTS (What we're looking for)
  "productionLabourCostPerKg": 508,
  "packingLabourCostPerKg": 1,
  
  // Timestamps
  "createdAt": ISODate("2024-01-15T10:30:00.000Z"),
  "updatedAt": ISODate("2024-01-20T15:45:00.000Z"),
  
  // Recipe items (raw materials)
  "items": [
    {
      "rawMaterialId": "507f1f77bcf86cd799439013",
      "rawMaterialName": "Khaand - Sugar Sulphur Free Whole",
      "rawMaterialCode": "RM00035",
      "quantity": 0.65,
      "unitId": "507f1f77bcf86cd799439014",
      "unitName": "kg",
      "price": 40.30,
      "totalPrice": 26.20
    },
    {
      "rawMaterialId": "507f1f77bcf86cd799439015",
      "rawMaterialName": "Badam Premium-Almond - Premium",
      "rawMaterialCode": "RM00307",
      "quantity": 1,
      "unitId": "507f1f77bcf86cd799439014",
      "unitName": "kg",
      "price": 857.14,
      "totalPrice": 857.14
    }
  ]
}
```

---

## 🎯 Key Fields

| Field | Type | Value | Location |
|-------|------|-------|----------|
| `productionLabourCostPerKg` | Number | 508 | recipes → RES048 |
| `packingLabourCostPerKg` | Number | 1 | recipes → RES048 |

---

## ✅ Verification Checklist

- [ ] Logged into MongoDB Atlas
- [ ] Selected cluster
- [ ] Clicked "Browse Collections"
- [ ] Selected database: `faction_app`
- [ ] Selected collection: `recipes`
- [ ] Found document with code: `RES048`
- [ ] Expanded the document
- [ ] Found field: `productionLabourCostPerKg` with value `508`
- [ ] Found field: `packingLabourCostPerKg` with value `1`

If all checkboxes are checked ✅, the labour costs ARE saved in the database!

---

## 🔗 Database Hierarchy

```
MongoDB Atlas (Cloud)
│
└─ Cluster (Your MongoDB Server)
   │
   └─ faction_app (Database)
      │
      ├─ recipes (Collection)
      │  │
      │  ├─ RES001 (Document)
      │  ├─ RES002 (Document)
      │  ├─ RES048 (Document) ← BADAM KATLI
      │  │  ├─ _id
      │  │  ├─ code: "RES048"
      │  │  ├─ name: "BADAM KATLI"
      │  │  ├─ productionLabourCostPerKg: 508 ← HERE
      │  │  ├─ packingLabourCostPerKg: 1 ← HERE
      │  │  └─ ... other fields
      │  │
      │  └─ ... more recipes
      │
      ├─ raw_materials (Collection)
      ├─ quotations (Collection)
      ├─ recipe_items (Collection)
      └─ ... other collections
```

---

## 📝 Summary

**Where Labour Costs Are Saved:**

```
MongoDB Atlas
  → faction_app (database)
    → recipes (collection)
      → RES048 (document)
        → productionLabourCostPerKg: 508
        → packingLabourCostPerKg: 1
```

**To verify:**
1. Go to MongoDB Atlas
2. Browse Collections
3. Select faction_app → recipes
4. Find RES048
5. Look for productionLabourCostPerKg and packingLabourCostPerKg fields

**If you see these fields with values, labour costs ARE saved!** ✅
