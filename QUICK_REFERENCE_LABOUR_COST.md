# Quick Reference - Labour Cost Location

## 🎯 TL;DR (Too Long; Didn't Read)

**Where are labour costs saved?**

```
MongoDB Atlas → faction_app → recipes → RES048 → productionLabourCostPerKg & packingLabourCostPerKg
```

---

## 📍 Location Map

```
┌─────────────────────────────────────────────────────────────────┐
│                    MONGODB ATLAS                                │
│              (https://cloud.mongodb.com)                        │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                  DATABASE: faction_app                          │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                 COLLECTION: recipes                             │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│              DOCUMENT: RES048 (BADAM KATLI)                    │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  FIELDS:                                                        │
│  • productionLabourCostPerKg: 508                              │
│  • packingLabourCostPerKg: 1                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔍 How to Check (3 Steps)

### Step 1: Go to MongoDB Atlas
- URL: https://cloud.mongodb.com
- Login with your credentials

### Step 2: Navigate
- Click your cluster
- Click "Browse Collections"
- Select: `faction_app` → `recipes`

### Step 3: Find Recipe
- Search for: `RES048`
- Look for fields:
  - `productionLabourCostPerKg` (should be 508)
  - `packingLabourCostPerKg` (should be 1)

---

## ✅ What You Should See

```json
{
  "code": "RES048",
  "name": "BADAM KATLI",
  "productionLabourCostPerKg": 508,
  "packingLabourCostPerKg": 1
}
```

**If you see these fields with values → Labour costs ARE saved!** ✅

---

## ❌ What Means NOT Saved

```json
{
  "code": "RES048",
  "name": "BADAM KATLI",
  "productionLabourCostPerKg": 0,
  "packingLabourCostPerKg": 0
}
```

Or fields are missing entirely.

---

## 📊 Database Structure

| Level | Name | Type |
|-------|------|------|
| Cloud | MongoDB Atlas | Service |
| Server | Cluster | MongoDB Server |
| Database | faction_app | Database |
| Collection | recipes | Collection |
| Document | RES048 | Document |
| Field | productionLabourCostPerKg | Number (508) |
| Field | packingLabourCostPerKg | Number (1) |

---

## 🔗 Related Files

- `DATABASE_LOCATION_GUIDE.md` - Detailed visual guide
- `CHECK_DATABASE.md` - Step-by-step verification
- `LABOUR_COST_DATA_FLOW.md` - Complete data flow
- `VERIFY_LABOUR_COST_SAVE.md` - Verification methods

---

## 💡 Key Points

1. **Database**: `faction_app`
2. **Collection**: `recipes`
3. **Document**: Recipe with code `RES048`
4. **Fields**: 
   - `productionLabourCostPerKg` = 508
   - `packingLabourCostPerKg` = 1

---

## 🚀 Quick Commands

### MongoDB Shell
```bash
# Find the recipe
db.recipes.findOne({ code: "RES048" })

# You'll see:
{
  code: "RES048",
  productionLabourCostPerKg: 508,
  packingLabourCostPerKg: 1,
  ...
}
```

### MongoDB Compass
1. Connect to your MongoDB
2. Select `faction_app` database
3. Select `recipes` collection
4. Filter: `{ "code": "RES048" }`
5. View the document

---

## ✨ Summary

**Labour costs are saved in:**
- **Database**: faction_app
- **Collection**: recipes
- **Document**: RES048
- **Fields**: productionLabourCostPerKg (508) & packingLabourCostPerKg (1)

**To verify**: Go to MongoDB Atlas → Browse Collections → faction_app → recipes → RES048

**Status**: ✅ Labour costs ARE being saved to the database!
