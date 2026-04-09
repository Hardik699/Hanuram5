# Verify Labour Cost Saving to Database

## How to Check if Labour Costs are Being Saved

### Step 1: Open Browser DevTools
1. Press `F12` to open DevTools
2. Go to **Console** tab
3. Go to **Network** tab

### Step 2: Edit a Recipe and Save Labour Costs
1. Go to a recipe
2. Click **Edit**
3. Scroll to "Production Labour Cost" section
4. Enter a value (e.g., 100)
5. Enter a value for "Packing Labour Cost" (e.g., 50)
6. Click **Save Costs** button

### Step 3: Check Console Logs
In the **Console** tab, you should see:

```
Saving labour costs: {
  productionLabourCostPerKg: 100,
  packingLabourCostPerKg: 50
}
Labour costs saved successfully: {success: true}
```

If you see these logs, the labour costs are being saved to the database ✅

### Step 4: Check Network Requests
In the **Network** tab, look for:

1. **Request**: `PATCH /api/recipes/{id}/labour-cost`
   - Status: **200** (green) = Success
   - Response: `{"success": true}`

2. **Request**: `POST /api/recipes/{id}/packaging-costs`
   - Status: **200** (green) = Success
   - Response: `{"success": true}`

If both show status 200, the data is being saved ✅

### Step 5: Verify Data in Database
1. Navigate away from the recipe
2. Come back to the same recipe
3. Click **Edit** again
4. Check if the labour costs still show the values you entered

If the values are still there, they were saved to the database ✅

---

## What Each Log Message Means

### ✅ Success Messages
```
Saving labour costs: {...}
Labour costs saved successfully: {success: true}
```
**Meaning**: Labour costs were sent to the server and saved

### ❌ Error Messages
```
Labour cost save failed: 500
Failed to save labour costs
```
**Meaning**: Server error - check server logs

```
Server error response: 400
```
**Meaning**: Bad request - check if values are valid numbers

---

## Troubleshooting

### Issue: Labour costs not saving
**Check**:
1. Are you clicking "Save Costs" button?
2. Are the values valid numbers?
3. Check browser console for errors
4. Check server logs for errors

### Issue: Values show 0 after saving
**Check**:
1. Did you enter values before clicking save?
2. Are the values being sent in the request? (Check Network tab)
3. Refresh the page and check again

### Issue: Network request shows 500 error
**Check**:
1. Is the server running?
2. Is the database connected?
3. Check server console for error messages

---

## Database Query to Verify

If you have MongoDB access, run this query:

```javascript
// Connect to MongoDB
use faction_app

// Find the recipe
db.recipes.findOne({ code: "RES048" })

// You should see:
{
  _id: ObjectId(...),
  code: "RES048",
  name: "BADAM KATLI",
  productionLabourCostPerKg: 508,
  packingLabourCostPerKg: 1,
  // ... other fields
}
```

If `productionLabourCostPerKg` and `packingLabourCostPerKg` have values, they're saved ✅

---

## Step-by-Step Verification Process

### 1. Clear Console
```javascript
// In browser console
console.clear()
```

### 2. Edit Recipe and Save
- Go to recipe
- Click Edit
- Enter labour costs
- Click Save Costs

### 3. Check Console Output
Look for:
- `Saving labour costs: {...}`
- `Labour costs saved successfully: {success: true}`

### 4. Check Network Tab
Look for:
- `PATCH /api/recipes/.../labour-cost` → Status 200
- `POST /api/recipes/.../packaging-costs` → Status 200

### 5. Refresh and Verify
- Refresh page (F5)
- Go back to recipe
- Click Edit
- Check if values are still there

---

## Expected Behavior

### When Saving Works ✅
1. You see success messages in console
2. Network requests show status 200
3. Toast notification says "Packaging costs saved successfully!"
4. Values persist after page refresh

### When Saving Fails ❌
1. You see error messages in console
2. Network requests show status 400, 500, or other errors
3. Toast notification shows error message
4. Values don't persist after page refresh

---

## Quick Checklist

- [ ] Opened DevTools (F12)
- [ ] Went to Console tab
- [ ] Edited a recipe
- [ ] Entered labour cost values
- [ ] Clicked "Save Costs"
- [ ] Saw success messages in console
- [ ] Checked Network tab for 200 status
- [ ] Refreshed page
- [ ] Values still show in edit form

If all checkboxes are checked ✅, labour costs are being saved correctly!

---

## Need Help?

If labour costs are NOT being saved:

1. **Check server logs** for error messages
2. **Check browser console** for error messages
3. **Verify database connection** is working
4. **Check if recipe ID is valid**
5. **Try with different values** (maybe 0 is being treated as empty)

Contact support with:
- Screenshot of console errors
- Screenshot of Network tab
- Recipe code you're testing with
- Values you're trying to save
