import { useEffect, useState } from "react";
import { BarChart3, AlertCircle } from "lucide-react";

interface Labour {
  id: string;
  code: string;
  name: string;
  department: string;
  salaryPerDay: number;
}

interface RecipeLabour {
  id: string;
  labour: Labour;
  labourName: string;
  department: string;
  salaryPerDay: number;
  type: "production" | "packing";
}

interface PackagingCost {
  _id: string;
  type: string;
  cost: number;
  quantity: number;
}

interface CostBreakdownSectionProps {
  recipeId: string;
  batchSize: number;
  unitName: string;
  totalRawMaterialCost: number;
  recipeItems?: {
    rawMaterialId: string;
    price: number;
    quantity: number;
    totalPrice: number;
  }[];
}

export function CostBreakdownSection({
  recipeId,
  batchSize,
  unitName,
  totalRawMaterialCost,
  recipeItems = [],
}: CostBreakdownSectionProps) {
  const [productionLabour, setProductionLabour] = useState<RecipeLabour[]>([]);
  const [packingLabour, setPackingLabour] = useState<RecipeLabour[]>([]);
  const [packagingCosts, setPackagingCosts] = useState<PackagingCost[]>([]);
  const [loading, setLoading] = useState(true);

  // Debug: Log incoming props
  useEffect(() => {
    console.log("CostBreakdownSection props:", {
      recipeId,
      batchSize,
      unitName,
      totalRawMaterialCost,
    });
  }, [recipeId, batchSize, unitName, totalRawMaterialCost]);

  useEffect(() => {
    fetchAllCosts();
  }, [recipeId]);

  const fetchAllCosts = async () => {
    setLoading(true);
    try {
      const [prodRes, packRes] = await Promise.all([
        fetch(`/api/recipes/${recipeId}/labour?type=production`),
        fetch(`/api/recipes/${recipeId}/labour?type=packing`),
      ]);

      if (prodRes.ok) {
        const prodData = await prodRes.json();
        if (prodData.success) setProductionLabour(prodData.data || []);
      }

      if (packRes.ok) {
        const packData = await packRes.json();
        if (packData.success) setPackingLabour(packData.data || []);
      }

      // Packaging costs API is optional - will be added when user inputs in CostingCalculatorForm
      try {
        const costRes = await fetch(`/api/recipes/${recipeId}/packaging-costs`);
        if (costRes.ok) {
          const costData = await costRes.json();
          if (costData.success) setPackagingCosts(costData.data || []);
        }
      } catch (e) {
        // Silently ignore - packaging costs API may not exist yet
      }
    } catch (error) {
      console.error("Error fetching labour costs:", error);
    } finally {
      setLoading(false);
    }
  };

  // Calculate costs
  const rmCostPerKg = batchSize > 0 ? totalRawMaterialCost / batchSize : 0;

  const productionLabourTotal = productionLabour.reduce(
    (sum, item) => sum + item.salaryPerDay,
    0
  );
  const productionCostPerKg =
    batchSize > 0 ? productionLabourTotal / batchSize : 0;

  const packingLabourTotal = packingLabour.reduce(
    (sum, item) => sum + item.salaryPerDay,
    0
  );
  const packingCostPerKg = batchSize > 0 ? packingLabourTotal / batchSize : 0;

  const packagingTotal = packagingCosts.reduce((sum, item) => sum + item.cost, 0);
  const packagingCostPerKg = batchSize > 0 ? packagingTotal / batchSize : 0;

  const grandTotalCostPerKg =
    rmCostPerKg + productionCostPerKg + packingCostPerKg + packagingCostPerKg;

  // Calculate RM cost from items if totalRawMaterialCost is 0 or not provided
  let calculatedRMCost = totalRawMaterialCost || 0;
  if ((!totalRawMaterialCost || totalRawMaterialCost === 0) && recipeItems && recipeItems.length > 0) {
    calculatedRMCost = recipeItems.reduce((sum, item) => sum + (item.totalPrice || 0), 0);
  }

  // Recalculate RM cost per KG using actual total
  const actualRmCostPerKg = batchSize > 0 ? calculatedRMCost / batchSize : 0;
  const actualGrandTotalCostPerKg =
    actualRmCostPerKg + productionCostPerKg + packingCostPerKg + packagingCostPerKg;

  // Debug logging
  console.log("CostBreakdownSection calculations:", {
    batchSize,
    totalRawMaterialCost,
    calculatedRMCost,
    rmCostPerKg: actualRmCostPerKg,
    productionLabourTotal,
    productionCostPerKg,
    packingLabourTotal,
    packingCostPerKg,
    packagingTotal,
    packagingCostPerKg,
    grandTotalCostPerKg: actualGrandTotalCostPerKg,
  });

  const costItems = [
    {
      label: "1. Raw Material Cost / " + unitName,
      costPerKg: actualRmCostPerKg,
      total: calculatedRMCost,
    },
    {
      label: "2. Production Labour Cost / " + unitName,
      costPerKg: productionCostPerKg,
      total: productionLabourTotal,
    },
    {
      label: "3. Packing Labour Cost / " + unitName,
      costPerKg: packingCostPerKg,
      total: packingLabourTotal,
    },
    {
      label: "4. Packaging & Handling Cost / " + unitName,
      costPerKg: packagingCostPerKg,
      total: packagingTotal,
    },
  ];

  if (loading) {
    return (
      <div className="bg-slate-100 dark:bg-slate-800 rounded-lg p-6 animate-pulse">
        <div className="h-4 bg-slate-300 dark:bg-slate-700 rounded w-1/3 mb-4"></div>
        <div className="space-y-2">
          <div className="h-10 bg-slate-300 dark:bg-slate-700 rounded"></div>
          <div className="h-10 bg-slate-300 dark:bg-slate-700 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-900/10 dark:to-indigo-900/10 rounded-xl p-6 border-2 border-blue-200 dark:border-blue-800/50 shadow-lg">
      <div className="flex items-center gap-3 mb-6">
        <BarChart3 className="w-6 h-6 text-blue-600 dark:text-blue-400" />
        <h3 className="text-xl font-bold text-slate-900 dark:text-white">
          📊 Complete Cost Breakdown (Per {unitName})
        </h3>
      </div>

      {/* Cost Items */}
      <div className="space-y-3 mb-6">
        {costItems.map((item, idx) => (
          <div
            key={idx}
            className="flex items-center justify-between p-4 bg-white dark:bg-slate-800 rounded-lg border border-blue-100 dark:border-blue-900/30 hover:shadow-md transition-shadow"
          >
            <span className="font-semibold text-slate-900 dark:text-white text-sm md:text-base">
              {item.label}
            </span>
            <span className="text-green-600 dark:text-green-400 font-bold text-lg">
              ₹{item.costPerKg.toFixed(2)}
            </span>
          </div>
        ))}
      </div>

      {/* Grand Total */}
      <div className="bg-gradient-to-r from-blue-100 to-indigo-100 dark:from-blue-900/30 dark:to-indigo-900/30 rounded-lg p-5 border-2 border-blue-300 dark:border-blue-700/50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 bg-blue-600 dark:bg-blue-400 rounded-full"></div>
          <span className="font-bold text-slate-900 dark:text-white text-lg">
            GRAND TOTAL COST / {unitName}
          </span>
        </div>
        <span className="text-2xl font-bold text-blue-600 dark:text-blue-300">
          ₹{actualGrandTotalCostPerKg.toFixed(2)}
        </span>
      </div>

      {/* Debug Info */}
      <div className="mt-4 text-xs text-slate-600 dark:text-slate-400 border border-slate-300 dark:border-slate-700 rounded p-2 bg-slate-100 dark:bg-slate-900/30">
        <p className="font-mono">
          Debug: batchSize={batchSize}, totalRM=₹{calculatedRMCost.toFixed(2)} (items count: {recipeItems?.length || 0}), prodLabor=₹{productionLabourTotal.toFixed(2)}, packLabor=₹{packingLabourTotal.toFixed(2)}, pkg=₹{packagingTotal.toFixed(2)}
        </p>
      </div>

      {/* Info Message */}
      {(productionLabourTotal === 0 && packingLabourTotal === 0 && packagingTotal === 0) && (
        <div className="mt-4 flex gap-3 p-3 bg-amber-50 dark:bg-amber-900/20 rounded-lg border border-amber-200 dark:border-amber-800">
          <AlertCircle className="w-5 h-5 text-amber-600 dark:text-amber-500 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-amber-700 dark:text-amber-300">
            💡 <strong>Note:</strong> Add labour costs and packaging costs to see the complete cost breakdown
          </p>
        </div>
      )}
    </div>
  );
}

