import { useState, useEffect } from "react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Save, Check, AlertCircle } from "lucide-react";
import { toast } from "sonner";

interface CostingInputs {
  shipperBoxCost: number;
  shipperBoxQty: number;
  hygieneCostPerUnit: number;
  hygieneQtyPerKg: number;
  scavengerCostPerUnit: number;
  scavengerQtyPerKg: number;
  mapCostPerKg: number;
  smallerSizePackagingCost: number;
  monoCartonCostPerUnit: number;
  monoCartonQtyPerKg: number;
  stickerCostPerUnit: number;
  stickerQtyPerKg: number;
  butterPaperCostPerKg: number;
  butterPaperQtyPerKg: number;
  excessWeightPerKg: number;
  rmcCostPerKg: number;
  wastagePercentage: number;
}

interface CostingResults {
  shipperBoxCostPerKg: number;
  hygieneCostPerKg: number;
  scavengerCostPerKg: number;
  mapCostPerKg: number;
  smallerSizePackagingCostPerKg: number;
  monoCartonCostPerKg: number;
  stickerCostPerKg: number;
  butterPaperCostPerKg: number;
  excessStockCostPerKg: number;
  materialWastageCostPerKg: number;
  totalPackagingHandlingCost: number;
}

const initialInputs: CostingInputs = {
  shipperBoxCost: 0,
  shipperBoxQty: 0,
  hygieneCostPerUnit: 0,
  hygieneQtyPerKg: 0,
  scavengerCostPerUnit: 0,
  scavengerQtyPerKg: 0,
  mapCostPerKg: 0,
  smallerSizePackagingCost: 0,
  monoCartonCostPerUnit: 0,
  monoCartonQtyPerKg: 0,
  stickerCostPerUnit: 0,
  stickerQtyPerKg: 0,
  butterPaperCostPerKg: 0,
  butterPaperQtyPerKg: 0,
  excessWeightPerKg: 0,
  rmcCostPerKg: 0,
  wastagePercentage: 0,
};

interface CostingCalculatorFormProps {
  title?: string;
  rmCostPerKg?: number;
  productionLabourCostPerKg?: number;
  packingLabourCostPerKg?: number;
  recipeId?: string;
  onSave?: () => void;
  batchSize?: number;
  yield?: number;
  readOnly?: boolean;
  unitName?: string;
}

export function CostingCalculatorForm({
  title = "📦 Costing Calculator",
  rmCostPerKg = 0,
  productionLabourCostPerKg = 0,
  packingLabourCostPerKg = 0,
  recipeId,
  onSave,
  batchSize = 0,
  yield: yieldPercentage = 100,
  readOnly = false,
  unitName = "unit",
}: CostingCalculatorFormProps) {
  const [inputs, setInputs] = useState<CostingInputs>({ ...initialInputs, rmcCostPerKg: parseFloat((rmCostPerKg || 0).toFixed(3)) });
  const [results, setResults] = useState<CostingResults | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [labourCostPerKg, setLabourCostPerKg] = useState<number>(productionLabourCostPerKg);
  const [packingLabourCostPerKgState, setPackingLabourCostPerKgState] = useState<number>(packingLabourCostPerKg);

  // Load previously saved packaging costs and labour costs on mount
  useEffect(() => {
    if (!recipeId) return;

    const loadPackagingCosts = async () => {
      try {
        const response = await fetch(`/api/recipes/${recipeId}/packaging-costs`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data) {
            const savedData = data.data;
            const loadedInputs = savedData.inputs || initialInputs;
            // Auto-fill rmcCostPerKg from recipe pricePerUnit if not already saved
            if (!loadedInputs.rmcCostPerKg && rmCostPerKg > 0) {
              loadedInputs.rmcCostPerKg = parseFloat(rmCostPerKg.toFixed(3));
            }
            setInputs(loadedInputs);
            setResults(savedData.results || null);
          }
        }
      } catch (error) {
        console.debug("Could not load packaging costs:", error);
      }
    };

    const loadLabourCosts = async () => {
      try {
        const response = await fetch(`/api/recipes/${recipeId}`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data) {
            const recipe = data.data;
            // Load saved labour costs from recipe, or use props as fallback
            if (recipe.productionLabourCostPerKg !== undefined && recipe.productionLabourCostPerKg > 0) {
              setLabourCostPerKg(recipe.productionLabourCostPerKg);
            } else if (productionLabourCostPerKg > 0) {
              setLabourCostPerKg(productionLabourCostPerKg);
            }
            
            if (recipe.packingLabourCostPerKg !== undefined && recipe.packingLabourCostPerKg > 0) {
              setPackingLabourCostPerKgState(recipe.packingLabourCostPerKg);
            } else if (packingLabourCostPerKg > 0) {
              setPackingLabourCostPerKgState(packingLabourCostPerKg);
            }
          }
        }
      } catch (error) {
        console.debug("Could not load labour costs:", error);
      }
    };

    loadPackagingCosts();
    loadLabourCosts();
  }, [recipeId, productionLabourCostPerKg, packingLabourCostPerKg]);

  // Sync labour cost when prop changes (only if not already loaded from DB)
  useEffect(() => {
    // Only update if the prop value is different and greater than current state
    if (productionLabourCostPerKg > 0 && productionLabourCostPerKg !== labourCostPerKg) {
      setLabourCostPerKg(productionLabourCostPerKg);
    }
  }, [productionLabourCostPerKg]);

  // Sync packing labour cost when prop changes (only if not already loaded from DB)
  useEffect(() => {
    // Only update if the prop value is different and greater than current state
    if (packingLabourCostPerKg > 0 && packingLabourCostPerKg !== packingLabourCostPerKgState) {
      setPackingLabourCostPerKgState(packingLabourCostPerKg);
    }
  }, [packingLabourCostPerKg]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (readOnly) return;
    const { name, value } = e.target;
    const updatedInputs = {
      ...inputs,
      [name]: value === "" ? 0 : parseFloat(value),
    };
    setInputs(updatedInputs);
    calculateCosts_internal(updatedInputs);
  };

  const handleWheel = (e: React.WheelEvent<HTMLInputElement>) => {
    (e.target as HTMLInputElement).blur();
  };

  const calculateCosts_internal = (currentInputs: CostingInputs = inputs) => {
    const shipperBoxCostPerKg =
      currentInputs.shipperBoxQty > 0
        ? currentInputs.shipperBoxCost / currentInputs.shipperBoxQty
        : 0;

    const hygieneCostPerKg = currentInputs.hygieneCostPerUnit * currentInputs.hygieneQtyPerKg;
    const scavengerCostPerKg = currentInputs.scavengerCostPerUnit * currentInputs.scavengerQtyPerKg;
    const mapCostPerKg = currentInputs.mapCostPerKg;
    const smallerSizePackagingCostPerKg = currentInputs.smallerSizePackagingCost;
    const monoCartonCostPerKg = currentInputs.monoCartonCostPerUnit * currentInputs.monoCartonQtyPerKg;
    const stickerCostPerKg = currentInputs.stickerCostPerUnit * currentInputs.stickerQtyPerKg;
    const butterPaperCostPerKg = currentInputs.butterPaperCostPerKg * currentInputs.butterPaperQtyPerKg;
    const excessStockCostPerKg = currentInputs.excessWeightPerKg * currentInputs.rmcCostPerKg;

    const wastageBaseSum =
      currentInputs.rmcCostPerKg +
      shipperBoxCostPerKg +
      hygieneCostPerKg +
      scavengerCostPerKg +
      monoCartonCostPerKg +
      stickerCostPerKg +
      butterPaperCostPerKg;
    const materialWastageCostPerKg = (wastageBaseSum * currentInputs.wastagePercentage) / 100;

    const totalPackagingHandlingCost =
      shipperBoxCostPerKg +
      hygieneCostPerKg +
      scavengerCostPerKg +
      mapCostPerKg +
      smallerSizePackagingCostPerKg +
      monoCartonCostPerKg +
      stickerCostPerKg +
      butterPaperCostPerKg +
      excessStockCostPerKg +
      materialWastageCostPerKg;

    setResults({
      shipperBoxCostPerKg,
      hygieneCostPerKg,
      scavengerCostPerKg,
      mapCostPerKg,
      smallerSizePackagingCostPerKg,
      monoCartonCostPerKg,
      stickerCostPerKg,
      butterPaperCostPerKg,
      excessStockCostPerKg,
      materialWastageCostPerKg,
      totalPackagingHandlingCost,
    });
  };

  const handleSavePackagingCosts = async () => {
    if (!recipeId) {
      toast.error("Recipe ID is required to save packaging costs");
      return;
    }

    if (!results) {
      toast.error("Please calculate the costs first");
      return;
    }

    setIsSaving(true);
    try {
      // Save labour costs first with the updated values
      console.log("Saving labour costs:", {
        productionLabourCostPerKg: labourCostPerKg,
        packingLabourCostPerKg: packingLabourCostPerKgState,
      });

      const labourResponse = await fetch(`/api/recipes/${recipeId}/labour-cost`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          productionLabourCostPerKg: labourCostPerKg,
          packingLabourCostPerKg: packingLabourCostPerKgState,
        }),
      });

      if (!labourResponse.ok) {
        console.error("Labour cost save failed:", labourResponse.status);
        toast.error("Failed to save labour costs");
        setIsSaving(false);
        return;
      }

      const labourData = await labourResponse.json();
      console.log("Labour costs saved successfully:", labourData);

      const response = await fetch(`/api/recipes/${recipeId}/packaging-costs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          inputs,
          results,
          totalPackagingHandlingCost: results.totalPackagingHandlingCost,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error("Server error response:", response.status, errorText);
        toast.error(`Server error: ${response.status}`);
        setIsSaving(false);
        return;
      }

      const responseText = await response.text();
      if (!responseText) {
        toast.success("Packaging costs saved successfully!");
        if (onSave) onSave();
        return;
      }

      const data = JSON.parse(responseText);
      if (data.success) {
        toast.success("Packaging costs saved successfully!");
        // Wait a moment for the database to update, then refresh
        setTimeout(() => {
          if (onSave) onSave();
        }, 500);
      } else {
        toast.error(data.message || "Failed to save packaging costs");
      }
    } catch (error) {
      console.error("Error saving packaging costs:", error);
      toast.error("Failed to save packaging costs");
    } finally {
      setIsSaving(false);
    }
  };

  const sectionInputClass = "w-full px-3 py-2.5 rounded-lg border border-slate-300 bg-white text-slate-800 font-medium text-sm focus:outline-none focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100 transition-all placeholder:text-slate-400 placeholder:font-normal";
  const resultBadge = (text: string) => (
    <span className="text-xs font-semibold text-indigo-700 bg-indigo-100 px-3 py-1.5 rounded-full whitespace-nowrap border border-indigo-200">{text}</span>
  );
  const sectionHeader = (num: number, label: string, badge?: React.ReactNode) => (
    <div className="flex items-center gap-3 px-4 py-3 bg-gradient-to-r from-indigo-50 to-slate-50 border-b border-slate-200 rounded-t-lg">
      <span className="w-6 h-6 rounded-full bg-indigo-600 text-white text-xs font-bold flex items-center justify-center flex-shrink-0">{num}</span>
      <span className="text-sm font-semibold text-slate-700">{label}</span>
      {badge && <div className="ml-auto">{badge}</div>}
    </div>
  );

  return (
    <div className={`bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden ${readOnly ? "pointer-events-none select-none" : ""}`}>
      {/* Header */}
      <div className="px-6 py-4 bg-gradient-to-r from-indigo-50 via-slate-50 to-slate-50 border-b border-slate-200">
        <h2 className="text-base font-bold text-slate-800">{title}</h2>
      </div>

      <div className="p-5 space-y-3">

        {/* Production Labour Cost Section */}
        <div className="rounded-lg border border-slate-200 overflow-hidden shadow-xs hover:shadow-sm transition-shadow">
          <div className="flex items-center gap-3 px-4 py-3 bg-gradient-to-r from-indigo-50 to-slate-50 border-b border-slate-200 rounded-t-lg">
            <span className="text-sm font-semibold text-slate-700">Production Labour Cost</span>
            {results && <div className="ml-auto text-xs font-semibold text-indigo-700 bg-indigo-100 px-3 py-1.5 rounded-full border border-indigo-200">₹{(labourCostPerKg * yieldPercentage).toFixed(2)}/Kg</div>}
          </div>
          <div className="p-4 bg-slate-50 grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1.5">Cost per Kg</label>
              <Input
                type="number"
                value={labourCostPerKg || ""}
                onChange={(e) => {
                  const val = e.target.value === "" ? 0 : parseFloat(e.target.value);
                  setLabourCostPerKg(val);
                }}
                onWheel={(e) => (e.target as HTMLInputElement).blur()}
                placeholder="0.00"
                step="0.01"
                readOnly={readOnly}
                className={`w-full px-3 py-2.5 rounded-lg border font-medium text-sm focus:outline-none transition-all ${
                  readOnly
                    ? "border-slate-300 bg-slate-100 text-slate-500 cursor-not-allowed"
                    : "border-slate-300 bg-white text-slate-800 focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
                }`}
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1.5">Yield</label>
              <Input
                type="number"
                value={yieldPercentage || ""}
                onChange={(e) => {
                  // This is read-only, so we don't update it
                }}
                onWheel={(e) => (e.target as HTMLInputElement).blur()}
                placeholder="0.00"
                step="0.01"
                readOnly
                className="w-full px-3 py-2.5 rounded-lg border border-slate-300 bg-slate-100 text-slate-500 font-medium text-sm focus:outline-none cursor-not-allowed"
              />
            </div>
          </div>
          <div className="px-4 pb-3 bg-slate-50">
            <div className="text-xs font-medium text-slate-700 bg-indigo-50 border border-indigo-200 rounded px-3 py-2">
              {labourCostPerKg.toFixed(4)} × {yieldPercentage.toFixed(2)} = ₹{(labourCostPerKg * yieldPercentage).toFixed(2)}/Kg
            </div>
          </div>
        </div>

        {/* Packing Labour Cost Section */}
        <div className="rounded-lg border border-slate-200 overflow-hidden shadow-xs hover:shadow-sm transition-shadow">
          <div className="flex items-center gap-3 px-4 py-3 bg-gradient-to-r from-indigo-50 to-slate-50 border-b border-slate-200 rounded-t-lg">
            <span className="text-sm font-semibold text-slate-700">Packing Labour Cost</span>
            {results && <div className="ml-auto text-xs font-semibold text-indigo-700 bg-indigo-100 px-3 py-1.5 rounded-full border border-indigo-200">₹{(packingLabourCostPerKgState * yieldPercentage).toFixed(2)}/Kg</div>}
          </div>
          <div className="p-4 bg-slate-50 grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1.5">Cost per Kg</label>
              <Input
                type="number"
                value={packingLabourCostPerKgState || ""}
                onChange={(e) => {
                  const val = e.target.value === "" ? 0 : parseFloat(e.target.value);
                  setPackingLabourCostPerKgState(val);
                }}
                onWheel={(e) => (e.target as HTMLInputElement).blur()}
                placeholder="0.00"
                step="0.01"
                readOnly={readOnly}
                className={`w-full px-3 py-2.5 rounded-lg border font-medium text-sm focus:outline-none transition-all ${
                  readOnly
                    ? "border-slate-300 bg-slate-100 text-slate-500 cursor-not-allowed"
                    : "border-slate-300 bg-white text-slate-800 focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
                }`}
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1.5">Yield</label>
              <Input
                type="number"
                value={yieldPercentage || ""}
                onChange={(e) => {
                  // This is read-only, so we don't update it
                }}
                onWheel={(e) => (e.target as HTMLInputElement).blur()}
                placeholder="0.00"
                step="0.01"
                readOnly
                className="w-full px-3 py-2.5 rounded-lg border border-slate-300 bg-slate-100 text-slate-500 font-medium text-sm focus:outline-none cursor-not-allowed"
              />
            </div>
          </div>
          <div className="px-4 pb-3 bg-slate-50">
            <div className="text-xs font-medium text-slate-700 bg-indigo-50 border border-indigo-200 rounded px-3 py-2">
              {packingLabourCostPerKgState.toFixed(4)} × {yieldPercentage.toFixed(2)} = ₹{(packingLabourCostPerKgState * yieldPercentage).toFixed(2)}/Kg
            </div>
          </div>
        </div>

        {[
          { num: 1, title: "Shipper Box Cost", result: results ? results.shipperBoxCostPerKg.toFixed(2) : null, fields: [
            { name: "shipperBoxCost", label: "Cost per Box" },
            { name: "shipperBoxQty", label: "Qty per Box (Kg)" },
          ]},
          { num: 2, title: "Hygiene Cost", result: results ? results.hygieneCostPerKg.toFixed(2) : null, fields: [
            { name: "hygieneCostPerUnit", label: "Cost per Unit" },
            { name: "hygieneQtyPerKg", label: "Qty used per Kg" },
          ]},
          { num: 3, title: "Scavenger Cost", result: results ? results.scavengerCostPerKg.toFixed(2) : null, fields: [
            { name: "scavengerCostPerUnit", label: "Cost per Unit" },
            { name: "scavengerQtyPerKg", label: "Qty used per Kg" },
          ]},
          { num: 4, title: "MAP Cost", result: results ? results.mapCostPerKg.toFixed(2) : null, fields: [
            { name: "mapCostPerKg", label: "Cost per Kg" },
          ]},
          { num: 5, title: "Smaller Size Packaging", result: results ? results.smallerSizePackagingCostPerKg.toFixed(2) : null, fields: [
            { name: "smallerSizePackagingCost", label: "Cost per Kg" },
          ]},
          { num: 6, title: "Mono Carton Cost", result: results ? results.monoCartonCostPerKg.toFixed(2) : null, fields: [
            { name: "monoCartonCostPerUnit", label: "Cost per Carton" },
            { name: "monoCartonQtyPerKg", label: "Qty used per Kg" },
          ]},
          { num: 7, title: "Sticker Cost", result: results ? results.stickerCostPerKg.toFixed(2) : null, fields: [
            { name: "stickerCostPerUnit", label: "Cost per Sticker" },
            { name: "stickerQtyPerKg", label: "Qty used per Kg" },
          ]},
          { num: 8, title: "Butter Paper Cost", result: results ? results.butterPaperCostPerKg.toFixed(2) : null, fields: [
            { name: "butterPaperCostPerKg", label: "Cost per Kg" },
            { name: "butterPaperQtyPerKg", label: "Qty used per Kg" },
          ]},
          { num: 9, title: "Excess Stock Cost", result: results ? results.excessStockCostPerKg.toFixed(2) : null, fields: [
            { name: "excessWeightPerKg", label: "Excess Weight per Kg", readOnly: false },
            { name: "rmcCostPerKg", label: "Price Per Unit Yield (₹)", readOnly: true },
          ]},
          { num: 10, title: "Material Wastage", result: results ? results.materialWastageCostPerKg.toFixed(2) : null, fields: [
            { name: "wastagePercentage", label: "Wastage %" },
          ]},
        ].map((s) => (
          <div key={s.num} className="rounded-lg border border-slate-200 overflow-hidden shadow-xs hover:shadow-sm transition-shadow">
            {sectionHeader(s.num, s.title, s.result ? resultBadge(`₹${s.result}/Kg`) : undefined)}
            <div className={`p-4 bg-slate-50 grid gap-3 ${s.fields.length > 1 ? "grid-cols-2" : "grid-cols-1 max-w-xs"}`}>
              {s.fields.map((f) => (
                <div key={f.name}>
                  <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1.5">{f.label}</label>
                  <Input
                    type="number"
                    name={f.name}
                    value={(inputs as any)[f.name] || ""}
                    onChange={handleInputChange}
                    onWheel={handleWheel}
                    placeholder="0.00"
                    step="0.01"
                    readOnly={(f as any).readOnly}
                    className={`${sectionInputClass} ${(f as any).readOnly ? "bg-slate-100 cursor-not-allowed text-slate-500 border-slate-200" : ""}`}
                  />
                </div>
              ))}
            </div>
            {/* Calculation row */}
            {results && s.result && (
              <div className="px-4 pb-3 bg-slate-50">
                <div className="text-xs font-medium text-slate-700 bg-indigo-50 border border-indigo-200 rounded px-3 py-2">
                  {s.num === 10
                    ? `${(inputs as any)[s.fields[0].name] || 0}% of base costs = ₹${s.result}/Kg`
                    : s.fields.length === 2
                    ? `${(inputs as any)[s.fields[0].name] || 0} × ${(inputs as any)[s.fields[1].name] || 0} = ₹${s.result}/Kg`
                    : `₹${s.result}/Kg`}
                </div>
              </div>
            )}
          </div>
        ))}

      </div>

      {/* Results Table */}
      {results && (
        <div className="mt-6 px-5 pb-5">
          <div className="overflow-x-auto mb-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-100 border-b border-slate-300">
                  <th className="px-4 py-3 text-left font-semibold text-slate-700">Cost Component</th>
                  <th className="px-4 py-3 text-right font-semibold text-slate-700">Cost per Kg (₹)</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-b border-slate-200 hover:bg-slate-50">
                  <td className="px-4 py-3 text-slate-700">Shipper Box Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-slate-800">₹{results.shipperBoxCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="border-b border-slate-200 hover:bg-slate-50">
                  <td className="px-4 py-3 text-slate-700">Hygiene Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-slate-800">₹{results.hygieneCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="border-b border-slate-200 hover:bg-slate-50">
                  <td className="px-4 py-3 text-slate-700">Scavenger Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-slate-800">₹{results.scavengerCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="border-b border-slate-200 hover:bg-slate-50">
                  <td className="px-4 py-3 text-slate-700">MAP Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-slate-800">₹{results.mapCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="border-b border-slate-200 hover:bg-slate-50">
                  <td className="px-4 py-3 text-slate-700">Smaller Size Packaging Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-slate-800">₹{results.smallerSizePackagingCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="border-b border-slate-200 hover:bg-slate-50">
                  <td className="px-4 py-3 text-slate-700">Mono Carton Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-slate-800">₹{results.monoCartonCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="border-b border-slate-200 hover:bg-slate-50">
                  <td className="px-4 py-3 text-slate-700">Sticker Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-slate-800">₹{results.stickerCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="border-b border-slate-200 hover:bg-slate-50">
                  <td className="px-4 py-3 text-slate-700">Butter Paper Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-slate-800">₹{results.butterPaperCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="border-b border-slate-200 hover:bg-slate-50">
                  <td className="px-4 py-3 text-slate-700">Excess Stock Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-slate-800">₹{results.excessStockCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="border-b border-slate-200 bg-indigo-50 hover:bg-indigo-100">
                  <td className="px-4 py-3 font-medium text-slate-700">Material Wastage Cost</td>
                  <td className="px-4 py-3 text-right font-medium text-indigo-700">₹{results.materialWastageCostPerKg.toFixed(2)}</td>
                </tr>
                <tr className="bg-indigo-100 border-t-2 border-indigo-300">
                  <td className="px-4 py-4 font-bold text-slate-800">TOTAL PACKAGING & HANDLING COST / KG</td>
                  <td className="px-4 py-4 text-right font-bold text-indigo-700">₹{results.totalPackagingHandlingCost.toFixed(2)}</td>
                </tr>
              </tbody>
            </table>
          </div>

          {/* Grand Total Summary */}
          <div className="mt-6 border-t border-slate-300 pt-6">

            {/* Save Button - above breakdown */}
            {recipeId && !readOnly && (
              <div className="flex justify-end mb-4">
                <button
                  onClick={handleSavePackagingCosts}
                  disabled={isSaving || !results}
                  className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-400 disabled:cursor-not-allowed text-white font-semibold transition-all shadow-md hover:shadow-lg"
                >
                  {isSaving ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                      <span>Saving...</span>
                    </>
                  ) : (
                    <>
                      <Save className="w-4 h-4" />
                      <span>Save Costs</span>
                    </>
                  )}
                </button>
              </div>
            )}

            <div className="bg-indigo-50 rounded-lg p-5 border border-indigo-200">
              <h3 className="text-base font-bold text-slate-800 mb-4">
                📊 Complete Cost Breakdown (Per Kg)
              </h3>
              <div className="space-y-3">
                <div className="pb-3 border-b border-indigo-200">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-sm font-medium text-slate-700">1. Raw Material Cost / KG</span>
                    <span className="text-base font-bold text-slate-800">₹{rmCostPerKg.toFixed(2)}</span>
                  </div>
                  {batchSize > 0 && (
                    <div className="flex justify-between items-center text-xs text-slate-600">
                      <span></span>
                      <span>{rmCostPerKg.toFixed(2)} × {yieldPercentage} = ₹{(rmCostPerKg * yieldPercentage).toFixed(2)}</span>
                    </div>
                  )}
                </div>
                <div className="pb-3 border-b border-indigo-200">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-sm font-medium text-slate-700">2. Production Labour Cost / KG</span>
                    <span className="text-base font-bold text-slate-800">₹{labourCostPerKg.toFixed(4)}</span>
                  </div>
                  {batchSize > 0 && (
                    <div className="flex justify-between items-center text-xs text-slate-600">
                      <span></span>
                      <span>{labourCostPerKg.toFixed(4)} × {yieldPercentage} = ₹{(labourCostPerKg * yieldPercentage).toFixed(2)}</span>
                    </div>
                  )}
                </div>
                <div className="pb-3 border-b border-indigo-200">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-sm font-medium text-slate-700">3. Packing Labour Cost / KG</span>
                    <span className="text-base font-bold text-slate-800">₹{packingLabourCostPerKgState.toFixed(4)}</span>
                  </div>
                  {batchSize > 0 && (
                    <div className="flex justify-between items-center text-xs text-slate-600">
                      <span></span>
                      <span>{packingLabourCostPerKgState.toFixed(4)} × {yieldPercentage} = ₹{(packingLabourCostPerKgState * yieldPercentage).toFixed(2)}</span>
                    </div>
                  )}
                </div>
                <div className="pb-3 border-b border-indigo-200">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-sm font-medium text-slate-700">4. Packaging & Handling Cost / KG</span>
                    <span className="text-base font-bold text-slate-800">₹{results.totalPackagingHandlingCost.toFixed(2)}</span>
                  </div>
                  {batchSize > 0 && (
                    <div className="flex justify-between items-center text-xs text-slate-600">
                      <span></span>
                      <span>{results.totalPackagingHandlingCost.toFixed(2)} × {yieldPercentage} = ₹{(results.totalPackagingHandlingCost * yieldPercentage).toFixed(2)}</span>
                    </div>
                  )}
                </div>
                <div className="flex justify-between items-center pt-3 mt-3 border-t-2 border-indigo-300 bg-indigo-100 p-4 rounded">
                  <span className="text-base font-bold text-slate-800">GRAND TOTAL COST / KG</span>
                  <span className="text-xl font-bold text-indigo-700">
                    ₹{(rmCostPerKg + labourCostPerKg + packingLabourCostPerKgState + results.totalPackagingHandlingCost).toFixed(2)}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {recipeId && !readOnly && (
            <div className="mt-6 pt-6 border-t border-slate-300 flex gap-3 justify-end">
            </div>
          )}
        </div>
      )}
    </div>
  );
}




