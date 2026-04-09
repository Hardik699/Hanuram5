import { useState } from "react";
import { Layout } from "@/components/Layout";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Calculator } from "lucide-react";

interface CostingInputs {
  productName: string;
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
  productName: "",
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

export default function CostingAnalysis() {
  const [inputs, setInputs] = useState<CostingInputs>(initialInputs);
  const [results, setResults] = useState<CostingResults | null>(null);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    const updatedInputs = {
      ...inputs,
      [name]: value === "" ? 0 : parseFloat(value),
    };
    setInputs(updatedInputs);

    // Auto-calculate for all inputs
    calculateCosts_internal(updatedInputs);
  };

  const calculateCosts_internal = (currentInputs: CostingInputs = inputs) => {
    // 1. Shipper Box Cost / Kg
    const shipperBoxCostPerKg =
      currentInputs.shipperBoxQty > 0
        ? currentInputs.shipperBoxCost / currentInputs.shipperBoxQty
        : 0;

    // 2. Hygiene Cost / Kg
    const hygieneCostPerKg =
      currentInputs.hygieneCostPerUnit * currentInputs.hygieneQtyPerKg;

    // 3. Scavenger Cost / Kg
    const scavengerCostPerKg =
      currentInputs.scavengerCostPerUnit * currentInputs.scavengerQtyPerKg;

    // 4. MAP Cost / Kg (direct input)
    const mapCostPerKg = currentInputs.mapCostPerKg;

    // 5. Smaller Size Packaging Cost / Kg (direct input)
    const smallerSizePackagingCostPerKg =
      currentInputs.smallerSizePackagingCost;

    // 6. Mono Carton Cost / Kg
    const monoCartonCostPerKg =
      currentInputs.monoCartonCostPerUnit * currentInputs.monoCartonQtyPerKg;

    // 7. Sticker Cost / Kg
    const stickerCostPerKg =
      currentInputs.stickerCostPerUnit * currentInputs.stickerQtyPerKg;

    // 8. Butter Paper Cost / Kg
    const butterPaperCostPerKg =
      currentInputs.butterPaperCostPerKg * currentInputs.butterPaperQtyPerKg;

    // 9. Excess Stock Cost / Kg
    const excessStockCostPerKg =
      currentInputs.excessWeightPerKg * currentInputs.rmcCostPerKg;

    // Material Wastage Cost / Kg
    const wastageBaseSum =
      shipperBoxCostPerKg +
      hygieneCostPerKg +
      scavengerCostPerKg +
      monoCartonCostPerKg +
      stickerCostPerKg +
      butterPaperCostPerKg;
    const materialWastageCostPerKg =
      (wastageBaseSum * currentInputs.wastagePercentage) / 100;

    // Total Packaging & Handling Cost / Kg
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

  return (
    <Layout title="Costing Analysis">
      <>
        <PageHeader
          title="Costing Analysis"
          description="Calculate packaging & handling cost per Kg for products"
          breadcrumbs={[{ label: "Costing Analysis" }]}
          icon={<Calculator className="w-6 h-6 text-white" />}
        />

        <div className="space-y-6">
          {/* Product Details Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h2 className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">
              📦 Product Details
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Product Name
                </Label>
                <Input
                  type="text"
                  name="productName"
                  value={inputs.productName}
                  onChange={handleInputChange}
                  placeholder="Enter product name"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
          </div>

          {/* 1. Shipper Box Cost Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold">
                1
              </span>
              Shipper Box Cost
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Cost per Box (₹)
                </Label>
                <Input
                  type="number"
                  name="shipperBoxCost"
                  value={inputs.shipperBoxCost || ""}
                  onChange={handleInputChange}
                  placeholder="Cost per box"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Qty per Box (Kg)
                </Label>
                <Input
                  type="number"
                  name="shipperBoxQty"
                  value={inputs.shipperBoxQty || ""}
                  onChange={handleInputChange}
                  placeholder="Quantity in kg"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-blue-50 dark:bg-blue-950 p-3 rounded border border-blue-200 dark:border-blue-800">
                <p className="font-medium text-blue-900 dark:text-blue-200">
                  ✓ Shipper Box Cost / Kg = {inputs.shipperBoxCost} ÷{" "}
                  {inputs.shipperBoxQty} ={" "}
                  <span className="font-bold">
                    ₹{results.shipperBoxCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* 2. Hygiene Cost Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold">
                2
              </span>
              Hygiene Cost
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Cost per Unit (₹)
                </Label>
                <Input
                  type="number"
                  name="hygieneCostPerUnit"
                  value={inputs.hygieneCostPerUnit || ""}
                  onChange={handleInputChange}
                  placeholder="Cost per unit"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Qty used per Kg
                </Label>
                <Input
                  type="number"
                  name="hygieneQtyPerKg"
                  value={inputs.hygieneQtyPerKg || ""}
                  onChange={handleInputChange}
                  placeholder="Quantity per kg"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-green-50 dark:bg-green-950 p-3 rounded border border-green-200 dark:border-green-800">
                <p className="font-medium text-green-900 dark:text-green-200">
                  ✓ Hygiene Cost / Kg = {inputs.hygieneCostPerUnit} ×{" "}
                  {inputs.hygieneQtyPerKg} ={" "}
                  <span className="font-bold">
                    ₹{results.hygieneCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* 3. Scavenger Cost Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold">
                3
              </span>
              Scavenger Cost
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Cost per Unit (₹)
                </Label>
                <Input
                  type="number"
                  name="scavengerCostPerUnit"
                  value={inputs.scavengerCostPerUnit || ""}
                  onChange={handleInputChange}
                  placeholder="Cost per unit"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Qty used per Kg
                </Label>
                <Input
                  type="number"
                  name="scavengerQtyPerKg"
                  value={inputs.scavengerQtyPerKg || ""}
                  onChange={handleInputChange}
                  placeholder="Quantity per kg"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-purple-50 dark:bg-purple-950 p-3 rounded border border-purple-200 dark:border-purple-800">
                <p className="font-medium text-purple-900 dark:text-purple-200">
                  ✓ Scavenger Cost / Kg = {inputs.scavengerCostPerUnit} ×{" "}
                  {inputs.scavengerQtyPerKg} ={" "}
                  <span className="font-bold">
                    ₹{results.scavengerCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* 4. MAP Cost Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold">
                4
              </span>
              MAP Cost
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Cost per Kg (₹)
                </Label>
                <Input
                  type="number"
                  name="mapCostPerKg"
                  value={inputs.mapCostPerKg || ""}
                  onChange={handleInputChange}
                  placeholder="Direct input"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-orange-50 dark:bg-orange-950 p-3 rounded border border-orange-200 dark:border-orange-800">
                <p className="font-medium text-orange-900 dark:text-orange-200">
                  ✓ MAP Cost / Kg ={" "}
                  <span className="font-bold">
                    ₹{results.mapCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* 5. Smaller Size Packaging Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="bg-pink-100 dark:bg-pink-900 text-pink-700 dark:text-pink-300 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold">
                5
              </span>
              Smaller Size Packaging Cost
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Cost per Kg (₹)
                </Label>
                <Input
                  type="number"
                  name="smallerSizePackagingCost"
                  value={inputs.smallerSizePackagingCost || ""}
                  onChange={handleInputChange}
                  placeholder="Direct input"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-pink-50 dark:bg-pink-950 p-3 rounded border border-pink-200 dark:border-pink-800">
                <p className="font-medium text-pink-900 dark:text-pink-200">
                  ✓ Smaller Size Packaging Cost / Kg ={" "}
                  <span className="font-bold">
                    ₹{results.smallerSizePackagingCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* 6. Mono Carton Cost Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold">
                6
              </span>
              Mono Carton Cost
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Cost per Carton (₹)
                </Label>
                <Input
                  type="number"
                  name="monoCartonCostPerUnit"
                  value={inputs.monoCartonCostPerUnit || ""}
                  onChange={handleInputChange}
                  placeholder="Cost per carton"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Qty used per Kg
                </Label>
                <Input
                  type="number"
                  name="monoCartonQtyPerKg"
                  value={inputs.monoCartonQtyPerKg || ""}
                  onChange={handleInputChange}
                  placeholder="Quantity per kg"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-red-50 dark:bg-red-950 p-3 rounded border border-red-200 dark:border-red-800">
                <p className="font-medium text-red-900 dark:text-red-200">
                  ✓ Mono Carton Cost / Kg = {inputs.monoCartonCostPerUnit} ×{" "}
                  {inputs.monoCartonQtyPerKg} ={" "}
                  <span className="font-bold">
                    ₹{results.monoCartonCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* 7. Sticker Cost Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="bg-indigo-100 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-300 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold">
                7
              </span>
              Sticker Cost
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Cost per Sticker (₹)
                </Label>
                <Input
                  type="number"
                  name="stickerCostPerUnit"
                  value={inputs.stickerCostPerUnit || ""}
                  onChange={handleInputChange}
                  placeholder="Cost per sticker"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Qty used per Kg
                </Label>
                <Input
                  type="number"
                  name="stickerQtyPerKg"
                  value={inputs.stickerQtyPerKg || ""}
                  onChange={handleInputChange}
                  placeholder="Quantity per kg"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-purple-50 dark:bg-purple-950 p-3 rounded border border-purple-200 dark:border-purple-800">
                <p className="font-medium text-purple-900 dark:text-purple-200">
                  ✓ Sticker Cost / Kg = {inputs.stickerCostPerUnit} ×{" "}
                  {inputs.stickerQtyPerKg} ={" "}
                  <span className="font-bold">
                    ₹{results.stickerCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* 8. Butter Paper Cost Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold">
                8
              </span>
              Butter Paper Cost
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Cost per Kg (₹)
                </Label>
                <Input
                  type="number"
                  name="butterPaperCostPerKg"
                  value={inputs.butterPaperCostPerKg || ""}
                  onChange={handleInputChange}
                  placeholder="Cost per kg"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Qty used per Kg
                </Label>
                <Input
                  type="number"
                  name="butterPaperQtyPerKg"
                  value={inputs.butterPaperQtyPerKg || ""}
                  onChange={handleInputChange}
                  placeholder="Quantity per kg"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-yellow-50 dark:bg-yellow-950 p-3 rounded border border-yellow-200 dark:border-yellow-800">
                <p className="font-medium text-yellow-900 dark:text-yellow-200">
                  ✓ Butter Paper Cost / Kg = {inputs.butterPaperCostPerKg} ×{" "}
                  {inputs.butterPaperQtyPerKg} ={" "}
                  <span className="font-bold">
                    ₹{results.butterPaperCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* 9. Excess Stock Cost Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="bg-cyan-100 dark:bg-cyan-900 text-cyan-700 dark:text-cyan-300 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold">
                9
              </span>
              Excess Stock Cost
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Excess Weight per Kg
                </Label>
                <Input
                  type="number"
                  name="excessWeightPerKg"
                  value={inputs.excessWeightPerKg || ""}
                  onChange={handleInputChange}
                  placeholder="Excess weight"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  RMC Cost per Kg (₹)
                </Label>
                <Input
                  type="number"
                  name="rmcCostPerKg"
                  value={inputs.rmcCostPerKg || ""}
                  onChange={handleInputChange}
                  placeholder="RMC cost"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-cyan-50 dark:bg-cyan-950 p-3 rounded border border-cyan-200 dark:border-cyan-800">
                <p className="font-medium text-cyan-900 dark:text-cyan-200">
                  ✓ Excess Stock Cost / Kg = {inputs.excessWeightPerKg} ×{" "}
                  {inputs.rmcCostPerKg} ={" "}
                  <span className="font-bold">
                    ₹{results.excessStockCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* Wastage Section */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 dark:text-white flex items-center gap-2">
              <span className="text-2xl">⚠️</span>
              Material Wastage
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Wastage Percentage (%)
                </Label>
                <Input
                  type="number"
                  name="wastagePercentage"
                  value={inputs.wastagePercentage || ""}
                  onChange={handleInputChange}
                  placeholder="Wastage %"
                  step="0.01"
                  className="border-slate-300 dark:border-slate-600"
                />
              </div>
            </div>
            {results && (
              <div className="bg-amber-50 dark:bg-amber-950 p-3 rounded border border-amber-200 dark:border-amber-800">
                <p className="font-medium text-amber-900 dark:text-amber-200">
                  ✓ Material Wastage Cost / Kg ({inputs.wastagePercentage}%) ={" "}
                  <span className="font-bold">
                    ₹{results.materialWastageCostPerKg.toFixed(2)}/Kg
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* Results Section */}
          {results && (
            <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
              {/* Results Table */}
              <div className="overflow-x-auto mb-6">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-slate-100 dark:bg-slate-700 border-b border-slate-300 dark:border-slate-600">
                      <th className="px-4 py-3 text-left font-semibold text-slate-900 dark:text-white">
                        Cost Component
                      </th>
                      <th className="px-4 py-3 text-right font-semibold text-slate-900 dark:text-white">
                        Cost per Kg (₹)
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-750">
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        Shipper Box Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-slate-900 dark:text-white">
                        ₹{results.shipperBoxCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-750">
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        Hygiene Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-slate-900 dark:text-white">
                        ₹{results.hygieneCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-750">
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        Scavenger Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-slate-900 dark:text-white">
                        ₹{results.scavengerCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-750">
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        MAP Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-slate-900 dark:text-white">
                        ₹{results.mapCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-750">
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        Smaller Size Packaging Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-slate-900 dark:text-white">
                        ₹{results.smallerSizePackagingCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-750">
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        Mono Carton Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-slate-900 dark:text-white">
                        ₹{results.monoCartonCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-750">
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        Sticker Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-slate-900 dark:text-white">
                        ₹{results.stickerCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-750">
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        Butter Paper Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-slate-900 dark:text-white">
                        ₹{results.butterPaperCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-750">
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        Excess Stock Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-slate-900 dark:text-white">
                        ₹{results.excessStockCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-200 dark:border-slate-700 bg-amber-50 dark:bg-amber-950">
                      <td className="px-4 py-3 font-medium text-slate-900 dark:text-white">
                        Material Wastage Cost
                      </td>
                      <td className="px-4 py-3 text-right font-medium text-amber-900 dark:text-amber-200">
                        ₹{results.materialWastageCostPerKg.toFixed(2)}
                      </td>
                    </tr>
                    <tr className="bg-green-100 dark:bg-green-900 border-t-2 border-green-300 dark:border-green-700">
                      <td className="px-4 py-4 font-bold text-lg text-green-900 dark:text-green-200">
                        👉 TOTAL PACKAGING & HANDLING COST / KG
                      </td>
                      <td className="px-4 py-4 text-right font-bold text-lg text-green-900 dark:text-green-200">
                        ₹{results.totalPackagingHandlingCost.toFixed(2)}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* Summary Box */}
              <div className="bg-gradient-to-r from-green-50 to-blue-50 dark:from-green-950 dark:to-blue-950 rounded-lg p-6 border-2 border-green-300 dark:border-green-700">
                <h3 className="text-lg font-bold text-green-900 dark:text-green-200 mb-3">
                  📊 Final Summary
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">
                      Product Name
                    </p>
                    <p className="text-xl font-bold text-slate-900 dark:text-white">
                      {inputs.productName || "Not specified"}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">
                      Total Cost per Kg
                    </p>
                    <p className="text-2xl font-bold text-green-700 dark:text-green-300">
                      ₹{results.totalPackagingHandlingCost.toFixed(2)}/Kg
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </>
    </Layout>
  );
}



