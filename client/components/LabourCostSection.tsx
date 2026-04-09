import { useEffect, useState, useRef } from "react";

interface LabourCostSectionProps {
  recipeId?: string;
  recipeQuantity: number;
  type: "production" | "packing";
  title: string;
  initialCostPerKg?: number;
  onCostChange?: (costPerKg: number) => void;
  readOnly?: boolean;
}

export function LabourCostSection({
  recipeId,
  recipeQuantity,
  type,
  title,
  initialCostPerKg = 0,
  onCostChange,
  readOnly = false,
}: LabourCostSectionProps) {
  const [perKgCost, setPerKgCost] = useState<string>("");
  const synced = useRef(false);

  useEffect(() => {
    if (!synced.current && initialCostPerKg > 0) {
      setPerKgCost(String(initialCostPerKg));
      synced.current = true;
    }
  }, [initialCostPerKg]);

  const perKgNum = parseFloat(perKgCost) || 0;
  const totalCost = perKgNum * recipeQuantity;

  // Notify parent on every change so Save button gets latest value
  useEffect(() => {
    onCostChange?.(perKgNum);
  }, [perKgNum]);

  const handleChange = (val: string) => {
    setPerKgCost(val);
  };

  return (
    <div className="rounded-xl border-2 border-blue-100 overflow-hidden">
      {/* Title */}
      <div className="flex items-center px-4 py-3 bg-gradient-to-r from-blue-600 to-blue-500">
        <span className="text-sm font-bold text-white tracking-wide">{title}</span>
      </div>

      {/* Content */}
      <div className="p-4 bg-blue-50/20">
        <div className="grid grid-cols-3 gap-4 items-end">

          {/* Cost per KG */}
          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1.5">
              Cost / KG (&#8377;)
            </label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 font-bold text-sm">&#8377;</span>
              <input
                type="number"
                min="0"
                step="0.01"
                value={perKgCost}
                onChange={(e) => !readOnly && handleChange(e.target.value)}
                onWheel={(e) => (e.target as HTMLInputElement).blur()}
                placeholder="0.00"
                readOnly={readOnly}
                className={`w-full pl-8 pr-3 py-2.5 rounded-lg border-2 font-bold text-sm outline-none transition-all ${
                  readOnly
                    ? "bg-slate-100 border-slate-200 cursor-not-allowed text-slate-400"
                    : "bg-white border-blue-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 text-slate-900"
                }`}
              />
            </div>
          </div>

          {/* Yield Qty */}
          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1.5">
              Yield Qty
            </label>
            <div className="w-full px-4 py-2.5 rounded-lg border-2 border-dashed border-blue-300 bg-blue-50 font-bold text-sm text-center text-slate-600">
              {recipeQuantity || 0}
            </div>
          </div>

          {/* Total */}
          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1.5">
              Total Cost
            </label>
            <div className="w-full px-4 py-2.5 rounded-lg bg-blue-600 font-bold text-sm text-center text-white">
              &#8377;{totalCost.toFixed(2)}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
