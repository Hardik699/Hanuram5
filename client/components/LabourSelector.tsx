import { useState, useEffect, useRef } from "react";
import { ChevronDown, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface Labour {
  id: string;
  code: string;
  name: string;
  department: string;
  salaryPerDay: number;
}

interface LabourSelectorProps {
  recipeId?: string;
  type: "production" | "packing";
  onLabourAdded?: () => void;
  selectedLabour?: Labour[];
}

export function LabourSelector({
  recipeId,
  type,
  onLabourAdded,
  selectedLabour = [],
}: LabourSelectorProps) {
  const [allLabour, setAllLabour] = useState<Labour[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(
    new Set(selectedLabour.map((l) => l.id))
  );
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Fetch all labour
  const fetchLabour = async () => {
    try {
      const response = await fetch("/api/labour");
      if (!response.ok) {
        console.error("API response not ok:", response.status, response.statusText);
        return;
      }
      const result = await response.json();
      if (result.success && Array.isArray(result.data)) {
        setAllLabour(result.data);
      }
    } catch (error) {
      console.error("Error fetching labour:", error);
    }
  };

  useEffect(() => {
    fetchLabour();
  }, []);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Filter labour (exclude already selected)
  const filteredLabour = allLabour.filter((labour) => {
    const matchesSearch =
      labour.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      labour.code.toLowerCase().includes(searchTerm.toLowerCase()) ||
      labour.department.toLowerCase().includes(searchTerm.toLowerCase());

    const isNotSelected = !selectedIds.has(labour.id);

    return matchesSearch && isNotSelected;
  });

  const handleSelectLabour = async (labour: Labour) => {
    if (!recipeId) {
      toast.error("Recipe ID is required");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch("/api/recipes/labour", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          recipeId,
          labourId: labour.id,
          type,
        }),
      });

      const result = await response.json();

      if (result.success) {
        setSelectedIds((prev) => new Set(prev).add(labour.id));
        setSearchTerm("");
        setIsOpen(false);
        toast.success(`${labour.name} added to ${type} labour`);
        onLabourAdded?.();
      } else {
        toast.error(result.message || "Failed to add labour");
      }
    } catch (error) {
      console.error("Error adding labour:", error);
      toast.error("Failed to add labour");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <Button
        type="button"
        variant="outline"
        className="w-full justify-between"
        onClick={() => setIsOpen(!isOpen)}
        disabled={loading || allLabour.length === 0}
      >
        <span className="text-slate-600">
          {allLabour.length === 0
            ? "No labour available"
            : `Select Labour (${allLabour.length - selectedIds.size} available)`}
        </span>
        <ChevronDown
          className={`w-4 h-4 transition-transform ${isOpen ? "rotate-180" : ""}`}
        />
      </Button>

      {isOpen && (
        <div className="absolute top-full left-0 right-0 mt-2 bg-white border border-slate-200 rounded-lg shadow-lg z-50">
          <div className="p-2 border-b border-slate-200">
            <Input
              placeholder="Search labour..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="h-9"
              autoFocus
            />
          </div>

          <div className="max-h-64 overflow-y-auto">
            {filteredLabour.length === 0 ? (
              <div className="p-4 text-center text-slate-500 text-sm">
                {searchTerm
                  ? "No labour found matching search"
                  : "All labour are already added"}
              </div>
            ) : (
              filteredLabour.map((labour) => (
                <button
                  key={labour.id}
                  onClick={() => handleSelectLabour(labour)}
                  className="w-full px-4 py-2.5 text-left hover:bg-slate-100 transition-colors border-b border-slate-100 last:border-b-0"
                  disabled={loading}
                >
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="font-medium text-slate-900">
                        {labour.name}
                      </div>
                      <div className="text-xs text-slate-500">
                        {labour.code} • {labour.department}
                      </div>
                    </div>
                    <div className="text-sm font-semibold text-teal-600">
                      ₹{labour.salaryPerDay.toFixed(2)}
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}

