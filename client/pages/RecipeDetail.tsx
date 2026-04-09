import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Edit2,
  Trash2,
  FileText,
  Plus,
  X,
  Check,
  AlertCircle,
  ChevronDown,
  CheckCircle,
  History,
  Calculator,
  ArrowLeft,
  Settings,
  Shield,
  Eye,
  MoreVertical,
} from "lucide-react";
import { Layout } from "@/components/Layout";
import Modal from "@/components/ui/Modal";
import { Button } from "@/components/ui/button";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { CostingCalculatorForm } from "@/components/CostingCalculatorForm";
import { PermissionGate } from "@/components/PermissionGate";
import { useAuth } from "@/hooks/useAuth";
import { toast } from "sonner";
import { ProfessionalPage, EmptyState } from "@/components/ProfessionalPage";
import {
  ProfessionalForm,
  FormGroup,
  FormActions,
} from "@/components/ProfessionalForm";
import { DataTable } from "@/components/DataTable";
import { cn } from "@/lib/utils";

interface Unit {
  _id: string;
  name: string;
}

interface Vendor {
  _id: string;
  name: string;
  contactPerson?: string;
  phone?: string;
  email?: string;
}

interface RecipeItem {
  _id?: string;
  rawMaterialId: string;
  rawMaterialName: string;
  rawMaterialCode: string;
  quantity: number;
  unitId?: string;
  unitName?: string;
  price: number;
  vendorId?: string;
  vendorName?: string;
  totalPrice: number;
}

interface Recipe {
  _id: string;
  code: string;
  name: string;
  recipeType?: string; // "master" or "sub"
  batchSize: number;
  unitId: string;
  unitName: string;
  yield?: number;
  moisturePercentage?: number;
  totalRawMaterialCost: number;
  pricePerUnit: number;
  productionLabourCostPerKg?: number;
  packingLabourCostPerKg?: number;
  createdAt: string;
  updatedAt: string;
  items?: RecipeItem[];
}

interface Quotation {
  _id: string;
  recipeId: string;
  companyName: string;
  reason: string;
  quantity: number;
  unitId: string;
  date: string;
  createdBy: string;
  phoneNumber: string;
  email: string;
  items: RecipeItem[];
  totalRecipeCost?: number;
  perUnitCost?: number;
  status?: "pending" | "approved" | "rejected";
  createdAt: string;
}

interface VendorPrice {
  _id: string;
  vendorId: string;
  vendorName: string;
  price: number;
  addedDate: string;
  lastPurchaseDate?: string;
}

interface RecipeLog {
  _id: string;
  recipeId: string;
  fieldChanged: string;
  oldValue: any;
  newValue: any;
  changeDate: string;
  changedBy: string;
}

interface QuotationCalculatedItem {
  rawMaterialId: string;
  rawMaterialName: string;
  rawMaterialCode: string;
  masterQty: number;
  calculatedQty: number;
  unitName: string;
  unitPrice: number;
  calculatedTotal: number;
}

export default function RecipeDetail() {
  const { recipeId } = useParams();
  const navigate = useNavigate();
  const { hasPermission, user } = useAuth();
  const isProductionUser = user?.role_id === 7;

  // Data
  const [recipe, setRecipe] = useState<Recipe | null>(null);
  const [units, setUnits] = useState<Unit[]>([]);
  const [vendors, setVendors] = useState<Vendor[]>([]);
  const [quotations, setQuotations] = useState<Quotation[]>([]);
  const [logs, setLogs] = useState<RecipeLog[]>([]);
  const [productionLabourCostPerKg, setProductionLabourCostPerKg] = useState(0);
  const [packingLabourCostPerKg, setPackingLabourCostPerKg] = useState(0);
  const [packagingCostPerKg, setPackagingCostPerKg] = useState(0);

  // UI State
  const [activeTab, setActiveTab] = useState<
    "information" | "recipe-history" | "quotation-history"
  >("information");
  const [recipeHistory, setRecipeHistory] = useState<any[]>([]);
  const [selectedHistorySnapshot, setSelectedHistorySnapshot] =
    useState<any>(null);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteError, setDeleteError] = useState("");
  const [showQuotationForm, setShowQuotationForm] = useState(false);
  const [quotationCreating, setQuotationCreating] = useState(false);
  const [showChangeVendorModal, setShowChangeVendorModal] = useState(false);
  const [selectedItemForVendor, setSelectedItemForVendor] =
    useState<RecipeItem | null>(null);
  const [vendorPrices, setVendorPrices] = useState<VendorPrice[]>([]);
  const [selectedVendorId, setSelectedVendorId] = useState<string>("");
  const [quotationItemOverrides, setQuotationItemOverrides] = useState<
    Record<string, { vendorId: string; vendorName: string; price: number }>
  >({});
  const [showDeleteQuotationModal, setShowDeleteQuotationModal] =
    useState(false);
  const [quotationToDelete, setQuotationToDelete] = useState<string | null>(
    null,
  );
  const [selectedEntriesForComparison, setSelectedEntriesForComparison] =
    useState<any[]>([]);
  const [showComparisonModal, setShowComparisonModal] = useState(false);

  // Quotation Form
  const [quotationForm, setQuotationForm] = useState({
    companyName: "",
    reason: "",
    quantity: "",
    date: new Date().toISOString().split("T")[0],
    createdBy: "",
    phoneNumber: "",
    email: "",
    unitId: "",
  });
  const [quotationErrors, setQuotationErrors] = useState<
    Record<string, string>
  >({});

  // Quotation Calculations
  const [quotationCalculatedItems, setQuotationCalculatedItems] = useState<
    QuotationCalculatedItem[]
  >([]);
  const [quotationSummary, setQuotationSummary] = useState({
    totalRecipeCost: 0,
    perUnitCost: 0,
    scalingFactor: 0,
  });

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      navigate("/");
      return;
    }
    const username = localStorage.getItem("username");
    if (username) {
      setQuotationForm((prev) => ({ ...prev, createdBy: username }));
    }
    fetchAllData();
  }, [recipeId]);

  useEffect(() => {
    if (recipe) {
      fetchAndCalculateLabourCosts();
    }
  }, [recipe, recipeId]);

  // Refresh recipe data when component comes back into focus
  useEffect(() => {
    const handleFocus = () => {
      if (recipeId) {
        fetchRecipe();
      }
    };

    window.addEventListener("focus", handleFocus);
    return () => window.removeEventListener("focus", handleFocus);
  }, [recipeId]);

  const fetchAllData = async () => {
    try {
      setLoading(true);
      // Reset all cost states for fresh recipe data
      setProductionLabourCostPerKg(0);
      setPackingLabourCostPerKg(0);
      setPackagingCostPerKg(0);

      if (recipeId) {
        await Promise.all([
          fetchRecipe(),
          fetchUnits(),
          fetchVendors(),
          fetchQuotations(),
          fetchLogs(),
          fetchRecipeHistory(),
          fetchPackagingCosts(),
        ]);
      }
    } catch (error) {
      console.error("Error fetching data:", error);
      toast.error("Failed to load data");
    } finally {
      setLoading(false);
    }
  };

  const fetchRecipe = async () => {
    try {
      const response = await fetch(`/api/recipes`);
      const data = await response.json();
      if (data.success) {
        const found = data.data.find((r: Recipe) => r._id === recipeId);
        if (found) {
          setRecipe(found);
          // Load saved labour costs from recipe
          if (found.productionLabourCostPerKg !== undefined) {
            setProductionLabourCostPerKg(found.productionLabourCostPerKg);
          }
          if (found.packingLabourCostPerKg !== undefined) {
            setPackingLabourCostPerKg(found.packingLabourCostPerKg);
          }
          // Fetch recipe items
          const itemsResponse = await fetch(`/api/recipes/${recipeId}/items`);
          const itemsData = await itemsResponse.json();
          if (itemsData.success) {
            setRecipe((prev) =>
              prev ? { ...prev, items: itemsData.data } : null,
            );
          }
        }
      }
    } catch (error) {
      console.error("Error fetching recipe:", error);
    }
  };

  const fetchUnits = async () => {
    try {
      const response = await fetch("/api/units");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success) setUnits(data.data);
    } catch (error) {
      console.error("Error fetching units:", error);
    }
  };

  const fetchVendors = async () => {
    try {
      const response = await fetch("/api/vendors");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success) setVendors(data.data);
    } catch (error) {
      console.error("Error fetching vendors:", error);
    }
  };

  const fetchQuotations = async () => {
    try {
      if (recipeId) {
        const url = `/api/quotations/recipe/${recipeId}`;
        console.log("Fetching quotations from:", url);
        const response = await fetch(url);

        if (!response.ok) {
          const errorText = await response.text();
          console.error(
            "Failed to fetch quotations - Status:",
            response.status,
            "Response:",
            errorText,
          );
          return;
        }

        const contentType = response.headers.get("content-type");
        if (!contentType?.includes("application/json")) {
          console.error("Invalid content-type:", contentType);
          return;
        }

        const data = await response.json();
        if (data.success) {
          setQuotations(data.data || []);
        } else {
          console.error("API returned error:", data.message);
        }
      }
    } catch (error) {
      console.error("Error fetching quotations:", error);
    }
  };

  const fetchLogs = async () => {
    try {
      if (recipeId) {
        const response = await fetch(`/api/recipes/${recipeId}/logs`);
        const data = await response.json();
        if (data.success) setLogs(data.data);
      }
    } catch (error) {
      console.error("Error fetching logs:", error);
    }
  };

  const fetchRecipeHistory = async () => {
    try {
      if (recipeId) {
        const response = await fetch(`/api/recipes/${recipeId}/history`);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        if (data.success) setRecipeHistory(data.data || []);
      }
    } catch (error) {
      console.error("Error fetching recipe history:", error);
    }
  };

  const fetchPackagingCosts = async () => {
    try {
      if (recipeId) {
        const response = await fetch(
          `/api/recipes/${recipeId}/packaging-costs`,
        );
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data && data.data.results) {
            setPackagingCostPerKg(
              data.data.results.totalPackagingHandlingCost || 0,
            );
          }
        }
      }
    } catch (error) {
      console.debug("Error fetching packaging costs:", error);
      setPackagingCostPerKg(0);
    }
  };

  const fetchVendorPricesForRawMaterial = async (rawMaterialId: string) => {
    try {
      const response = await fetch(
        `/api/raw-materials/${rawMaterialId}/vendor-prices`,
      );
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setVendorPrices(data.data);
      } else {
        setVendorPrices([]);
      }
    } catch (error) {
      console.error("Error fetching vendor prices:", error);
      setVendorPrices([]);
    }
  };

  const fetchAndCalculateLabourCosts = async () => {
    try {
      if (!recipeId || !recipe) return;

      let prodLabourTotal = 0;
      let packLabourTotal = 0;

      try {
        const prodRes = await fetch(
          `/api/recipes/${recipeId}/labour?type=production`,
        );
        if (prodRes.ok) {
          const prodData = await prodRes.json();
          if (prodData.success && prodData.data) {
            prodLabourTotal = (prodData.data as any[]).reduce(
              (sum, item) => sum + (item.labour?.salaryPerDay || 0),
              0,
            );
          }
        }
      } catch (error) {
        console.debug("Error fetching production labour costs:", error);
      }

      try {
        const packRes = await fetch(
          `/api/recipes/${recipeId}/labour?type=packing`,
        );
        if (packRes.ok) {
          const packData = await packRes.json();
          if (packData.success && packData.data) {
            packLabourTotal = (packData.data as any[]).reduce(
              (sum, item) => sum + (item.labour?.salaryPerDay || 0),
              0,
            );
          }
        }
      } catch (error) {
        console.debug("Error fetching packing labour costs:", error);
      }

      const prodCostPerKg =
        recipe.batchSize > 0 ? prodLabourTotal / recipe.batchSize : 0;
      const packCostPerKg =
        recipe.batchSize > 0 ? packLabourTotal / recipe.batchSize : 0;

      // Use saved values if they exist, otherwise use calculated values
      const finalProdCost = recipe.productionLabourCostPerKg || prodCostPerKg;
      const finalPackCost = recipe.packingLabourCostPerKg || packCostPerKg;

      setProductionLabourCostPerKg(finalProdCost);
      setPackingLabourCostPerKg(finalPackCost);
    } catch (error) {
      console.error("Unexpected error fetching labour costs:", error);
    }
  };

  const handleDeleteRecipe = async () => {
    if (!deletePassword) {
      setDeleteError("Password is required");
      return;
    }

    try {
      const response = await fetch(`/api/recipes/${recipeId}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: deletePassword }),
      });

      const data = await response.json();
      if (data.success) {
        toast.success("Recipe Deleted!", {
          description: `Recipe has been permanently removed from your database`,
          duration: 3000,
        });
        setTimeout(() => {
          navigate("/rmc");
        }, 1000);
      } else {
        const errMsg = data.message || "Failed to delete recipe";
        setDeleteError(errMsg);
        toast.error("Delete Failed", {
          description: errMsg,
          duration: 3000,
        });
      }
    } catch (error) {
      const errMsg = "Failed to delete recipe";
      setDeleteError(errMsg);
      toast.error("Error Deleting Recipe", {
        description: errMsg,
        duration: 3000,
      });
    }
  };

  // Calculate quotation items based on required quantity
  const handleCalculateQuotation = (requiredQty: number) => {
    if (!recipe || requiredQty <= 0 || recipe.batchSize <= 0) {
      setQuotationCalculatedItems([]);
      setQuotationSummary({
        totalRecipeCost: 0,
        perUnitCost: 0,
        scalingFactor: 0,
      });
      return;
    }

    // Calculate scaling factor
    const scalingFactor = requiredQty / recipe.batchSize;

    // Calculate each item
    const calculated: QuotationCalculatedItem[] = (recipe.items || []).map(
      (item) => {
        const calculatedQty = item.quantity * scalingFactor;
        const calculatedTotal = calculatedQty * item.price;

        return {
          rawMaterialId: item.rawMaterialId,
          rawMaterialName: item.rawMaterialName,
          rawMaterialCode: item.rawMaterialCode,
          masterQty: item.quantity,
          calculatedQty: calculatedQty,
          unitName: item.unitName || "",
          unitPrice: item.price,
          calculatedTotal: calculatedTotal,
        };
      },
    );

    // Calculate total cost and per unit cost
    const totalRecipeCost = calculated.reduce(
      (sum, item) => sum + item.calculatedTotal,
      0,
    );
    const perUnitCost = totalRecipeCost / requiredQty;

    setQuotationCalculatedItems(calculated);
    setQuotationSummary({
      totalRecipeCost,
      perUnitCost,
      scalingFactor,
    });
  };

  const handleAddQuotation = async () => {
    if (!recipe) return;

    // Validate required fields
    if (
      !quotationForm.companyName.trim() ||
      !quotationForm.reason.trim() ||
      !quotationForm.quantity ||
      !quotationForm.unitId ||
      !quotationForm.phoneNumber.trim() ||
      !quotationForm.email.trim()
    ) {
      toast.error("Please fill in all required fields");
      return;
    }

    // Validate that calculation has been done
    if (quotationCalculatedItems.length === 0) {
      toast.error("Please enter a valid quantity to calculate");
      return;
    }

    // Validate that all items have prices
    if (quotationCalculatedItems.some((item) => item.unitPrice <= 0)) {
      toast.error("Some raw materials are missing prices");
      return;
    }

    setQuotationCreating(true);
    try {
      // Create items with calculated values
      const itemsForQuotation = quotationCalculatedItems.map((item) => {
        const override = quotationItemOverrides[item.rawMaterialId];
        const finalPrice = override?.price ?? item.unitPrice;
        const finalCalculatedTotal = item.calculatedQty * finalPrice;

        return {
          rawMaterialId: item.rawMaterialId,
          rawMaterialName: item.rawMaterialName,
          rawMaterialCode: item.rawMaterialCode,
          masterQty: item.masterQty,
          calculatedQty: item.calculatedQty,
          unitName: item.unitName,
          unitPrice: finalPrice,
          calculatedTotal: finalCalculatedTotal,
          vendorId: override?.vendorId || "",
        };
      });

      const response = await fetch("/api/quotations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          recipeId: recipe._id,
          companyName: quotationForm.companyName,
          reason: quotationForm.reason,
          requiredQty: Number(quotationForm.quantity),
          masterBatchQty: recipe.batchSize,
          scalingFactor: quotationSummary.scalingFactor,
          date: quotationForm.date,
          createdBy: quotationForm.createdBy,
          phoneNumber: quotationForm.phoneNumber,
          email: quotationForm.email,
          unitId: quotationForm.unitId || recipe.unitId,
          items: itemsForQuotation,
          totalRecipeCost: quotationSummary.totalRecipeCost,
          perUnitCost: quotationSummary.perUnitCost,
        }),
      });

      const data = await response.json();
      if (data.success) {
        toast.success("Quotation Created!", {
          description: `Quotation for ${quotationForm.companyName} has been created successfully`,
          duration: 3000,
        });
        setShowQuotationForm(false);
        setQuotationForm({
          companyName: "",
          reason: "",
          quantity: "",
          date: new Date().toISOString().split("T")[0],
          createdBy: quotationForm.createdBy,
          phoneNumber: "",
          email: "",
          unitId: "",
        });
        // Clear calculations and overrides
        setQuotationCalculatedItems([]);
        setQuotationSummary({
          totalRecipeCost: 0,
          perUnitCost: 0,
          scalingFactor: 0,
        });
        setQuotationItemOverrides({});
        fetchQuotations();
      } else {
        toast.error("Failed to Create Quotation", {
          description: data.message || "Something went wrong",
          duration: 3000,
        });
      }
    } catch (error) {
      toast.error("Error Creating Quotation", {
        description: "An unexpected error occurred",
        duration: 3000,
      });
    } finally {
      setQuotationCreating(false);
    }
  };

  const handleChangeVendor = (newVendorId: string, newPrice: number) => {
    if (!selectedItemForVendor) return;

    // Find the selected vendor's name from vendorPrices
    const selectedVendor = vendorPrices.find(
      (vp) => vp.vendorId === newVendorId,
    );
    if (!selectedVendor) return;

    // Store vendor override for this quotation item only
    const itemKey = selectedItemForVendor.rawMaterialId;
    setQuotationItemOverrides((prev) => ({
      ...prev,
      [itemKey]: {
        vendorId: newVendorId,
        vendorName: selectedVendor.vendorName,
        price: newPrice,
      },
    }));

    toast.success("Vendor changed successfully");
    setShowChangeVendorModal(false);
    setSelectedItemForVendor(null);
    setSelectedVendorId("");
  };

  const toggleHistorySelection = (snapshot: any) => {
    const isSelected = selectedEntriesForComparison.find(
      (s) => s._id === snapshot._id,
    );
    if (isSelected) {
      // Deselect
      setSelectedEntriesForComparison(
        selectedEntriesForComparison.filter((s) => s._id !== snapshot._id),
      );
    } else {
      // Select (max 2)
      if (selectedEntriesForComparison.length < 2) {
        setSelectedEntriesForComparison([
          ...selectedEntriesForComparison,
          snapshot,
        ]);
      } else {
        // Replace the oldest one
        setSelectedEntriesForComparison([
          selectedEntriesForComparison[1],
          snapshot,
        ]);
      }
    }
  };

  const getComparisonChanges = () => {
    if (selectedEntriesForComparison.length !== 2) return [];

    const [first, second] = selectedEntriesForComparison;
    const changes: any[] = [];

    // Compare items
    first.items?.forEach((item: any) => {
      const secondItem = second.items?.find(
        (si: any) => si.rawMaterialId === item.rawMaterialId,
      );
      if (secondItem) {
        if (item.price !== secondItem.price) {
          changes.push({
            type: "price_change",
            rawMaterialName: item.rawMaterialName,
            rawMaterialCode: item.rawMaterialCode,
            field: "Price",
            oldValue: secondItem.price,
            newValue: item.price,
            oldValueFormatted: `₹${secondItem.price.toFixed(2)}`,
            newValueFormatted: `₹${item.price.toFixed(2)}`,
          });
        }
        if (item.quantity !== secondItem.quantity) {
          changes.push({
            type: "quantity_change",
            rawMaterialName: item.rawMaterialName,
            rawMaterialCode: item.rawMaterialCode,
            field: "Quantity",
            oldValue: secondItem.quantity,
            newValue: item.quantity,
            oldValueFormatted: secondItem.quantity,
            newValueFormatted: item.quantity,
          });
        }
        if (item.vendorName !== secondItem.vendorName) {
          changes.push({
            type: "vendor_change",
            rawMaterialName: item.rawMaterialName,
            rawMaterialCode: item.rawMaterialCode,
            field: "Vendor",
            oldValue: secondItem.vendorName || "-",
            newValue: item.vendorName || "-",
            oldValueFormatted: secondItem.vendorName || "-",
            newValueFormatted: item.vendorName || "-",
          });
        }
      } else {
        // Item was removed
        changes.push({
          type: "item_removed",
          rawMaterialName: item.rawMaterialName,
          rawMaterialCode: item.rawMaterialCode,
          field: "Item Status",
          oldValue: "Present",
          newValue: "Removed",
          oldValueFormatted: "Present",
          newValueFormatted: "Removed",
        });
      }
    });

    // Check for added items
    second.items?.forEach((item: any) => {
      const firstItem = first.items?.find(
        (fi: any) => fi.rawMaterialId === item.rawMaterialId,
      );
      if (!firstItem) {
        changes.push({
          type: "item_added",
          rawMaterialName: item.rawMaterialName,
          rawMaterialCode: item.rawMaterialCode,
          field: "Item Status",
          oldValue: "Not Present",
          newValue: "Added",
          oldValueFormatted: "Not Present",
          newValueFormatted: "Added",
        });
      }
    });

    return changes;
  };

  const handleApproveQuotation = async (quotationId: string) => {
    try {
      const response = await fetch(`/api/quotations/${quotationId}/approve`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
      });

      const data = await response.json();
      if (data.success) {
        toast.success("Quotation approved successfully");
        fetchQuotations();
      } else {
        toast.error(data.message || "Failed to approve quotation");
      }
    } catch (error) {
      toast.error("Failed to approve quotation");
    }
  };

  const handleRejectQuotation = async (quotationId: string) => {
    try {
      const response = await fetch(`/api/quotations/${quotationId}/reject`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
      });

      const data = await response.json();
      if (data.success) {
        toast.success("Quotation rejected successfully");
        fetchQuotations();
      } else {
        toast.error(data.message || "Failed to reject quotation");
      }
    } catch (error) {
      toast.error("Failed to reject quotation");
    }
  };

  const handleDeleteQuotation = async () => {
    if (!quotationToDelete) return;

    try {
      const response = await fetch(`/api/quotations/${quotationToDelete}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
      });

      const data = await response.json();
      if (data.success) {
        toast.success("Quotation deleted successfully");
        setShowDeleteQuotationModal(false);
        setQuotationToDelete(null);
        fetchQuotations();
      } else {
        toast.error(data.message || "Failed to delete quotation");
      }
    } catch (error) {
      toast.error("Failed to delete quotation");
    }
  };

  const handlePrintRecipePDF = () => {
    if (!recipe) return;
    const printWindow = window.open("", "_blank");
    if (printWindow) {
      const today = new Date().toLocaleDateString("en-IN", { day: "2-digit", month: "long", year: "numeric" });
      const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>${recipe.name} - Recipe Card</title>
          <meta charset="UTF-8">
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #fff; color: #1a1a2e; font-size: 13px; }

            /* Header */
            .header {
              background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
              color: white;
              padding: 28px 40px 22px;
              display: flex;
              justify-content: space-between;
              align-items: center;
            }
            .company-name { font-size: 26px; font-weight: 800; letter-spacing: 1px; }
            .company-sub { font-size: 11px; opacity: 0.8; margin-top: 3px; letter-spacing: 2px; text-transform: uppercase; }
            .doc-info { text-align: right; }
            .doc-title { font-size: 14px; font-weight: 700; background: rgba(255,255,255,0.2); padding: 6px 14px; border-radius: 20px; display: inline-block; }
            .doc-date { font-size: 11px; opacity: 0.75; margin-top: 6px; }

            /* Recipe Title Band */
            .recipe-title-band {
              background: #f0f6ff;
              border-left: 6px solid #2563eb;
              padding: 18px 40px;
              display: flex;
              justify-content: space-between;
              align-items: center;
              border-bottom: 1px solid #dbeafe;
            }
            .recipe-name { font-size: 22px; font-weight: 800; color: #1e3a5f; text-transform: uppercase; letter-spacing: 0.5px; }
            .recipe-code-badge {
              background: #2563eb;
              color: white;
              padding: 5px 16px;
              border-radius: 20px;
              font-size: 12px;
              font-weight: 700;
              letter-spacing: 1px;
            }

            /* Info Grid */
            .info-section { padding: 20px 40px; border-bottom: 1px solid #e5e7eb; }
            .section-title {
              font-size: 11px;
              font-weight: 700;
              color: #6b7280;
              text-transform: uppercase;
              letter-spacing: 1.5px;
              margin-bottom: 14px;
              display: flex;
              align-items: center;
              gap: 8px;
            }
            .section-title::after { content: ''; flex: 1; height: 1px; background: #e5e7eb; }
            .info-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
            .info-card {
              background: #f9fafb;
              border: 1px solid #e5e7eb;
              border-radius: 8px;
              padding: 12px 16px;
            }
            .info-label { font-size: 10px; color: #9ca3af; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 4px; }
            .info-value { font-size: 16px; font-weight: 700; color: #111827; }
            .info-value.green { color: #059669; }
            .info-value.blue { color: #2563eb; }

            /* Table */
            .table-section { padding: 20px 40px; }
            table { width: 100%; border-collapse: collapse; }
            thead tr {
              background: linear-gradient(135deg, #1e3a5f, #2563eb);
              color: white;
            }
            thead th {
              padding: 11px 14px;
              font-size: 11px;
              font-weight: 700;
              text-transform: uppercase;
              letter-spacing: 0.8px;
            }
            thead th:first-child { border-radius: 6px 0 0 6px; }
            thead th:last-child { border-radius: 0 6px 6px 0; }
            tbody tr { border-bottom: 1px solid #f3f4f6; }
            tbody tr:nth-child(even) { background: #f9fafb; }
            tbody tr:hover { background: #eff6ff; }
            tbody td { padding: 10px 14px; font-size: 12px; color: #374151; }
            .rm-name { font-weight: 600; color: #111827; }
            .rm-code { font-size: 10px; color: #9ca3af; margin-top: 2px; }
            .text-right { text-align: right; }
            .text-center { text-align: center; }
            .price-cell { font-weight: 600; color: #374151; }
            .total-cell { font-weight: 700; color: #1e3a5f; }

            /* Summary Footer */
            .summary-bar {
              margin: 0 40px 20px;
              background: linear-gradient(135deg, #1e3a5f, #2563eb);
              border-radius: 10px;
              padding: 18px 28px;
              display: flex;
              justify-content: flex-end;
              gap: 50px;
              color: white;
            }
            .summary-item { text-align: center; }
            .summary-label { font-size: 10px; opacity: 0.8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
            .summary-value { font-size: 20px; font-weight: 800; }

            /* Footer */
            .footer {
              background: #f9fafb;
              border-top: 2px solid #e5e7eb;
              padding: 14px 40px;
              display: flex;
              justify-content: space-between;
              align-items: center;
              font-size: 10px;
              color: #9ca3af;
            }
            .footer-brand { font-weight: 700; color: #6b7280; font-size: 11px; }

            @media print {
              body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
              @page { margin: 0; size: A4; }
            }
          </style>
        </head>
        <body>
          <!-- Header -->
          <div class="header">
            <div>
              <div class="company-name">🍬 HANURAM FOODS</div>
              <div class="company-sub">Premium Quality · Authentic Taste</div>
            </div>
            <div class="doc-info">
              <div class="doc-title">📋 RECIPE CARD</div>
              <div class="doc-date">Generated: ${today}</div>
            </div>
          </div>

          <!-- Recipe Title -->
          <div class="recipe-title-band">
            <div class="recipe-name">${recipe.name}</div>
            <div class="recipe-code-badge">${recipe.code}</div>
          </div>

          <!-- Recipe Info -->
          <div class="info-section">
            <div class="section-title">Recipe Details</div>
            <div class="info-grid">
              <div class="info-card">
                <div class="info-label">Recipe Type</div>
                <div class="info-value">${recipe.recipeType || "Master Recipe"}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Batch Size</div>
                <div class="info-value blue">${recipe.batchSize} ${recipe.unitName || "kg"}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Yield</div>
                <div class="info-value blue">${recipe.yield} ${recipe.unitName || "kg"}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Moisture %</div>
                <div class="info-value">${recipe.moisturePercentage ? recipe.moisturePercentage + "%" : "—"}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Total RM Cost</div>
                <div class="info-value green">₹${recipe.totalRawMaterialCost.toFixed(2)}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Price Per Unit</div>
                <div class="info-value green">₹${recipe.pricePerUnit.toFixed(2)}/${recipe.unitName || "kg"}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Total Items</div>
                <div class="info-value">${recipe.items?.length || 0} Materials</div>
              </div>
              <div class="info-card">
                <div class="info-label">Unit</div>
                <div class="info-value">${recipe.unitName || "kg"}</div>
              </div>
            </div>
          </div>

          <!-- Materials Table -->
          <div class="table-section">
            <div class="section-title">Raw Materials</div>
            <table>
              <thead>
                <tr>
                  <th style="width:40%">Raw Material</th>
                  <th class="text-center" style="width:10%">Qty</th>
                  <th class="text-center" style="width:10%">Unit</th>
                  <th class="text-right" style="width:20%">Unit Price</th>
                  <th class="text-right" style="width:20%">Total</th>
                </tr>
              </thead>
              <tbody>
                ${recipe.items?.map((item, i) => `
                  <tr>
                    <td>
                      <div class="rm-name">${item.rawMaterialName}</div>
                      <div class="rm-code">${item.rawMaterialCode}</div>
                    </td>
                    <td class="text-center">${item.quantity}</td>
                    <td class="text-center">${item.unitName || "—"}</td>
                    <td class="text-right price-cell">₹${item.price.toFixed(2)}</td>
                    <td class="text-right total-cell">₹${item.totalPrice.toFixed(2)}</td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>

          <!-- Summary -->
          <div class="summary-bar">
            <div class="summary-item">
              <div class="summary-label">Total RM Cost</div>
              <div class="summary-value">₹${recipe.totalRawMaterialCost.toFixed(2)}</div>
            </div>
            <div class="summary-item">
              <div class="summary-label">Price Per Unit</div>
              <div class="summary-value">₹${recipe.pricePerUnit.toFixed(2)}/${recipe.unitName || "kg"}</div>
            </div>
          </div>

          <!-- Footer -->
          <div class="footer">
            <div class="footer-brand">🍬 HANURAM FOODS — Confidential Recipe Document</div>
            <div>${recipe.code} · ${today}</div>
          </div>

          <script>window.onload = () => { window.print(); }</script>
        </body>
        </html>
      `;
      printWindow.document.write(htmlContent);
      printWindow.document.close();
    }
  };

  if (loading) {
    return (
      <Layout>
        <LoadingSpinner message="Loading recipe details..." fullScreen />
      </Layout>
    );
  }

  if (!recipe) {
    return (
      <Layout>
        <div className="flex items-center justify-center min-h-screen">
          <p>Recipe not found</p>
        </div>
      </Layout>
    );
  }

  const totalRMCost = recipe.totalRawMaterialCost;
  const pricePerUnit = recipe.pricePerUnit;

  return (
    <Layout>
      <ProfessionalPage
        title={recipe.name}
        description={`View and manage recipe details, history, and quotations for ${recipe.code}.`}
        showBackButton={true}
        headerAction={
          <div className="flex items-center gap-3">
            {!isProductionUser && (
              <>
                <button
                  onClick={() => navigate(`/recipe/${recipeId}/edit`)}
                  className="prof-btn-secondary"
                  title="Edit Recipe"
                >
                  <Edit2 size={16} />
                  <span>Edit</span>
                </button>
                <button
                  onClick={() => setShowDeleteModal(true)}
                  className="prof-btn-danger"
                  title="Delete Recipe"
                >
                  <Trash2 size={16} />
                  <span>Delete</span>
                </button>
              </>
            )}
            <button
              onClick={handlePrintRecipePDF}
              className="prof-btn-secondary"
              title="Print PDF"
            >
              <FileText size={16} />
              <span>PDF</span>
            </button>
            <button
              onClick={() => setShowLogsModal(true)}
              className="prof-btn-secondary"
              title="View Logs"
            >
              <History size={16} />
              <span>Logs</span>
            </button>
          </div>
        }
      >
        {/* Tabs */}
        <div className="flex gap-2 mb-4">
          {[
            {
              id: "information",
              label: "Information",
              icon: <FileText size={16} />,
            },
            ...(isProductionUser
              ? []
              : [
                  {
                    id: "recipe-history",
                    label: "Recipe History",
                    icon: <History size={16} />,
                  },
                  {
                    id: "quotation-history",
                    label: "Quotation History",
                    icon: <FileText size={16} />,
                  },
                ]),
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={cn(
                "flex items-center gap-2 px-4 py-1.5 rounded-lg text-sm font-semibold transition-all whitespace-nowrap border",
                activeTab === tab.id
                  ? "bg-blue-50 border-blue-200 text-blue-700 hover:bg-blue-100 hover:border-blue-300 hover:shadow-md"
                  : "bg-white border-slate-200 text-slate-600 hover:bg-slate-50 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-400",
              )}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* TAB 1: Information */}
        {activeTab === "information" && (
          <div className="space-y-4">
            {/* Recipe Info Section */}
            <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 p-5">
              <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-3">Recipe Information</h2>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                <div className="p-3 rounded bg-blue-50 dark:bg-blue-900/10 border border-blue-100 dark:border-blue-900/30">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-0.5">Recipe Code</label>
                  <p className="text-sm font-bold text-slate-900 dark:text-white">{recipe.code}</p>
                </div>

                <div className="p-3 rounded bg-blue-50 dark:bg-blue-900/10 border border-blue-100 dark:border-blue-900/30">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-0.5">Recipe Type</label>
                  <p className="text-sm font-bold text-slate-900 dark:text-white">
                    {recipe.recipeType === "sub" ? "Sub Recipe" : "Master Recipe"}
                  </p>
                </div>

                <div className="p-3 rounded bg-blue-50 dark:bg-blue-900/10 border border-blue-100 dark:border-blue-900/30">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-0.5">Batch Size</label>
                  <p className="text-sm font-bold text-slate-900 dark:text-white">{recipe.batchSize} {recipe.unitName}</p>
                </div>

                <div className="p-3 rounded bg-blue-50 dark:bg-blue-900/10 border border-blue-100 dark:border-blue-900/30">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-0.5">Yield</label>
                  <p className="text-sm font-bold text-slate-900 dark:text-white">{recipe.yield || "-"}</p>
                </div>

                <div className="p-3 rounded bg-blue-50 dark:bg-blue-900/10 border border-blue-100 dark:border-blue-900/30">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-0.5">Moisture %</label>
                  <p className="text-sm font-bold text-slate-900 dark:text-white">{recipe.moisturePercentage || "-"}%</p>
                </div>

                <div className="p-3 rounded bg-blue-50 dark:bg-blue-900/10 border border-blue-100 dark:border-blue-900/30">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-0.5">Total RM Cost</label>
                  <p className="text-sm font-bold text-slate-900 dark:text-white">₹{totalRMCost.toFixed(2)}</p>
                </div>

                <div className="p-3 rounded bg-blue-50 dark:bg-blue-900/10 border border-blue-100 dark:border-blue-900/30">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-0.5">Price per Unit</label>
                  <p className="text-sm font-bold text-slate-900 dark:text-white">₹{pricePerUnit.toFixed(2)}/{recipe.unitName}</p>
                </div>
              </div>
            </div>

            {/* RM Table */}
            <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 p-5">
              <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-3">Recipe Making RM</h2>
              <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                <table className="w-full">
                  <thead className="bg-blue-50 dark:bg-blue-900/20 border-b border-blue-200 dark:border-blue-900/50">
                    <tr>
                      <th className="text-left py-2 px-4 font-semibold text-slate-700 dark:text-slate-300 text-xs uppercase tracking-wider">
                        <span className="flex items-center gap-2">
                          <span className="inline-block w-1.5 h-1.5 bg-blue-500 rounded-full"></span>
                          Raw Material
                        </span>
                      </th>
                      <th className="text-left py-2 px-4 font-semibold text-slate-700 dark:text-slate-300 text-xs uppercase tracking-wider">
                        <span className="flex items-center gap-2">
                          <span className="inline-block w-1 h-1 bg-blue-500 rounded-full"></span>
                          Qty
                        </span>
                      </th>
                      <th className="text-left py-2 px-4 font-semibold text-slate-700 dark:text-slate-300 text-xs uppercase tracking-wider">
                        <span className="flex items-center gap-2">
                          <span className="inline-block w-1 h-1 bg-blue-500 rounded-full"></span>
                          Unit
                        </span>
                      </th>
                      <th className="text-right py-2 px-4 font-semibold text-slate-700 dark:text-slate-300 text-xs uppercase tracking-wider">
                        <span className="flex items-center justify-end gap-2">
                          <span className="inline-block w-1 h-1 bg-blue-500 rounded-full"></span>
                          Unit Price
                        </span>
                      </th>
                      <th className="text-right py-2 px-4 font-semibold text-slate-700 dark:text-slate-300 text-xs uppercase tracking-wider">
                        <span className="flex items-center justify-end gap-2">
                          <span className="inline-block w-1.5 h-1.5 bg-blue-500 rounded-full"></span>
                          Total
                        </span>
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {recipe.items?.map((item) => (
                      <tr
                        key={item._id || item.rawMaterialId}
                        className="hover:bg-blue-50 dark:hover:bg-blue-900/10 transition-colors border-b border-slate-100 dark:border-slate-700/50"
                      >
                        <td className="py-2.5 px-4">
                          <p className="font-semibold text-slate-900 dark:text-white text-sm">
                            {item.rawMaterialName}
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                            {item.rawMaterialCode}
                          </p>
                        </td>
                        <td className="py-2.5 px-4 text-slate-900 dark:text-white font-semibold text-sm">
                          {item.quantity}
                        </td>
                        <td className="py-2.5 px-4 text-slate-700 dark:text-slate-300 font-medium text-sm">
                          {item.unitName || "-"}
                        </td>
                        <td className="py-2.5 px-4 text-right text-slate-900 dark:text-white font-semibold text-sm">
                          ₹{item.price.toFixed(2)}
                        </td>
                        <td className="py-2.5 px-4 text-right font-bold text-slate-900 dark:text-white text-sm">
                          ₹{item.totalPrice.toFixed(2)}
                        </td>
                      </tr>
                    ))}
                    {/* Footer row: Total Qty + Total RM Cost */}
                    <tr className="bg-slate-100 dark:bg-slate-800/50 border-t-2 border-slate-300 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors">
                      <td className="py-2.5 px-4 text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                        Total
                      </td>
                      <td className="py-2.5 px-4 font-bold text-slate-800 dark:text-slate-200 text-sm">
                        {recipe.items?.reduce((sum, item) => sum + (item.quantity || 0), 0).toFixed(3)}
                      </td>
                      <td className="py-2.5 px-4 text-slate-700 dark:text-slate-300 text-sm font-semibold">
                        {recipe.unitName || "—"}
                      </td>
                      <td className="py-2.5 px-4 text-right text-slate-400 text-xs font-medium">
                        —
                      </td>
                      <td className="py-2.5 px-4 text-right font-bold text-slate-700 dark:text-slate-300 text-sm">
                        ₹{totalRMCost.toFixed(2)}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* Summary */}
              <div className="flex justify-end gap-4 mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
                <div className="text-right px-6 py-4 rounded-xl bg-blue-100 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-700 shadow-sm hover:shadow-md hover:bg-blue-600 hover:border-blue-600 transition-all duration-200 cursor-default group min-w-[180px]">
                  <p className="text-xs font-bold text-blue-600 dark:text-blue-400 group-hover:text-blue-100 uppercase tracking-widest mb-1">
                    Price Per {recipe.unitName || "Unit"} (Yield)
                  </p>
                  <p className="text-2xl font-extrabold text-blue-800 dark:text-blue-200 group-hover:text-white leading-tight">
                    ₹{pricePerUnit.toFixed(2)}<span className="text-base font-semibold text-blue-600 dark:text-blue-400 group-hover:text-blue-200 ml-0.5">/{recipe.unitName || "unit"}</span>
                  </p>
                </div>
              </div>
            </div>

            {/* Costing Calculator Form */}
            {!isProductionUser && (
              <CostingCalculatorForm
                title="📦 Packaging & Handling Costing Calculator"
                recipeId={recipeId}
                rmCostPerKg={
                  recipe.batchSize > 0
                    ? recipe.totalRawMaterialCost / recipe.batchSize
                    : 0
                }
                productionLabourCostPerKg={productionLabourCostPerKg}
                packingLabourCostPerKg={packingLabourCostPerKg}
                batchSize={recipe.batchSize}
                yield={recipe.yield || 100}
                readOnly
              />
            )}
          </div>
        )}

        {/* TAB 2: Recipe History */}
        {activeTab === "recipe-history" && (
          <div className="space-y-6">
            {/* Comparison Controls */}
            {recipeHistory.length > 1 && (
              <div className="bg-blue-50 dark:bg-blue-900/20 border-2 border-blue-200 dark:border-blue-800 rounded-lg p-4 flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold text-blue-900 dark:text-blue-100">
                    📊 Compare Mode: {selectedEntriesForComparison.length} of 2
                    entries selected
                  </p>
                  <p className="text-xs text-blue-700 dark:text-blue-200 mt-1">
                    Click on entries to compare changes between two snapshots
                  </p>
                </div>
                <div className="flex gap-2">
                  <Button
                    onClick={() => {
                      setShowComparisonModal(true);
                    }}
                    disabled={selectedEntriesForComparison.length !== 2}
                    variant={
                      selectedEntriesForComparison.length === 2
                        ? "default"
                        : "outline"
                    }
                    size="sm"
                  >
                    Compare
                  </Button>
                  {selectedEntriesForComparison.length > 0 && (
                    <Button
                      onClick={() => setSelectedEntriesForComparison([])}
                      variant="outline"
                      size="sm"
                    >
                      Clear
                    </Button>
                  )}
                </div>
              </div>
            )}

            {recipeHistory.length === 0 ? (
              <div className="bg-card rounded-lg p-12 border text-center">
                <AlertCircle
                  size={40}
                  className="mx-auto mb-4 text-muted-foreground opacity-50"
                />
                <p className="text-muted-foreground">
                  No history found for this recipe
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {recipeHistory.map((snapshot, index) => {
                  const isLatest = index === 0;
                  const isCurrent = isLatest;
                  const nextSnapshot =
                    index < recipeHistory.length - 1
                      ? recipeHistory[index + 1]
                      : null;
                  const isSelected = selectedEntriesForComparison.find(
                    (s) => s._id === snapshot._id,
                  );

                  // Calculate what changed
                  const changedItems =
                    snapshot.items?.filter((item) => {
                      if (!nextSnapshot) return false;
                      const prevItem = nextSnapshot.items?.find(
                        (pi) => pi.rawMaterialId === item.rawMaterialId,
                      );
                      return (
                        !prevItem ||
                        prevItem.price !== item.price ||
                        prevItem.quantity !== item.quantity
                      );
                    }) || [];

                  return (
                    <button
                      key={snapshot._id}
                      onClick={() => {
                        setSelectedHistorySnapshot(snapshot);
                        setShowHistoryModal(true);
                      }}
                      className={`w-full text-left rounded-lg border-2 p-6 transition cursor-pointer hover:shadow-lg ${
                        isSelected
                          ? "border-blue-500 bg-blue-50 dark:bg-blue-900/20 shadow-lg"
                          : "border-slate-200 dark:border-slate-700 hover:border-primary hover:bg-slate-50 dark:hover:bg-slate-800/50"
                      }`}
                    >
                      <div className="flex items-start gap-4">
                        {/* Selection Checkbox */}
                        <div
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleHistorySelection(snapshot);
                          }}
                          className={`flex-shrink-0 pt-1 w-6 h-6 rounded border-2 flex items-center justify-center transition cursor-pointer ${
                            isSelected
                              ? "bg-blue-500 border-blue-500"
                              : "border-slate-300 dark:border-slate-600 hover:border-blue-400 hover:bg-slate-100 dark:hover:bg-slate-700/50"
                          }`}
                        >
                          {isSelected && (
                            <Check size={16} className="text-white" />
                          )}
                        </div>

                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            {isCurrent && (
                              <span className="px-2 py-1 bg-slate-200 dark:bg-slate-700 text-slate-900 dark:text-white text-xs font-semibold rounded">
                                Current
                              </span>
                            )}
                            <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-xs font-semibold rounded capitalize">
                              {snapshot.createdReason?.replace(/_/g, " ") ||
                                "unknown"}
                            </span>
                            {isSelected && (
                              <span className="px-2 py-1 bg-blue-500 text-white text-xs font-semibold rounded">
                                ✓ Selected
                              </span>
                            )}
                          </div>
                          <p className="text-sm font-semibold text-slate-600 dark:text-slate-400">
                            {new Date(snapshot.snapshotDate).toLocaleString(
                              "en-IN",
                            )}
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-500 mt-1">
                            Changed by: {snapshot.changedBy}
                          </p>
                          {changedItems.length > 0 && (
                            <p className="text-xs text-slate-600 dark:text-slate-400 mt-2">
                              📊 {changedItems.length} item(s) changed
                            </p>
                          )}
                        </div>
                        <div className="text-right flex-shrink-0">
                          <p className="text-xs text-slate-600 dark:text-slate-400">
                            Total RM Cost
                          </p>
                          <p className="text-lg font-bold text-slate-900 dark:text-white">
                            ₹{snapshot.totalRawMaterialCost.toFixed(2)}
                          </p>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* TAB 3: Quotation History */}
        {activeTab === "quotation-history" && (
          <div className="space-y-6">
            {/* Add Quotation Button */}
            <div className="flex justify-between items-center">
              <h2 className="text-xl font-semibold">Quotation History</h2>
              <Button
                onClick={() => setShowQuotationForm(!showQuotationForm)}
                size="sm"
              >
                <Plus size={16} className="mr-2" />
                {showQuotationForm ? "Cancel" : "Add Quotation"}
              </Button>
            </div>

            {/* Quotation Form */}
            {showQuotationForm && (
              <div className="bg-card rounded-lg p-6 border">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium">
                      Company Name *
                    </label>
                    <input
                      type="text"
                      value={quotationForm.companyName}
                      onChange={(e) =>
                        setQuotationForm({
                          ...quotationForm,
                          companyName: e.target.value,
                        })
                      }
                      className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                      placeholder="Enter company name"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Reason *</label>
                    <input
                      type="text"
                      value={quotationForm.reason}
                      onChange={(e) =>
                        setQuotationForm({
                          ...quotationForm,
                          reason: e.target.value,
                        })
                      }
                      className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                      placeholder="Enter reason"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Quantity *</label>
                    <input
                      type="number"
                      value={quotationForm.quantity}
                      onChange={(e) => {
                        const qty = e.target.value;
                        setQuotationForm({
                          ...quotationForm,
                          quantity: qty,
                        });
                        // Trigger calculation
                        if (qty && parseFloat(qty) > 0) {
                          handleCalculateQuotation(parseFloat(qty));
                        } else {
                          setQuotationCalculatedItems([]);
                          setQuotationSummary({
                            totalRecipeCost: 0,
                            perUnitCost: 0,
                            scalingFactor: 0,
                          });
                        }
                      }}
                      className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                      placeholder="Enter quantity"
                      min="0"
                      step="0.01"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Unit *</label>
                    <select
                      value={quotationForm.unitId}
                      onChange={(e) =>
                        setQuotationForm({
                          ...quotationForm,
                          unitId: e.target.value,
                        })
                      }
                      className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                    >
                      <option value="">-- Select a unit --</option>
                      {units.map((unit) => (
                        <option key={unit._id} value={unit._id}>
                          {unit.name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-sm font-medium">Date *</label>
                    <input
                      type="date"
                      value={quotationForm.date}
                      onChange={(e) =>
                        setQuotationForm({
                          ...quotationForm,
                          date: e.target.value,
                        })
                      }
                      className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">
                      Phone Number *
                    </label>
                    <input
                      type="tel"
                      value={quotationForm.phoneNumber}
                      onChange={(e) =>
                        setQuotationForm({
                          ...quotationForm,
                          phoneNumber: e.target.value,
                        })
                      }
                      className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                      placeholder="Enter phone number"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Email *</label>
                    <input
                      type="email"
                      value={quotationForm.email}
                      onChange={(e) =>
                        setQuotationForm({
                          ...quotationForm,
                          email: e.target.value,
                        })
                      }
                      className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                      placeholder="Enter email"
                    />
                  </div>
                </div>

                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-4">
                  <p className="text-sm text-blue-800 dark:text-blue-300">
                    💡 <strong>Tip:</strong> Enter the required quantity above
                    to automatically calculate raw material requirements based
                    on your master recipe.
                  </p>
                </div>

                {quotationCalculatedItems.length === 0 && (
                  <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4 mb-4">
                    <p className="text-sm text-amber-800 dark:text-amber-300">
                      ⚠️ Please enter a valid quantity to see calculated
                      requirements
                    </p>
                  </div>
                )}

                <div className="flex gap-2 mt-4">
                  <Button
                    onClick={handleAddQuotation}
                    variant="default"
                    size="sm"
                    disabled={
                      quotationCalculatedItems.length === 0 || quotationCreating
                    }
                  >
                    {quotationCreating ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                        Creating...
                      </>
                    ) : (
                      "Create Quotation"
                    )}
                  </Button>
                  <Button
                    onClick={() => {
                      setShowQuotationForm(false);
                      setQuotationCalculatedItems([]);
                      setQuotationSummary({
                        totalRecipeCost: 0,
                        perUnitCost: 0,
                        scalingFactor: 0,
                      });
                    }}
                    variant="outline"
                    size="sm"
                    disabled={quotationCreating}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            )}

            {/* RM Table for Quotation */}
            {showQuotationForm && quotationCalculatedItems.length > 0 && (
              <div className="bg-card rounded-lg p-6 border">
                <h3 className="text-lg font-semibold mb-4">
                  Calculated Recipe Materials
                  <span className="text-sm text-slate-600 dark:text-slate-400 ml-2">
                    (Scaling Factor: {quotationSummary.scalingFactor.toFixed(2)}
                    x)
                  </span>
                </h3>
                <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                  <table className="w-full">
                    <thead className="bg-slate-100 dark:bg-slate-700 border-b border-slate-200 dark:border-slate-600">
                      <tr>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Raw Material
                        </th>
                        <th className="text-center py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Master Qty
                        </th>
                        <th className="text-center py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Calculated Qty
                        </th>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Unit
                        </th>
                        <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Unit Price
                        </th>
                        <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Total Cost
                        </th>
                        <th className="text-center py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                      {quotationCalculatedItems.map((calcItem) => {
                        const override =
                          quotationItemOverrides[calcItem.rawMaterialId];
                        const displayPrice =
                          override?.price ?? calcItem.unitPrice;
                        const displayTotal =
                          calcItem.calculatedQty * displayPrice;
                        const originalItem = recipe.items?.find(
                          (i) => i.rawMaterialId === calcItem.rawMaterialId,
                        );

                        return (
                          <tr
                            key={calcItem.rawMaterialId}
                            className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                          >
                            <td className="py-4 px-4">
                              <p className="font-medium text-slate-900 dark:text-white">
                                {calcItem.rawMaterialName}
                              </p>
                              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                                {calcItem.rawMaterialCode}
                              </p>
                              {override && (
                                <p className="text-xs text-blue-600 dark:text-blue-400 mt-1">
                                  ✓ Vendor changed
                                </p>
                              )}
                            </td>
                            <td className="py-4 px-4 text-center text-slate-700 dark:text-slate-300 font-medium">
                              {calcItem.masterQty} {calcItem.unitName}
                            </td>
                            <td className="py-4 px-4 text-center">
                              <p className="text-slate-900 dark:text-white font-bold text-lg">
                                {calcItem.calculatedQty.toFixed(2)}
                              </p>
                              <p className="text-xs text-slate-600 dark:text-slate-400">
                                {calcItem.unitName}
                              </p>
                            </td>
                            <td className="py-4 px-4 text-slate-700 dark:text-slate-300">
                              {calcItem.unitName || "-"}
                            </td>
                            <td className="py-4 px-4 text-right text-slate-900 dark:text-white font-medium">
                              ₹{displayPrice.toFixed(2)}
                              {override && (
                                <p className="text-xs text-slate-600 dark:text-slate-400 line-through">
                                  ₹{calcItem.unitPrice.toFixed(2)}
                                </p>
                              )}
                            </td>
                            <td className="py-4 px-4 text-right font-semibold text-teal-600 dark:text-teal-400 text-lg">
                              ₹{displayTotal.toFixed(2)}
                            </td>
                            <td className="py-4 px-4 text-center">
                              <Button
                                onClick={() => {
                                  if (originalItem) {
                                    setSelectedItemForVendor(originalItem);
                                    setShowChangeVendorModal(true);
                                    fetchVendorPricesForRawMaterial(
                                      calcItem.rawMaterialId,
                                    );
                                  }
                                }}
                                variant="outline"
                                size="sm"
                              >
                                Change Vendor
                              </Button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Cost Summary */}
                <div className="flex justify-end gap-8 mt-6 pt-6 border-t border-slate-200 dark:border-slate-700">
                  <div className="text-right">
                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">
                      Total Recipe Cost
                    </p>
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                      ₹{quotationSummary.totalRecipeCost.toFixed(2)}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">
                      Per Unit Cost
                    </p>
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                      ₹{quotationSummary.perUnitCost.toFixed(2)}/
                      {recipe.unitName}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Labour Costing Sections in Quotation */}
            {showQuotationForm && (
              <div className="space-y-6">
                {/* Costing Calculator Form */}
                <CostingCalculatorForm
                  title="📦 Packaging & Handling Costing Calculator"
                  recipeId={recipeId}
                  rmCostPerKg={
                    recipe.batchSize > 0
                      ? recipe.totalRawMaterialCost / recipe.batchSize
                      : 0
                  }
                  productionLabourCostPerKg={productionLabourCostPerKg}
                  packingLabourCostPerKg={packingLabourCostPerKg}
                  batchSize={recipe.batchSize}
                  yield={recipe.yield || 100}
                  onSave={() => {
                    // Refresh cost breakdown when packaging costs are saved
                    fetchAllData();
                  }}
                />
              </div>
            )}

            {/* Quotation History Table */}
            <div className="bg-card rounded-lg p-6 border">
              {quotations.length === 0 ? (
                <p className="text-muted-foreground">No quotations found</p>
              ) : (
                <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                  <table className="w-full">
                    <thead className="bg-slate-100 dark:bg-slate-700 border-b border-slate-200 dark:border-slate-600">
                      <tr>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Company Name
                        </th>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Recipe Name
                        </th>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Qty
                        </th>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Unit
                        </th>
                        <th className="text-center py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Yield %
                        </th>
                        <th className="text-center py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Moisture %
                        </th>
                        <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          RM Cost
                        </th>
                        <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Packaging Cost
                        </th>
                        <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Labour Cost
                        </th>
                        <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Total Cost
                        </th>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Date
                        </th>
                        <th className="text-center py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                      {quotations.map((q) => {
                        // Calculate costs based on quantity
                        const rmCost = q.totalRecipeCost || 0;
                        const labourCostPerUnit =
                          productionLabourCostPerKg * q.quantity;

                        // Use actual packaging cost per Kg from recipe
                        const packagingCostPerUnit =
                          packagingCostPerKg * q.quantity;

                        const totalCost =
                          rmCost + labourCostPerUnit + packagingCostPerUnit;

                        return (
                          <tr
                            key={q._id}
                            onClick={() => navigate(`/quotation/${q._id}`)}
                            className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer"
                          >
                            <td className="py-4 px-4 font-medium text-slate-900 dark:text-white">
                              {q.companyName}
                            </td>
                            <td className="py-4 px-4 text-slate-700 dark:text-slate-300">
                              {recipe.name}
                            </td>
                            <td className="py-4 px-4 text-slate-700 dark:text-slate-300 font-medium">
                              {q.quantity}
                            </td>
                            <td className="py-4 px-4 text-slate-700 dark:text-slate-300">
                              {recipe.unitName}
                            </td>
                            <td className="py-4 px-4 text-center font-semibold text-slate-900 dark:text-white">
                              {(recipe.yield || 100).toFixed(2)}%
                            </td>
                            <td className="py-4 px-4 text-center font-semibold text-slate-900 dark:text-white">
                              {(recipe.moisturePercentage || 0).toFixed(2)}%
                            </td>
                            <td className="py-4 px-4 text-right font-semibold text-blue-600 dark:text-blue-400">
                              ₹{rmCost.toFixed(2)}
                            </td>
                            <td className="py-4 px-4 text-right font-semibold text-orange-600 dark:text-orange-400">
                              ₹{packagingCostPerUnit.toFixed(2)}
                            </td>
                            <td className="py-4 px-4 text-right font-semibold text-purple-600 dark:text-purple-400">
                              ₹{labourCostPerUnit.toFixed(2)}
                            </td>
                            <td className="py-4 px-4 text-right font-semibold text-teal-600 dark:text-teal-400">
                              ₹{totalCost.toFixed(2)}
                            </td>
                            <td className="py-4 px-4 text-slate-700 dark:text-slate-300 text-sm">
                              {new Date(q.date).toLocaleDateString("en-GB")}
                            </td>
                            <td className="py-4 px-4">
                              <div className="flex gap-2 justify-center">
                                <Button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    navigate(`/quotation/${q._id}`);
                                  }}
                                  variant="outline"
                                  size="sm"
                                  title="View quotation details"
                                >
                                  <FileText size={16} className="mr-2" />
                                  PDF
                                </Button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </ProfessionalPage>

      {/* Logs Modal - Full Screen */}
      {showLogsModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-800 rounded-3xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden border border-slate-200/50 dark:border-slate-700/50 flex flex-col animate-scale-in">
            {/* Header */}
            <div className="sticky top-0 p-6 border-b border-slate-200 dark:border-slate-700 bg-gradient-to-r from-blue-50 to-slate-50 dark:from-slate-800 dark:to-slate-800 flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-slate-900 dark:text-white">
                  Recipe Logs
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                  {logs.length} {logs.length === 1 ? "log entry" : "log entries"}
                </p>
              </div>
              <button
                onClick={() => setShowLogsModal(false)}
                className="p-2 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-all"
                title="Close"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Content */}
            <div className="overflow-y-auto flex-1 p-6">
              {logs.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <svg className="w-12 h-12 text-slate-300 dark:text-slate-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="text-slate-500 dark:text-slate-400 text-center">No logs found for this recipe</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {logs.map((log, idx) => {
                    const formatValue = (val: any) => {
                      if (val === null || val === undefined) return "-";
                      if (typeof val === "object") return JSON.stringify(val);
                      return String(val);
                    };

                    return (
                      <div key={log._id} className="p-4 border border-slate-200 dark:border-slate-700 rounded-xl bg-white dark:bg-slate-800/50 hover:shadow-md transition-shadow">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1">
                            <p className="font-semibold text-slate-900 dark:text-white text-sm uppercase tracking-wide text-blue-600 dark:text-blue-400">
                              {log.fieldChanged}
                            </p>
                          </div>
                          <span className="text-xs font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 px-2 py-1 rounded-full">
                            #{idx + 1}
                          </span>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-3">
                          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                            <p className="text-xs font-semibold text-red-700 dark:text-red-400 mb-1">OLD VALUE</p>
                            <p className="text-sm font-mono text-slate-900 dark:text-white break-words">
                              {formatValue(log.oldValue)}
                            </p>
                          </div>
                          <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
                            <p className="text-xs font-semibold text-green-700 dark:text-green-400 mb-1">NEW VALUE</p>
                            <p className="text-sm font-mono text-slate-900 dark:text-white break-words">
                              {formatValue(log.newValue)}
                            </p>
                          </div>
                        </div>

                        <p className="text-xs text-slate-600 dark:text-slate-400">
                          <span className="font-semibold">Changed:</span> {new Date(log.changeDate).toLocaleString()}
                          {" "}<span className="font-semibold">by</span> {log.changedBy}
                        </p>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Delete Modal */}
      {showDeleteModal && (
        <Modal onClose={() => setShowDeleteModal(false)}>
          <div className="bg-card rounded-lg p-6 max-w-sm">
            <h2 className="text-xl font-semibold mb-4">Delete Recipe</h2>
            <p className="text-muted-foreground mb-4">
              This action cannot be undone. Please enter your password to
              confirm.
            </p>
            <input
              type="password"
              value={deletePassword}
              onChange={(e) => {
                setDeletePassword(e.target.value);
                setDeleteError("");
              }}
              placeholder="Enter password"
              className="w-full px-3 py-2 border rounded-md bg-input mb-2"
            />
            {deleteError && (
              <p className="text-destructive text-sm mb-4">{deleteError}</p>
            )}
            <div className="flex gap-2">
              <Button
                onClick={handleDeleteRecipe}
                variant="destructive"
                className="flex-1"
              >
                Delete
              </Button>
              <Button
                onClick={() => {
                  setShowDeleteModal(false);
                  setDeletePassword("");
                  setDeleteError("");
                }}
                variant="outline"
                className="flex-1"
              >
                Cancel
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Change Vendor Modal */}
      {showChangeVendorModal && selectedItemForVendor && (
        <Modal
          onClose={() => {
            setShowChangeVendorModal(false);
            setSelectedVendorId("");
          }}
        >
          <div className="bg-card rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto border border-slate-200 dark:border-slate-700">
            {/* Header */}
            <div className="p-6 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between sticky top-0 bg-card">
              <div>
                <h2 className="text-2xl font-bold">
                  Change Vendor - {selectedItemForVendor.rawMaterialName}
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                  Code: {selectedItemForVendor.rawMaterialCode}
                </p>
              </div>
              <button
                onClick={() => {
                  setShowChangeVendorModal(false);
                  setSelectedVendorId("");
                }}
                className="text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Current Item Information */}
              <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-6 border border-blue-200 dark:border-blue-800">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
                  Current Information
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mb-2">
                      Quantity
                    </p>
                    <p className="font-bold text-slate-900 dark:text-white text-lg">
                      {selectedItemForVendor.quantity}{" "}
                      <span className="text-sm">
                        {selectedItemForVendor.unitName}
                      </span>
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mb-2">
                      Current Price
                    </p>
                    <p className="font-bold text-blue-600 dark:text-blue-400 text-lg">
                      ₹{selectedItemForVendor.price.toFixed(2)}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mb-2">
                      Total Cost
                    </p>
                    <p className="font-bold text-slate-900 dark:text-white text-lg">
                      ₹{selectedItemForVendor.totalPrice.toFixed(2)}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mb-2">
                      Current Vendor
                    </p>
                    <p className="font-bold text-slate-900 dark:text-white text-lg">
                      {selectedItemForVendor.vendorName || "-"}
                    </p>
                  </div>
                </div>
              </div>

              {/* Vendor Selection */}
              {vendorPrices.length === 0 ? (
                <div className="text-center py-12 text-slate-500 dark:text-slate-400">
                  <AlertCircle size={40} className="mx-auto mb-4 opacity-50" />
                  <p className="text-lg font-medium">No vendor history found</p>
                  <p className="text-sm mt-2">
                    This raw material has not been purchased from any vendor
                    yet.
                  </p>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-3">
                      Select New Vendor *
                    </label>
                    <select
                      value={selectedVendorId}
                      onChange={(e) => setSelectedVendorId(e.target.value)}
                      className="w-full px-4 py-3 border-2 border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-800 text-slate-900 dark:text-white font-medium focus:outline-none focus:border-teal-500 focus:ring-2 focus:ring-teal-200 dark:focus:ring-teal-900"
                    >
                      <option value="">-- Select a vendor --</option>
                      {vendorPrices
                        .reduce(
                          (
                            seen: { vendorId: string; vendorName: string }[],
                            vp,
                          ) => {
                            const exists = seen.some(
                              (v) => v.vendorId === vp.vendorId,
                            );
                            if (!exists) {
                              // Get vendor name from vendorPrices or fallback to vendors array
                              let vendorName = vp.vendorName;
                              if (!vendorName) {
                                const vendorData = vendors.find(
                                  (v) => v._id === vp.vendorId,
                                );
                                vendorName =
                                  vendorData?.name || "Unknown Vendor";
                              }
                              seen.push({ vendorId: vp.vendorId, vendorName });
                            }
                            return seen;
                          },
                          [],
                        )
                        .map((uniqueVendor) => {
                          const isCurrentVendor =
                            selectedItemForVendor.vendorId ===
                            uniqueVendor.vendorId;
                          return (
                            <option
                              key={uniqueVendor.vendorId}
                              value={uniqueVendor.vendorId}
                            >
                              {uniqueVendor.vendorName || "Unknown"}
                              {isCurrentVendor ? " (Current)" : ""}
                            </option>
                          );
                        })}
                    </select>
                  </div>

                  {/* Selected Vendor Details */}
                  {selectedVendorId && (
                    <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-6 border border-green-200 dark:border-green-800">
                      <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
                        Vendor Details
                      </h3>
                      {vendorPrices
                        .filter((vp) => vp.vendorId === selectedVendorId)
                        .map((vendorPrice) => {
                          const vendorDetails = vendors.find(
                            (v) => v._id === vendorPrice.vendorId,
                          );
                          return (
                            <div key={vendorPrice._id} className="space-y-4">
                              <div className="bg-white dark:bg-slate-800 rounded-lg p-4 border-2 border-blue-300 dark:border-blue-700 mb-4">
                                <p className="text-xs text-green-700 dark:text-green-400 font-bold mb-2 uppercase tracking-wide">
                                  Selected Vendor
                                </p>
                                <p className="text-2xl font-bold text-slate-900 dark:text-white">
                                  {vendorPrice.vendorName ||
                                    vendorDetails?.name ||
                                    "Unknown Vendor"}
                                </p>
                              </div>

                              {vendorDetails ? (
                                <div>
                                  <p className="text-xs text-green-700 dark:text-green-400 font-bold mb-3 uppercase tracking-wide">
                                    Contact Information
                                  </p>
                                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                                    {vendorDetails.contactPerson && (
                                      <div className="bg-white dark:bg-slate-800 rounded p-3 border border-slate-200 dark:border-slate-700">
                                        <p className="text-xs text-slate-600 dark:text-slate-400 mb-2 font-semibold">
                                          Contact Person
                                        </p>
                                        <p className="font-medium text-slate-900 dark:text-white">
                                          {vendorDetails.contactPerson}
                                        </p>
                                      </div>
                                    )}
                                    {vendorDetails.email && (
                                      <div className="bg-white dark:bg-slate-800 rounded p-3 border border-slate-200 dark:border-slate-700">
                                        <p className="text-xs text-slate-600 dark:text-slate-400 mb-2 font-semibold">
                                          Email
                                        </p>
                                        <p className="font-medium text-slate-900 dark:text-white break-all text-sm">
                                          {vendorDetails.email}
                                        </p>
                                      </div>
                                    )}
                                    {vendorDetails.phone && (
                                      <div className="bg-white dark:bg-slate-800 rounded p-3 border border-slate-200 dark:border-slate-700">
                                        <p className="text-xs text-slate-600 dark:text-slate-400 mb-2 font-semibold">
                                          Phone
                                        </p>
                                        <p className="font-medium text-slate-900 dark:text-white">
                                          {vendorDetails.phone}
                                        </p>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              ) : (
                                <div className="bg-slate-50 dark:bg-slate-800 rounded p-3 border border-slate-200 dark:border-slate-700">
                                  <p className="text-xs text-slate-600 dark:text-slate-400">
                                    No additional vendor details available
                                  </p>
                                </div>
                              )}

                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-4 border-t border-green-200 dark:border-green-800">
                                <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4 border border-blue-200 dark:border-blue-800">
                                  <p className="text-xs text-blue-700 dark:text-blue-400 font-bold mb-2 uppercase tracking-wide">
                                    Unit Price
                                  </p>
                                  <p className="text-2xl font-bold text-teal-600 dark:text-teal-400">
                                    ₹{vendorPrice.price.toFixed(2)}
                                  </p>
                                  {vendorPrice.lastPurchaseDate && (
                                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-2">
                                      Last bought:{" "}
                                      {new Date(
                                        vendorPrice.lastPurchaseDate,
                                      ).toLocaleDateString("en-GB")}
                                    </p>
                                  )}
                                </div>

                                <div className="bg-green-100 dark:bg-green-900/30 rounded-lg p-4 border-2 border-green-300 dark:border-green-700">
                                  <p className="text-xs text-green-700 dark:text-green-400 font-bold mb-2 uppercase tracking-wide">
                                    New Total Cost
                                  </p>
                                  <p className="text-3xl font-bold text-green-600 dark:text-green-400">
                                    ₹
                                    {(
                                      vendorPrice.price *
                                      selectedItemForVendor.quantity
                                    ).toFixed(2)}
                                  </p>
                                  <p className="text-xs text-green-700 dark:text-green-400 mt-2">
                                    {vendorPrice.price.toFixed(2)} ×{" "}
                                    {selectedItemForVendor.quantity}{" "}
                                    {selectedItemForVendor.unitName}
                                  </p>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="flex gap-3 pt-4">
                    <Button
                      onClick={() => {
                        const selectedVendor = vendorPrices.find(
                          (vp) => vp.vendorId === selectedVendorId,
                        );
                        if (selectedVendor) {
                          handleChangeVendor(
                            selectedVendorId,
                            selectedVendor.price,
                          );
                        }
                      }}
                      disabled={!selectedVendorId}
                      variant="default"
                      className="flex-1"
                    >
                      <Check size={16} className="mr-2" />
                      Submit Change
                    </Button>
                    <Button
                      onClick={() => {
                        setShowChangeVendorModal(false);
                        setSelectedVendorId("");
                      }}
                      variant="outline"
                      className="flex-1"
                    >
                      <X size={16} className="mr-2" />
                      Cancel
                    </Button>
                  </div>
                </>
              )}
            </div>
          </div>
        </Modal>
      )}

      {/* Recipe History Details Modal */}
      {showHistoryModal && selectedHistorySnapshot && (
        <Modal
          onClose={() => {
            setShowHistoryModal(false);
            setSelectedHistorySnapshot(null);
          }}
        >
          <div className="bg-card rounded-lg w-full max-w-5xl max-h-[95vh] overflow-y-auto border border-slate-200 dark:border-slate-700">
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between sticky top-0 bg-card z-10">
              <div>
                <h2 className="text-2xl font-bold">Recipe History Snapshot</h2>
                <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                  {new Date(
                    selectedHistorySnapshot.snapshotDate,
                  ).toLocaleString("en-IN")}{" "}
                  • Changed by: {selectedHistorySnapshot.changedBy}
                </p>
              </div>
              <button
                onClick={() => {
                  setShowHistoryModal(false);
                  setSelectedHistorySnapshot(null);
                }}
                className="text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition-colors flex-shrink-0"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">
              {/* Change Summary */}
              {(() => {
                const currentIndex = recipeHistory.findIndex(
                  (h) => h._id === selectedHistorySnapshot._id,
                );
                const prevSnapshot =
                  currentIndex > 0 ? recipeHistory[currentIndex + 1] : null;

                const changes: {
                  rawMaterialName: string;
                  field: string;
                  oldValue: any;
                  newValue: any;
                }[] = [];

                if (prevSnapshot) {
                  selectedHistorySnapshot.items?.forEach((item: any) => {
                    const prevItem = prevSnapshot.items?.find(
                      (pi: any) => pi.rawMaterialId === item.rawMaterialId,
                    );
                    if (prevItem) {
                      if (prevItem.price !== item.price) {
                        changes.push({
                          rawMaterialName: item.rawMaterialName,
                          field: "Price",
                          oldValue: `₹${prevItem.price.toFixed(2)}`,
                          newValue: `₹${item.price.toFixed(2)}`,
                        });
                      }
                      if (prevItem.quantity !== item.quantity) {
                        changes.push({
                          rawMaterialName: item.rawMaterialName,
                          field: "Quantity",
                          oldValue: prevItem.quantity,
                          newValue: item.quantity,
                        });
                      }
                      if (prevItem.vendorName !== item.vendorName) {
                        changes.push({
                          rawMaterialName: item.rawMaterialName,
                          field: "Vendor",
                          oldValue: prevItem.vendorName || "-",
                          newValue: item.vendorName || "-",
                        });
                      }
                    }
                  });
                }

                return changes.length > 0 ? (
                  <div className="bg-amber-50 dark:bg-amber-900/20 border-2 border-amber-200 dark:border-amber-800 rounded-lg p-6">
                    <h3 className="text-lg font-semibold mb-4 text-amber-900 dark:text-amber-100">
                      🔄 What Changed in this Snapshot
                    </h3>
                    <div className="space-y-3">
                      {changes.map((change, idx) => (
                        <div
                          key={idx}
                          className="bg-white dark:bg-slate-800/50 rounded p-4 border-l-4 border-l-blue-300 dark:border-l-blue-700"
                        >
                          <p className="font-bold text-slate-900 dark:text-white">
                            {change.rawMaterialName}
                          </p>
                          <p className="text-sm text-slate-700 dark:text-slate-300 mt-2">
                            <span className="font-semibold">
                              {change.field}:
                            </span>
                            <br />
                            <span className="line-through text-slate-500">
                              Old: {change.oldValue}
                            </span>
                            <br />
                            <span className="text-slate-900 dark:text-white font-bold">
                              New: {change.newValue}
                            </span>
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="bg-blue-50 dark:bg-blue-900/20 border-2 border-blue-200 dark:border-blue-800 rounded-lg p-6">
                    <p className="text-blue-800 dark:text-blue-200">
                      ℹ️ No changes found (initial creation or unchanged items)
                    </p>
                  </div>
                );
              })()}

              {/* Snapshot Info */}
              <div className="bg-gradient-to-r from-blue-50 to-cyan-50 dark:from-blue-900/20 dark:to-cyan-900/20 rounded-lg p-6 border-2 border-blue-200 dark:border-blue-800">
                <h3 className="text-lg font-semibold mb-4 text-blue-900 dark:text-blue-100">
                  Snapshot Information
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-xs text-blue-600 dark:text-blue-400 font-semibold">
                      Date & Time
                    </p>
                    <p className="font-bold text-blue-900 dark:text-blue-100">
                      {new Date(
                        selectedHistorySnapshot.snapshotDate,
                      ).toLocaleString("en-IN")}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-blue-600 dark:text-blue-400 font-semibold">
                      Reason
                    </p>
                    <p className="font-bold text-blue-900 dark:text-blue-100 capitalize">
                      {selectedHistorySnapshot.createdReason?.replace(
                        /_/g,
                        " ",
                      ) || "Unknown"}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-blue-600 dark:text-blue-400 font-semibold">
                      Changed By
                    </p>
                    <p className="font-bold text-blue-900 dark:text-blue-100">
                      {selectedHistorySnapshot.changedBy}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-blue-600 dark:text-blue-400 font-semibold">
                      Total RM Cost
                    </p>
                    <p className="font-bold text-blue-600 dark:text-blue-400 text-lg">
                      ₹{selectedHistorySnapshot.totalRawMaterialCost.toFixed(2)}
                    </p>
                  </div>
                </div>
              </div>

              {/* Raw Materials Table with Highlighting */}
              <div className="bg-card rounded-lg p-6 border">
                <h3 className="text-lg font-bold mb-4">
                  Complete Recipe - All Raw Materials
                </h3>
                <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                  <table className="w-full">
                    <thead className="bg-slate-100 dark:bg-slate-700 border-b border-slate-200 dark:border-slate-600">
                      <tr>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Raw Material
                        </th>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Qty
                        </th>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Unit
                        </th>
                        <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Unit Price
                        </th>
                        <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Total
                        </th>
                        <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">
                          Vendor
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                      {selectedHistorySnapshot.items?.map((item) => {
                        const currentIndex = recipeHistory.findIndex(
                          (h) => h._id === selectedHistorySnapshot._id,
                        );
                        const prevSnapshot =
                          currentIndex > 0
                            ? recipeHistory[currentIndex + 1]
                            : null;
                        const prevItem = prevSnapshot?.items?.find(
                          (pi: any) => pi.rawMaterialId === item.rawMaterialId,
                        );
                        const itemChanged =
                          prevItem &&
                          (prevItem.price !== item.price ||
                            prevItem.quantity !== item.quantity ||
                            prevItem.vendorName !== item.vendorName);

                        return (
                          <tr
                            key={item._id || item.rawMaterialId}
                            className={`transition-colors ${
                              itemChanged
                                ? "bg-amber-50 dark:bg-amber-900/20 border-l-4 border-l-amber-500 font-semibold"
                                : "hover:bg-slate-50 dark:hover:bg-slate-800/50"
                            }`}
                          >
                            <td className="py-4 px-4">
                              <p className="font-medium text-slate-900 dark:text-white">
                                {item.rawMaterialName}
                                {itemChanged && (
                                  <span className="ml-2 text-xs text-amber-600 dark:text-amber-400 font-bold bg-amber-100 dark:bg-amber-900/50 px-2 py-1 rounded">
                                    📝 CHANGED
                                  </span>
                                )}
                              </p>
                              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                                {item.rawMaterialCode}
                              </p>
                            </td>
                            <td className="py-4 px-4 text-slate-700 dark:text-slate-300 font-medium">
                              {item.quantity}
                            </td>
                            <td className="py-4 px-4 text-slate-700 dark:text-slate-300">
                              {item.unitName || "-"}
                            </td>
                            <td className="py-4 px-4 text-right text-slate-900 dark:text-white font-medium">
                              ₹{item.price.toFixed(2)}
                            </td>
                            <td className="py-4 px-4 text-right font-semibold text-teal-600 dark:text-teal-400">
                              ₹{item.totalPrice.toFixed(2)}
                            </td>
                            <td className="py-4 px-4 text-slate-700 dark:text-slate-300 text-sm">
                              {item.vendorName || "-"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Summary */}
                <div className="flex justify-end gap-8 mt-6 pt-6 border-t border-slate-200 dark:border-slate-700">
                  <div className="text-right">
                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">
                      Total RM Cost
                    </p>
                    <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                      ₹{selectedHistorySnapshot.totalRawMaterialCost.toFixed(2)}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">
                      Per Unit Price
                    </p>
                    <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                      ₹{selectedHistorySnapshot.pricePerUnit.toFixed(2)}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Modal>
      )}

      {/* Delete Quotation Modal */}
      {showDeleteQuotationModal && (
        <Modal onClose={() => setShowDeleteQuotationModal(false)}>
          <div className="bg-card rounded-lg p-6 max-w-sm">
            <h2 className="text-xl font-semibold mb-4">Delete Quotation</h2>
            <p className="text-muted-foreground mb-4">
              Are you sure you want to delete this quotation? This action cannot
              be undone.
            </p>
            <div className="flex gap-2">
              <Button
                onClick={handleDeleteQuotation}
                variant="destructive"
                className="flex-1"
              >
                Delete
              </Button>
              <Button
                onClick={() => {
                  setShowDeleteQuotationModal(false);
                  setQuotationToDelete(null);
                }}
                variant="outline"
                className="flex-1"
              >
                Cancel
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Recipe History Comparison Modal */}
      {showComparisonModal && selectedEntriesForComparison.length === 2 && (
        <Modal onClose={() => setShowComparisonModal(false)}>
          <div className="bg-card rounded-lg w-full max-w-6xl max-h-[95vh] overflow-y-auto border border-slate-200 dark:border-slate-700">
            {/* Header */}
            <div className="p-6 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between sticky top-0 bg-card z-10">
              <div>
                <h2 className="text-2xl font-bold">
                  📊 Recipe History Comparison
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                  Comparing changes between two snapshots
                </p>
              </div>
              <button
                onClick={() => setShowComparisonModal(false)}
                className="text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition-colors flex-shrink-0"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Content */}
            <div className="p-6 space-y-6">
              {(() => {
                const [first, second] = selectedEntriesForComparison;
                const changes = getComparisonChanges();
                const changesByRawMaterial: Record<string, any[]> = {};

                changes.forEach((change) => {
                  const key = change.rawMaterialName;
                  if (!changesByRawMaterial[key]) {
                    changesByRawMaterial[key] = [];
                  }
                  changesByRawMaterial[key].push(change);
                });

                return (
                  <>
                    {/* Comparison Headers */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className="bg-amber-50 dark:bg-amber-900/20 border-2 border-amber-200 dark:border-amber-800 rounded-lg p-6">
                        <h3 className="text-lg font-bold text-amber-900 dark:text-amber-100 mb-2">
                          OLDER VERSION
                        </h3>
                        <div className="space-y-2">
                          <p className="text-sm text-amber-800 dark:text-amber-200">
                            <span className="font-semibold">Date:</span>
                            <br />
                            {new Date(second.snapshotDate).toLocaleString(
                              "en-IN",
                            )}
                          </p>
                          <p className="text-sm text-amber-800 dark:text-amber-200">
                            <span className="font-semibold">Changed by:</span>{" "}
                            {second.changedBy}
                          </p>
                          <p className="text-sm text-amber-800 dark:text-amber-200">
                            <span className="font-semibold">Total Cost:</span>
                            <br />
                            <span className="text-lg font-bold text-amber-600 dark:text-amber-400">
                              ₹{second.totalRawMaterialCost.toFixed(2)}
                            </span>
                          </p>
                        </div>
                      </div>

                      <div className="bg-blue-50 dark:bg-blue-900/10 border-2 border-blue-200 dark:border-blue-700 rounded-lg p-6">
                        <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">
                          NEWER VERSION
                        </h3>
                        <div className="space-y-2">
                          <p className="text-sm text-slate-700 dark:text-slate-300">
                            <span className="font-semibold">Date:</span>
                            <br />
                            {new Date(first.snapshotDate).toLocaleString(
                              "en-IN",
                            )}
                          </p>
                          <p className="text-sm text-slate-700 dark:text-slate-300">
                            <span className="font-semibold">Changed by:</span>{" "}
                            {first.changedBy}
                          </p>
                          <p className="text-sm text-slate-700 dark:text-slate-300">
                            <span className="font-semibold">Total Cost:</span>
                            <br />
                            <span className="text-lg font-bold text-slate-900 dark:text-white">
                              ₹{first.totalRawMaterialCost.toFixed(2)}
                            </span>
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Change Summary */}
                    <div className="bg-blue-50 dark:bg-blue-900/20 border-2 border-blue-200 dark:border-blue-800 rounded-lg p-6">
                      <h3 className="text-lg font-bold text-blue-900 dark:text-blue-100 mb-4">
                        📋 Summary: {changes.length} Change
                        {changes.length !== 1 ? "s" : ""} Found
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="text-sm">
                          <span className="text-blue-700 dark:text-blue-300 font-semibold">
                            Cost Difference:
                          </span>
                          <span
                            className={`ml-2 font-bold text-lg text-slate-900 dark:text-white`}
                          >
                            {first.totalRawMaterialCost >
                            second.totalRawMaterialCost
                              ? "+"
                              : ""}
                            ₹
                            {(
                              first.totalRawMaterialCost -
                              second.totalRawMaterialCost
                            ).toFixed(2)}
                          </span>
                        </div>
                        <div className="text-sm">
                          <span className="text-blue-700 dark:text-blue-300 font-semibold">
                            Percentage Change:
                          </span>
                          <span
                            className={`ml-2 font-bold text-lg ${
                              ((first.totalRawMaterialCost -
                                second.totalRawMaterialCost) /
                                second.totalRawMaterialCost) *
                                100 >
                              0
                                ? "text-slate-900 dark:text-white"
                                : "text-slate-900 dark:text-white"
                            }`}
                          >
                            {(
                              ((first.totalRawMaterialCost -
                                second.totalRawMaterialCost) /
                                second.totalRawMaterialCost) *
                              100
                            ).toFixed(2)}
                            %
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Detailed Changes */}
                    {changes.length === 0 ? (
                      <div className="bg-slate-50 dark:bg-slate-800/50 border-2 border-slate-200 dark:border-slate-700 rounded-lg p-6 text-center">
                        <CheckCircle
                          size={40}
                          className="mx-auto mb-4 text-blue-600"
                        />
                        <p className="text-slate-700 dark:text-slate-300 font-semibold">
                          No changes detected between these versions
                        </p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {Object.entries(changesByRawMaterial).map(
                          ([materialName, materialChanges]) => (
                            <div
                              key={materialName}
                              className="bg-slate-50 dark:bg-slate-800/50 border-2 border-slate-200 dark:border-slate-700 rounded-lg p-6"
                            >
                              <h4 className="text-lg font-bold text-slate-900 dark:text-white mb-4">
                                {materialName}
                                <span className="text-sm text-slate-600 dark:text-slate-400 ml-2">
                                  ({materialChanges.length} change
                                  {materialChanges.length !== 1 ? "s" : ""})
                                </span>
                              </h4>
                              <div className="space-y-3">
                                {materialChanges.map((change, idx) => (
                                  <div
                                    key={idx}
                                    className="grid grid-cols-3 gap-4 bg-white dark:bg-slate-900 rounded p-4 border border-slate-200 dark:border-slate-700"
                                  >
                                    <div>
                                      <p className="text-xs text-slate-600 dark:text-slate-400 font-semibold mb-1">
                                        FIELD
                                      </p>
                                      <p className="font-semibold text-slate-900 dark:text-white">
                                        {change.field}
                                      </p>
                                    </div>
                                    <div className="bg-slate-100 dark:bg-slate-700 rounded p-3 border border-slate-200 dark:border-slate-600">
                                      <p className="text-xs text-slate-700 dark:text-slate-300 font-semibold mb-1">
                                        BEFORE (Old)
                                      </p>
                                      <p className="text-sm font-bold text-slate-900 dark:text-white">
                                        {change.oldValueFormatted}
                                      </p>
                                    </div>
                                    <div className="bg-blue-50 dark:bg-blue-900/10 rounded p-3 border border-blue-200 dark:border-blue-700">
                                      <p className="text-xs text-blue-700 dark:text-blue-300 font-semibold mb-1">
                                        AFTER (New)
                                      </p>
                                      <p className="text-sm font-bold text-slate-900 dark:text-white">
                                        {change.newValueFormatted}
                                      </p>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ),
                        )}
                      </div>
                    )}
                  </>
                );
              })()}
            </div>
          </div>
        </Modal>
      )}
    </Layout>
  );
}



