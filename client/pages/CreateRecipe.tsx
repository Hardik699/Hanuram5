import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import {
  ArrowLeft,
  Check,
  AlertCircle,
  Plus,
  Trash2,
  Edit2,
  X,
  ChefHat,
  Save,
} from "lucide-react";
import { Layout } from "@/components/Layout";
import { CostingCalculatorForm } from "@/components/CostingCalculatorForm";
import { SearchableRMSelect } from "@/components/SearchableRMSelect";
import { useAuth } from "@/hooks/useAuth";
import { PageHeader } from "@/components/PageHeader";

interface Unit {
  _id: string;
  name: string;
}

interface Category {
  _id: string;
  name: string;
}

interface SubCategory {
  _id: string;
  name: string;
  categoryId: string;
}

interface RawMaterial {
  _id: string;
  code: string;
  name: string;
  categoryId: string;
  subCategoryId: string;
  unitId?: string;
  unitName?: string;
  lastAddedPrice?: number;
  lastVendorName?: string;
  brandIds?: string[];
  brandNames?: string[];
}

interface RecipeItem {
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
  brandId?: string;
  brandName?: string;
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
  items?: RecipeItem[];
}

export default function CreateRecipe() {
  const navigate = useNavigate();
  const { id } = useParams();
  const { hasPermission, user } = useAuth();
  const [units, setUnits] = useState<Unit[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [subCategories, setSubCategories] = useState<SubCategory[]>([]);
  const [rawMaterials, setRawMaterials] = useState<RawMaterial[]>([]);
  const [loading, setLoading] = useState(false);
  const [pageLoading, setPageLoading] = useState(id ? true : false);
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState<"success" | "error" | "">("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [recipeItems, setRecipeItems] = useState<RecipeItem[]>([]);
  const [showAddItemForm, setShowAddItemForm] = useState(false);
  const [itemErrors, setItemErrors] = useState<Record<string, string>>({});
  const [filterCategoryForRM, setFilterCategoryForRM] = useState("");
  const [filterSubCategoryForRM, setFilterSubCategoryForRM] = useState("");
  const [filterSearchRM, setFilterSearchRM] = useState("");
  const [selectedRMForItem, setSelectedRMForItem] = useState("");
  const [editingItemIndex, setEditingItemIndex] = useState<number | null>(null);
  const [editItemForm, setEditItemForm] = useState({
    quantity: "",
    unitId: "",
    price: "",
  });

  const [productionLabourCostPerKg, setProductionLabourCostPerKg] = useState(0);
  const [packingLabourCostPerKg, setPackingLabourCostPerKg] = useState(0);

  const [formData, setFormData] = useState({
    name: "",
    recipeType: "master",
    batchSize: "",
    unitId: "",
    yield: "",
    moisturePercentage: "",
  });

  const [itemForm, setItemForm] = useState({
    quantity: "",
    unitId: "",
    price: "",
    vendorId: "",
  });
  const [selectedBrandForItem, setSelectedBrandForItem] = useState("");
  const [vendorPricesByRM, setVendorPricesByRM] = useState<Record<string, any[]>>({});

  // Recipe selection modal state
  const [recipes, setRecipes] = useState<Recipe[]>([]);
  const [showAddRecipeModal, setShowAddRecipeModal] = useState(false);
  const [recipeSearchQuery, setRecipeSearchQuery] = useState("");

  // Unit search state
  const [unitSearchInput, setUnitSearchInput] = useState("");
  const [openUnitDropdown, setOpenUnitDropdown] = useState(false);

  // Item form unit search state
  const [itemUnitSearchInput, setItemUnitSearchInput] = useState("");
  const [openItemUnitDropdown, setOpenItemUnitDropdown] = useState(false);

  // Edit form unit search state
  const [editUnitSearchInput, setEditUnitSearchInput] = useState("");
  const [openEditUnitDropdown, setOpenEditUnitDropdown] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      navigate("/");
      return;
    }

    Promise.all([
      fetchUnits(),
      fetchCategories(),
      fetchSubCategories(),
      fetchRawMaterials(),
      fetchRecipes(),
    ]).then(() => {
      if (id) {
        fetchRecipe(id);
      } else {
        setPageLoading(false);
      }
    });
  }, [id]);

  const fetchUnits = async () => {
    try {
      const response = await fetch("/api/units");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setUnits(data.data);
      }
    } catch (error) {
      console.error("Error fetching units:", error);
    }
  };

  const fetchCategories = async () => {
    try {
      const response = await fetch("/api/categories");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setCategories(data.data);
      }
    } catch (error) {
      console.error("Error fetching categories:", error);
    }
  };

  const fetchSubCategories = async () => {
    try {
      const response = await fetch("/api/subcategories");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setSubCategories(data.data);
      }
    } catch (error) {
      console.error("Error fetching subcategories:", error);
    }
  };

  const fetchRawMaterials = async () => {
    try {
      const response = await fetch("/api/raw-materials");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setRawMaterials(data.data);
      }
    } catch (error) {
      console.error("Error fetching raw materials:", error);
    }
  };

  const fetchRecipes = async () => {
    try {
      const response = await fetch("/api/recipes");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setRecipes(data.data);
      }
    } catch (error) {
      console.error("Error fetching recipes:", error);
    }
  };

  const fetchVendorPricesForRM = async (rmId: string) => {
    try {
      const response = await fetch(`/api/raw-materials/${rmId}/vendor-prices`);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        console.log(`Vendor prices for RM ${rmId}:`, data.data);
        setVendorPricesByRM((prev) => ({
          ...prev,
          [rmId]: data.data,
        }));
      }
    } catch (error) {
      console.error("Error fetching vendor prices:", error);
    }
  };

  // Helper function to get price for a specific brand
  const getPriceForBrand = (rmId: string, brandId?: string): number => {
    if (!brandId) {
      // No brand selected, return the overall last purchase price
      const rm = rawMaterials.find((r) => r._id === rmId);
      return rm?.lastAddedPrice || 0;
    }

    // Find price for specific brand from vendor prices
    const prices = vendorPricesByRM[rmId] || [];

    // Try to find exact brand match
    let brandPrice = prices.find((p: any) => p.brandId === brandId);

    // If not found by brandId, try by brandName
    if (!brandPrice) {
      const selectedRM = rawMaterials.find((r) => r._id === rmId);
      if (selectedRM && selectedRM.brandIds) {
        const brandIndex = selectedRM.brandIds.indexOf(brandId);
        if (brandIndex !== -1 && selectedRM.brandNames) {
          const brandName = selectedRM.brandNames[brandIndex];
          brandPrice = prices.find((p: any) => p.brandName === brandName);
        }
      }
    }

    return brandPrice?.price || 0;
  };

  const fetchRecipe = async (recipeId: string) => {
    try {
      const response = await fetch("/api/recipes");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        const recipe = data.data.find((r: Recipe) => r._id === recipeId);
        if (recipe) {
          setFormData({
            name: recipe.name,
            recipeType: recipe.recipeType || "master",
            batchSize: recipe.batchSize.toString(),
            unitId: recipe.unitId,
            yield: recipe.yield?.toString() || "",
            moisturePercentage: recipe.moisturePercentage?.toString() || "",
          });

          // Load labour costs from recipe
          if (recipe.productionLabourCostPerKg !== undefined) {
            setProductionLabourCostPerKg(recipe.productionLabourCostPerKg);
          }
          if (recipe.packingLabourCostPerKg !== undefined) {
            setPackingLabourCostPerKg(recipe.packingLabourCostPerKg);
          }

          // Fetch recipe items separately
          try {
            const itemsResponse = await fetch(`/api/recipes/${recipeId}/items`);
            if (!itemsResponse.ok) {
              throw new Error(`HTTP error! status: ${itemsResponse.status}`);
            }
            const itemsData = await itemsResponse.json();
            if (itemsData.success && Array.isArray(itemsData.data)) {
              setRecipeItems(itemsData.data);
            } else if (recipe.items) {
              setRecipeItems(recipe.items);
            }
          } catch (itemsError) {
            console.error("Error fetching recipe items:", itemsError);
            if (recipe.items) {
              setRecipeItems(recipe.items);
            }
          }
        } else {
          navigate("/rmc");
        }
      }
    } catch (error) {
      console.error("Error fetching recipe:", error);
      navigate("/rmc");
    } finally {
      setPageLoading(false);
    }
  };

  const getFilteredRawMaterials = () => {
    return rawMaterials.filter((rm) => {
      if (filterCategoryForRM && rm.categoryId !== filterCategoryForRM)
        return false;
      if (filterSubCategoryForRM && rm.subCategoryId !== filterSubCategoryForRM)
        return false;
      if (
        filterSearchRM &&
        !rm.name.toLowerCase().includes(filterSearchRM.toLowerCase())
      )
        return false;
      if (recipeItems.some((item) => item.rawMaterialId === rm._id))
        return false;
      return true;
    });
  };

  const getFilteredSubCategories = () => {
    if (!filterCategoryForRM) return [];
    return subCategories.filter((sc) => sc.categoryId === filterCategoryForRM);
  };

  const getFilteredUnits = () => {
    if (!unitSearchInput) return units;
    return units.filter((unit) =>
      unit.name.toLowerCase().includes(unitSearchInput.toLowerCase()),
    );
  };

  const handleAddItem = () => {
    const newErrors: Record<string, string> = {};
    if (!selectedRMForItem) newErrors.rawMaterial = "Raw material is required";
    if (!itemForm.quantity || Number(itemForm.quantity) <= 0)
      newErrors.quantity = "Quantity must be greater than 0";
    if (!itemForm.price || Number(itemForm.price) < 0)
      newErrors.price = "Valid price is required";

    if (Object.keys(newErrors).length > 0) {
      setItemErrors(newErrors);
      return;
    }

    const selectedRM = rawMaterials.find((rm) => rm._id === selectedRMForItem);
    if (!selectedRM) return;

    const totalPrice = Number(itemForm.quantity) * Number(itemForm.price);

    // Get brand name if brand is selected
    let brandName = "";
    if (selectedBrandForItem && selectedRM.brandIds && selectedRM.brandNames) {
      const brandIndex = selectedRM.brandIds.indexOf(selectedBrandForItem);
      if (brandIndex !== -1) {
        brandName = selectedRM.brandNames[brandIndex];
      }
    }

    const newItem: RecipeItem = {
      rawMaterialId: selectedRM._id,
      rawMaterialName: selectedRM.name,
      rawMaterialCode: selectedRM.code,
      quantity: Number(itemForm.quantity),
      unitId: itemForm.unitId || selectedRM.unitId,
      unitName: itemForm.unitId
        ? units.find((u) => u._id === itemForm.unitId)?.name ||
          selectedRM.unitName
        : selectedRM.unitName,
      price: Number(itemForm.price),
      vendorId: itemForm.vendorId || selectedRM._id,
      vendorName: itemForm.vendorId
        ? selectedRM.lastVendorName
        : selectedRM.lastVendorName,
      totalPrice: parseFloat(totalPrice.toFixed(2)),
      brandId: selectedBrandForItem || undefined,
      brandName: brandName || undefined,
    };

    setRecipeItems([...recipeItems, newItem]);
    // Keep form open and reset only the fields, not closing the form
    setSelectedRMForItem("");
    setSelectedBrandForItem("");
    setItemForm({ quantity: "", unitId: "", price: "", vendorId: "" });
    setItemErrors({});

    toast.success("Item Added!", {
      description: `${newItem.rawMaterialName} added to recipe with quantity ${newItem.quantity}`,
      duration: 2500,
    });
  };

  const handleAddRecipe = (selectedRecipe: Recipe) => {
    try {
      // Add the entire recipe as a single item (with empty quantity for manual input)
      const recipeAsItem: RecipeItem = {
        rawMaterialId: selectedRecipe._id,
        rawMaterialName: selectedRecipe.name,
        rawMaterialCode: selectedRecipe.code,
        quantity: 0,
        unitId: formData.unitId || selectedRecipe.unitId,
        unitName: formData.unitId
          ? units.find((u) => u._id === formData.unitId)?.name ||
            selectedRecipe.unitName
          : selectedRecipe.unitName,
        price: (selectedRecipe as any).pricePerUnit || 0,
        vendorId: selectedRecipe._id,
        vendorName: selectedRecipe.name,
        totalPrice: 0,
      };

      // Add recipe as a single item
      const newItems = [...recipeItems, recipeAsItem];
      setRecipeItems(newItems);

      // Close modal and reset search
      setShowAddRecipeModal(false);
      setRecipeSearchQuery("");

      // Show success message
      const pricePerUnit = (selectedRecipe as any).pricePerUnit || 0;
      toast.success("Recipe Added!", {
        description: `"${selectedRecipe.name}" added with price ₹${pricePerUnit.toFixed(2)}/unit`,
        duration: 2500,
      });
    } catch (error) {
      console.error("Error adding recipe:", error);
      toast.error("Failed to Add Recipe", {
        description: "Something went wrong while adding the recipe",
        duration: 3000,
      });
    }
  };

  const handleRemoveItem = (index: number) => {
    const removedItem = recipeItems[index];
    setRecipeItems(recipeItems.filter((_, i) => i !== index));

    toast.success("Item Removed", {
      description: `${removedItem.rawMaterialName} has been removed from the recipe`,
      duration: 2000,
    });
  };

  const handleStartEditItem = (index: number) => {
    const item = recipeItems[index];
    setEditingItemIndex(index);
    setEditItemForm({
      quantity: item.quantity.toString(),
      unitId: item.unitId || "",
      price: item.price.toString(),
    });
  };

  const handleSaveEditItem = () => {
    const newErrors: Record<string, string> = {};
    if (!editItemForm.quantity || Number(editItemForm.quantity) <= 0)
      newErrors.quantity = "Quantity must be greater than 0";

    if (Object.keys(newErrors).length > 0) {
      setItemErrors(newErrors);
      return;
    }

    if (editingItemIndex === null) return;

    const updatedItems = [...recipeItems];
    const item = updatedItems[editingItemIndex];
    const newQuantity = Number(editItemForm.quantity);
    const totalPrice = newQuantity * item.price;

    updatedItems[editingItemIndex] = {
      ...item,
      quantity: newQuantity,
      totalPrice: parseFloat(totalPrice.toFixed(2)),
    };

    setRecipeItems(updatedItems);
    setEditingItemIndex(null);
    setEditItemForm({ quantity: "", unitId: "", price: "" });
    setItemErrors({});
  };

  const handleCancelEditItem = () => {
    setEditingItemIndex(null);
    setEditItemForm({ quantity: "", unitId: "", price: "" });
    setItemErrors({});
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = "Recipe name is required";
    }

    if (!formData.batchSize || Number(formData.batchSize) <= 0) {
      newErrors.batchSize = "Batch size must be greater than 0";
    }

    if (!formData.unitId) {
      newErrors.unitId = "Unit is required";
    }

    if (recipeItems.length === 0) {
      newErrors.items = "At least one raw material is required";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setLoading(true);
    setMessage("");

    try {
      const selectedUnit = units.find((u) => u._id === formData.unitId);

      const method = id ? "PUT" : "POST";
      const url = id ? `/api/recipes/${id}` : "/api/recipes";

      console.log("Recipe Form Data:", formData);
      console.log("Request URL:", url, "Method:", method);

      const response = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: formData.name,
          recipeType: formData.recipeType,
          batchSize: Number(formData.batchSize),
          unitId: formData.unitId,
          unitName: selectedUnit?.name,
          yield: formData.yield ? Number(formData.yield) : undefined,
          moisturePercentage: formData.moisturePercentage
            ? Number(formData.moisturePercentage)
            : undefined,
          items: recipeItems,
          createdBy: localStorage.getItem("username") || "admin",
        }),
      });

      const data = await response.json();
      console.log("Recipe save response:", { status: response.status, data });

      if (response.ok && data.success) {
        const successMsg = id ? "Recipe updated successfully!" : "Recipe created successfully!";
        toast.success(successMsg, {
          description: id
            ? "Your recipe has been updated with all changes."
            : "Your new recipe is ready to use.",
          duration: 3000,
        });
        setTimeout(() => {
          navigate("/rmc");
        }, 1500);
      } else {
        const errorMsg = data.message || `Operation failed (Status: ${response.status})`;
        toast.error("Operation Failed", {
          description: errorMsg,
          duration: 4000,
        });
        console.error("Recipe save failed:", errorMsg);
      }
    } catch (error) {
      const errorDesc = error instanceof Error ? error.message : "Unknown error occurred";
      toast.error("Error Saving Recipe", {
        description: errorDesc,
        duration: 4000,
      });
      console.error("Recipe save error:", error);
    } finally {
      setLoading(false);
    }
  };

  const calculateTotals = () => {
    const totalCost = recipeItems.reduce(
      (sum, item) => sum + item.totalPrice,
      0,
    );
    const pricePerUnit =
      formData.yield && Number(formData.yield) > 0
        ? totalCost / Number(formData.yield)
        : 0;
    return {
      totalCost: parseFloat(totalCost.toFixed(2)),
      pricePerUnit: parseFloat(pricePerUnit.toFixed(2)),
    };
  };

  if (pageLoading) {
    return (
      <Layout title="Loading...">
        <div className="flex items-center justify-center py-12">
          <div className="inline-block w-8 h-8 border-4 border-teal-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-600 dark:text-slate-400 ml-3 font-medium">
            Loading...
          </p>
        </div>
      </Layout>
    );
  }

  const totals = calculateTotals();

  return (
    <Layout title={id ? "Edit Recipe" : "Create Recipe"}>
      <div className="space-y-6">
        {/* Header */}
        <PageHeader
          title={id ? "Edit Recipe" : "Create Recipe"}
          description={
            id
              ? "Update recipe details, materials, and costing information"
              : "Create a new recipe with materials and costing details"
          }
          breadcrumbs={[
            { label: "Raw Material Costing", href: "/rmc" },
            { label: id ? "Edit Recipe" : "Create Recipe" },
          ]}
          icon={<ChefHat className="w-6 h-6 text-white" />}
          showBackButton={true}
        />

        {/* Message Alert */}
        {message && (
          <div
            className={`p-4 rounded-lg border ${
              messageType === "success"
                ? "bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800"
                : "bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800"
            }`}
          >
            <p
              className={
                messageType === "success"
                  ? "text-green-800 dark:text-green-300"
                  : "text-red-800 dark:text-red-300"
              }
            >
              {message}
            </p>
          </div>
        )}

        {/* Recipe Basic Info */}
        <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
          <div className="px-8 py-8 border-b border-slate-200 dark:border-slate-700">
            <div className="flex items-start justify-between gap-6 mb-6">
              <div className="flex-1">
                <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">
                  {id ? "Edit Recipe" : "Create Recipe"}
                </h2>
                <p className="text-slate-600 dark:text-slate-400">
                  {id ? "Update your recipe details and materials" : "Add a new recipe with materials and costing"}
                </p>
              </div>
              <div className="flex gap-2">
                {id && (
                  <>
                    <button className="px-4 py-2.5 rounded-lg border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 font-medium transition-all">
                      Delete
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-8 p-8">
            {/* RECIPE DETAILS Section */}
            <div className="border-l-4 border-indigo-500 pl-6">
              <h3 className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-widest mb-6">
                Recipe Details
              </h3>

              {/* Recipe Name */}
              <div className="mb-6">
                <label className="block text-sm font-bold text-slate-900 dark:text-white mb-3 tracking-tight">
                  Recipe Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                  placeholder="Enter recipe name"
                  className={`w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border transition-all ${
                    errors.name
                      ? "border-red-500 dark:border-red-400"
                      : "border-slate-300 dark:border-slate-600 hover:border-slate-400 dark:hover:border-slate-500"
                  } text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-medium`}
                />
                {errors.name && (
                  <p className="text-red-600 dark:text-red-400 text-xs mt-2 font-medium">
                    {errors.name}
                  </p>
                )}
              </div>

              {/* Recipe Type */}
              <div>
                <label className="block text-sm font-bold text-slate-900 dark:text-white mb-3 tracking-tight">
                  Recipe Type <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.recipeType}
                  onChange={(e) =>
                    setFormData({ ...formData, recipeType: e.target.value })
                  }
                  className="w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 hover:border-slate-400 dark:hover:border-slate-500 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all font-medium"
                >
                  <option value="master">Master Recipe</option>
                  <option value="sub">Sub Recipe</option>
                </select>
              </div>
            </div>


            {/* CONFIGURATION Section */}
            <div className="border-l-4 border-blue-500 pl-6">
              <h3 className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-widest mb-6">
                Configuration
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Batch Size */}
                <div>
                  <label className="block text-sm font-bold text-slate-900 dark:text-white mb-3 tracking-tight">
                    Batch Size <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="number"
                    value={formData.batchSize}
                    onChange={(e) =>
                      setFormData({ ...formData, batchSize: e.target.value })
                    }
                    placeholder="Enter batch size"
                    className={`w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border transition-all ${
                      errors.batchSize
                        ? "border-red-500 dark:border-red-400"
                        : "border-slate-300 dark:border-slate-600 hover:border-slate-400 dark:hover:border-slate-500"
                    } text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-medium`}
                  />
                  {errors.batchSize && (
                    <p className="text-red-600 dark:text-red-400 text-xs mt-2 font-medium">
                      {errors.batchSize}
                    </p>
                  )}
                </div>

                {/* Unit */}
                <div>
                  <label className="block text-sm font-bold text-slate-900 dark:text-white mb-3 tracking-tight">
                    Unit <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      placeholder="Search or select unit..."
                      value={
                        openUnitDropdown
                          ? unitSearchInput
                          : formData.unitId
                            ? units.find((u) => u._id === formData.unitId)?.name || ""
                            : ""
                      }
                      onChange={(e) => {
                        setOpenUnitDropdown(true);
                        setUnitSearchInput(e.target.value);
                      }}
                      onFocus={() => {
                        setOpenUnitDropdown(true);
                        setUnitSearchInput("");
                      }}
                      onBlur={() => {
                        setTimeout(() => setOpenUnitDropdown(false), 200);
                      }}
                      className={`w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border transition-all ${
                        errors.unitId
                          ? "border-red-500 dark:border-red-400"
                          : "border-slate-300 dark:border-slate-600 hover:border-slate-400 dark:hover:border-slate-500"
                      } text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-medium`}
                    />
                    {openUnitDropdown && (
                      <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg shadow-lg z-10 max-h-48 overflow-y-auto">
                        {getFilteredUnits().length > 0 ? (
                          getFilteredUnits().map((unit) => (
                            <div
                              key={unit._id}
                              onClick={() => {
                                setFormData({ ...formData, unitId: unit._id });
                                setOpenUnitDropdown(false);
                                setUnitSearchInput("");
                              }}
                              className="px-4 py-3 hover:bg-indigo-50 dark:hover:bg-slate-600 cursor-pointer border-b border-slate-100 dark:border-slate-600 last:border-b-0 text-slate-900 dark:text-white"
                            >
                              {unit.name}
                            </div>
                          ))
                        ) : (
                          <div className="px-4 py-3 text-center text-slate-500 dark:text-slate-400">
                            No units found
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                  {errors.unitId && (
                    <p className="text-red-600 dark:text-red-400 text-sm mt-1">
                      {errors.unitId}
                    </p>
                  )}
                </div>

                {/* Yield */}
                <div>
                  <label className="block text-sm font-bold text-slate-900 dark:text-white mb-3 tracking-tight">
                    Yield (Optional)
                  </label>
                  <input
                    type="number"
                    value={formData.yield}
                    onChange={(e) =>
                      setFormData({ ...formData, yield: e.target.value })
                    }
                    placeholder="Enter yield"
                    className="w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 hover:border-slate-400 dark:hover:border-slate-500 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-medium transition-all"
                  />
                </div>

                {/* Moisture Percentage */}
                <div>
                  <label className="block text-sm font-bold text-slate-900 dark:text-white mb-3 tracking-tight">
                    Moisture Percentage (Optional)
                  </label>
                  <input
                    type="number"
                    value={formData.moisturePercentage}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        moisturePercentage: e.target.value,
                      })
                    }
                    placeholder="Enter moisture percentage"
                    className="w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 hover:border-slate-400 dark:hover:border-slate-500 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-medium transition-all"
                  />
                </div>
              </div>
            </div>

            {/* Recipe Items Section */}
            <div className="border-l-4 border-blue-500 pl-6">
              <h3 className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-widest mb-6">
                Recipe Items
              </h3>

              <div className="flex items-center justify-between mb-6">
                <div></div>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setShowAddRecipeModal(!showAddRecipeModal)}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-all font-medium text-sm flex items-center gap-2 shadow-md"
                  >
                    <Plus className="w-4 h-4" />
                    Add Sub Recipe
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowAddItemForm(!showAddItemForm)}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-all font-medium text-sm flex items-center gap-2 shadow-md"
                  >
                    <Plus className="w-4 h-4" />
                    Add RM
                  </button>
                </div>
              </div>

              {/* Add Item Form */}
              {showAddItemForm && (
                <div className="bg-gradient-to-br from-blue-50 via-slate-50 to-blue-50 dark:from-slate-700/50 dark:via-slate-800/50 dark:to-slate-800/50 rounded-xl border border-blue-200 dark:border-slate-700/50 p-6 mb-6 space-y-4 shadow-sm">
                  {/* Filters Row - 3 columns */}
                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <label className="block text-sm font-bold text-slate-900 dark:text-white mb-2 tracking-tight">
                        Category
                      </label>
                      <select
                        value={filterCategoryForRM}
                        onChange={(e) => {
                          setFilterCategoryForRM(e.target.value);
                          setFilterSubCategoryForRM("");
                        }}
                        className="w-full px-3 py-2.5 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 hover:border-slate-300 dark:hover:border-slate-500 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm font-medium transition-all"
                      >
                        <option value="">All Categories</option>
                        {categories.map((cat) => (
                          <option key={cat._id} value={cat._id}>
                            {cat.name}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-bold text-slate-900 dark:text-white mb-2 tracking-tight">
                        Sub Category
                      </label>
                      <select
                        value={filterSubCategoryForRM}
                        onChange={(e) =>
                          setFilterSubCategoryForRM(e.target.value)
                        }
                        disabled={!filterCategoryForRM}
                        className="w-full px-3 py-2.5 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 hover:border-slate-300 dark:hover:border-slate-500 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm font-medium transition-all disabled:opacity-50"
                      >
                        <option value="">All Sub Categories</option>
                        {getFilteredSubCategories().map((sc) => (
                          <option key={sc._id} value={sc._id}>
                            {sc.name}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* Raw Material Selection - Full Width with Integrated Search */}
                  <div>
                    <label className="block text-sm font-bold text-slate-900 dark:text-white mb-2 tracking-tight">
                      Raw Material <span className="text-red-500">*</span>
                    </label>
                    <SearchableRMSelect
                      value={selectedRMForItem}
                      onChange={(rmId) => {
                        setSelectedRMForItem(rmId);
                        setSelectedBrandForItem(""); // Reset brand selection
                        // Auto-fill unit and price
                        if (rmId) {
                          const selectedRM = rawMaterials.find(
                            (rm) => rm._id === rmId,
                          );
                          if (selectedRM) {
                            setItemForm((prev) => ({
                              ...prev,
                              unitId: selectedRM.unitId || "",
                              price: (selectedRM.lastAddedPrice || 0).toString(),
                            }));
                            // Fetch vendor prices for brand-aware pricing
                            fetchVendorPricesForRM(rmId);
                          }
                        } else {
                          setItemForm((prev) => ({
                            ...prev,
                            unitId: "",
                            price: "",
                          }));
                        }
                      }}
                      options={getFilteredRawMaterials()}
                      placeholder="Choose Raw Material"
                      searchValue={filterSearchRM}
                      onSearchChange={setFilterSearchRM}
                      error={!!itemErrors.rawMaterial}
                    />
                    {itemErrors.rawMaterial && (
                      <p className="text-red-600 dark:text-red-400 text-xs mt-1">
                        {itemErrors.rawMaterial}
                      </p>
                    )}
                  </div>

                  {/* Brand Selection - Optional if RM has brands */}
                  {selectedRMForItem && (() => {
                    const selectedRM = rawMaterials.find(
                      (rm) => rm._id === selectedRMForItem,
                    );
                    return selectedRM?.brandNames && selectedRM.brandNames.length > 0 ? (
                      <div>
                        <label className="block text-sm font-bold text-slate-900 dark:text-white mb-2 tracking-tight">
                          Brand (Optional)
                        </label>
                        <select
                          value={selectedBrandForItem}
                          onChange={(e) => {
                            const brandId = e.target.value;
                            setSelectedBrandForItem(brandId);
                            // Update price based on selected brand
                            const price = getPriceForBrand(selectedRMForItem, brandId || undefined);
                            setItemForm((prev) => ({
                              ...prev,
                              price: price.toString(),
                            }));
                          }}
                          className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
                        >
                          <option value="">-- Select Brand --</option>
                          {selectedRM.brandNames.map((brand, index) => {
                            const brandId = selectedRM.brandIds?.[index];
                            return (
                              <option key={index} value={brandId || ""}>
                                {brand}
                              </option>
                            );
                          })}
                        </select>
                        {selectedBrandForItem && (() => {
                          const selectedRM = rawMaterials.find(
                            (rm) => rm._id === selectedRMForItem,
                          );
                          const price = getPriceForBrand(selectedRMForItem, selectedBrandForItem);
                          const prices = vendorPricesByRM[selectedRMForItem] || [];
                          const brandPrice = prices.find(
                            (p: any) => p.brandId === selectedBrandForItem ||
                              p.brandName === selectedRM?.brandNames?.[
                                selectedRM.brandIds?.indexOf(selectedBrandForItem) || 0
                              ]
                          );

                          return (
                            <div className="mt-2 text-xs text-slate-600 dark:text-slate-400">
                              {price > 0 ? (
                                <div>
                                  Brand price: ₹{price.toFixed(2)}
                                  {selectedRM?.unitName ? ` / ${selectedRM.unitName}` : ""}
                                </div>
                              ) : (
                                <div>No price data for this brand (using default)</div>
                              )}
                            </div>
                          );
                        })()}
                      </div>
                    ) : null;
                  })()}

                  {/* Quantity, Price, Unit - 3 columns */}
                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <label className="block text-sm font-bold text-slate-900 dark:text-white mb-2 tracking-tight">
                        Quantity <span className="text-red-500">*</span>
                      </label>
                      <input
                        type="number"
                        value={itemForm.quantity}
                        onChange={(e) =>
                          setItemForm({ ...itemForm, quantity: e.target.value })
                        }
                        placeholder="Enter quantity"
                        className={`w-full px-3 py-2.5 rounded-lg bg-white dark:bg-slate-800 border transition-all ${
                          itemErrors.quantity
                            ? "border-red-500 dark:border-red-400"
                            : "border-slate-200 dark:border-slate-600 hover:border-slate-300 dark:hover:border-slate-500"
                        } text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm font-medium`}
                      />
                      {itemErrors.quantity && (
                        <p className="text-red-600 dark:text-red-400 text-xs mt-1">
                          {itemErrors.quantity}
                        </p>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-bold text-slate-900 dark:text-white mb-2 tracking-tight">
                        Price (₹)
                        {selectedRMForItem && itemForm.price !== "" && (
                          <span className="text-xs font-normal text-green-600 dark:text-green-400 ml-1">(Auto-filled)</span>
                        )}
                      </label>
                      <div className="w-full px-3 py-2.5 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-700 dark:text-slate-300 text-sm font-semibold cursor-not-allowed">
                        {itemForm.price ? `₹${itemForm.price}` : "—"}
                      </div>
                      {selectedRMForItem && (
                        <div className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
                          {(() => {
                            const rm = rawMaterials.find((r) => r._id === selectedRMForItem);
                            if (selectedBrandForItem) {
                              const brandPrice = getPriceForBrand(selectedRMForItem, selectedBrandForItem);
                              return brandPrice > 0
                                ? `Brand price: ₹${brandPrice.toFixed(2)}${rm?.unitName ? ` / ${rm.unitName}` : ""}`
                                : `No brand price. Default: ₹${(rm?.lastAddedPrice || 0).toFixed(2)}${rm?.unitName ? ` / ${rm.unitName}` : ""}`;
                            }
                            return rm?.lastAddedPrice
                              ? `Last purchase: ₹${rm.lastAddedPrice.toFixed(2)}${rm.unitName ? ` / ${rm.unitName}` : ""}`
                              : "No price data available";
                          })()}
                        </div>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-bold text-slate-900 dark:text-white mb-2 tracking-tight">
                        Unit
                        {selectedRMForItem && itemForm.unitId !== "" && (
                          <span className="text-xs font-normal text-green-600 dark:text-green-400 ml-1">(Auto-filled)</span>
                        )}
                      </label>
                      <div className="w-full px-3 py-2.5 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-700 dark:text-slate-300 text-sm font-semibold cursor-not-allowed">
                        {itemForm.unitId ? units.find((u) => u._id === itemForm.unitId)?.name || "—" : "—"}
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={handleAddItem}
                      className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors font-medium text-sm"
                    >
                      ✓ Add Item & Continue
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setShowAddItemForm(false);
                        setSelectedRMForItem("");
                        setItemForm({
                          quantity: "",
                          unitId: "",
                          price: "",
                          vendorId: "",
                        });
                        setItemErrors({});
                      }}
                      className="flex-1 px-4 py-2 bg-slate-200 dark:bg-slate-700 text-slate-900 dark:text-white rounded-lg hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors font-medium text-sm"
                    >
                      Done
                    </button>
                  </div>
                </div>
              )}

              {/* Add Recipe Modal */}
              {showAddRecipeModal && (
                <div className="bg-gradient-to-br from-orange-50 dark:from-slate-700/50 to-amber-50 dark:to-slate-800/50 rounded-xl border border-orange-200 dark:border-orange-800/30 p-6 mb-6 space-y-4 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-md font-bold text-slate-900 dark:text-white">
                      Select Recipe to Add Items
                    </h4>
                    <button
                      type="button"
                      onClick={() => {
                        setShowAddRecipeModal(false);
                        setRecipeSearchQuery("");
                      }}
                      className="text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
                    >
                      <X className="w-5 h-5" />
                    </button>
                  </div>

                  {/* Search Input */}
                  <div>
                    <input
                      type="text"
                      placeholder="Search recipes by name or code..."
                      value={recipeSearchQuery}
                      onChange={(e) => setRecipeSearchQuery(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500"
                    />
                  </div>

                  {/* Recipes List */}
                  <div className="max-h-72 overflow-y-auto space-y-2 border border-slate-200 dark:border-slate-600 rounded-lg p-3 bg-white dark:bg-slate-800">
                    {recipes
                      .filter(
                        (recipe) =>
                          recipe._id !== id && // Exclude current recipe
                          (recipe.name
                            .toLowerCase()
                            .includes(recipeSearchQuery.toLowerCase()) ||
                            recipe.code
                              .toLowerCase()
                              .includes(recipeSearchQuery.toLowerCase())),
                      )
                      .map((recipe) => (
                        <button
                          key={recipe._id}
                          type="button"
                          onClick={() => handleAddRecipe(recipe)}
                          className="w-full text-left p-3 rounded-lg border border-slate-200 dark:border-slate-600 hover:bg-orange-100 dark:hover:bg-orange-900/30 hover:border-orange-400 dark:hover:border-orange-600 transition-all"
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex-1">
                              <p className="font-semibold text-slate-900 dark:text-white">
                                {recipe.name}
                              </p>
                              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                                Code: {recipe.code}
                              </p>
                            </div>
                            <div className="text-right ml-4">
                              <p className="text-sm font-bold text-orange-600 dark:text-orange-400">
                                ₹{((recipe as any).pricePerUnit || 0).toFixed(2)}
                              </p>
                              <p className="text-xs text-slate-600 dark:text-slate-400">
                                Price Per Unit
                              </p>
                            </div>
                          </div>
                        </button>
                      ))}

                    {recipes.filter(
                      (recipe) =>
                        recipe._id !== id &&
                        (recipe.name
                          .toLowerCase()
                          .includes(recipeSearchQuery.toLowerCase()) ||
                          recipe.code
                            .toLowerCase()
                            .includes(recipeSearchQuery.toLowerCase())),
                    ).length === 0 && (
                      <p className="text-center text-slate-600 dark:text-slate-400 py-4">
                        {recipes.length === 0
                          ? "No recipes available"
                          : "No recipes match your search"}
                      </p>
                    )}
                  </div>

                  <button
                    type="button"
                    onClick={() => {
                      setShowAddRecipeModal(false);
                      setRecipeSearchQuery("");
                    }}
                    className="w-full px-4 py-2 bg-slate-200 dark:bg-slate-700 text-slate-900 dark:text-white rounded-lg hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors font-medium text-sm"
                  >
                    Close
                  </button>
                </div>
              )}

              {/* Items Table */}
              {errors.items && (
                <p className="text-red-600 dark:text-red-400 text-sm mb-4">
                  {errors.items}
                </p>
              )}

              {recipeItems.length === 0 ? (
                <div className="text-center py-8 text-slate-500 dark:text-slate-400">
                  <p>No items added yet. Click "Add Item" to start.</p>
                </div>
              ) : (
                <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                  <table className="w-full min-w-[900px]">
                    <thead className="bg-blue-50 dark:bg-blue-900/20 border-b border-blue-200 dark:border-blue-900/50 sticky top-0">
                      <tr>
                        <th className="px-6 py-4 text-left text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                          <span className="flex items-center gap-2">
                            <span className="inline-block w-1.5 h-1.5 bg-blue-500 rounded-full"></span>
                            Raw Material
                          </span>
                        </th>
                        <th className="px-6 py-4 text-left text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                          Qty
                        </th>
                        <th className="px-6 py-4 text-left text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                          Unit
                        </th>
                        <th className="px-6 py-4 text-left text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                          Price
                        </th>
                        <th className="px-6 py-4 text-left text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                          Total
                        </th>
                        <th className="px-6 py-4 text-left text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                      {recipeItems.map((item, index) => (
                        <tr
                          key={index}
                          className={`transition-all group border-l-4 border-l-transparent hover:border-l-blue-500 cursor-pointer ${
                            editingItemIndex === index
                              ? "bg-blue-50 dark:bg-blue-900/20 border-l-blue-500"
                              : `${index % 2 === 0 ? "hover:bg-blue-50 dark:hover:bg-slate-700/50" : "bg-slate-50 dark:bg-slate-800/50 hover:bg-blue-50 dark:hover:bg-slate-700/50"}`
                          }`}
                        >
                          <td className="px-6 py-4 text-sm font-medium text-slate-900 dark:text-white">
                            {item.rawMaterialName} ({item.rawMaterialCode})
                          </td>
                          <td className="px-6 py-4 text-sm text-slate-900 dark:text-white">
                            {editingItemIndex === index ? (
                              <input
                                type="number"
                                value={editItemForm.quantity}
                                onChange={(e) =>
                                  setEditItemForm({
                                    ...editItemForm,
                                    quantity: e.target.value,
                                  })
                                }
                                className={`w-20 px-2 py-1 rounded border ${
                                  itemErrors.quantity
                                    ? "border-red-500"
                                    : "border-slate-300 dark:border-slate-600"
                                } bg-white dark:bg-slate-700 text-slate-900 dark:text-white`}
                              />
                            ) : (
                              item.quantity
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">
                            {editingItemIndex === index ? (
                              <span className="text-slate-700 dark:text-slate-300 font-medium">
                                {item.unitName || "-"}
                              </span>
                            ) : (
                              item.unitName || "-"
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm text-blue-600 dark:text-blue-400 font-semibold">
                            {editingItemIndex === index ? (
                              <span className="text-blue-600 dark:text-blue-400 font-semibold">
                                ₹{item.price.toFixed(2)}
                              </span>
                            ) : (
                              `₹${item.price.toFixed(2)}`
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm font-semibold text-slate-900 dark:text-white">
                            {editingItemIndex === index
                              ? `₹${(Number(editItemForm.quantity) * item.price).toFixed(2)}`
                              : `₹${item.totalPrice.toFixed(2)}`}
                          </td>
                          <td className="px-6 py-4 text-sm space-x-2 flex">
                            {editingItemIndex === index ? (
                              <>
                                <button
                                  type="button"
                                  onClick={handleSaveEditItem}
                                  className="inline-flex items-center gap-1 px-3 py-1.5 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded hover:bg-green-200 dark:hover:bg-green-800 transition-colors"
                                >
                                  <Check className="w-4 h-4" />
                                  Save
                                </button>
                                <button
                                  type="button"
                                  onClick={handleCancelEditItem}
                                  className="inline-flex items-center gap-1 px-3 py-1.5 bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 rounded hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors"
                                >
                                  <X className="w-4 h-4" />
                                  Cancel
                                </button>
                              </>
                            ) : (
                              <>
                                <button
                                  type="button"
                                  onClick={() => handleStartEditItem(index)}
                                  className="inline-flex items-center gap-1 px-3 py-1.5 bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 rounded hover:bg-blue-200 dark:hover:bg-blue-800 transition-colors"
                                >
                                  <Edit2 className="w-4 h-4" />
                                  Edit
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleRemoveItem(index)}
                                  className="inline-flex items-center gap-1 px-3 py-1.5 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded hover:bg-red-200 dark:hover:bg-red-800 transition-colors"
                                >
                                  <Trash2 className="w-4 h-4" />
                                  Remove
                                </button>
                              </>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Totals */}
              {id || recipeItems.length > 0 ? (
                <div className="mt-8 pt-8 border-t-2 border-blue-200 dark:border-blue-800">
                  {recipeItems.length === 0 && id ? (
                    <div className="space-y-4 bg-slate-50 dark:bg-slate-700/30 rounded-lg p-4">
                      <div className="flex justify-between items-center animate-pulse">
                        <span className="text-sm font-semibold text-slate-600 dark:text-slate-400">
                          Total Raw Material Cost:
                        </span>
                        <div className="h-6 w-24 bg-slate-300 dark:bg-slate-600 rounded"></div>
                      </div>
                      {formData.yield && Number(formData.yield) > 0 && (
                        <div className="flex justify-between items-center animate-pulse">
                          <span className="text-sm font-semibold text-slate-600 dark:text-slate-400">
                            Price Per Unit (Yield: {formData.yield}):
                          </span>
                          <div className="h-6 w-24 bg-slate-300 dark:bg-slate-600 rounded"></div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="bg-gradient-to-br from-blue-50 dark:from-blue-900/20 to-blue-100/50 dark:to-blue-900/10 rounded-lg p-4 border border-blue-200 dark:border-blue-800/30">
                        <p className="text-xs font-semibold text-blue-600 dark:text-blue-400 uppercase tracking-wide mb-2">
                          Total Raw Material Cost
                        </p>
                        <p className="text-2xl font-bold text-blue-700 dark:text-blue-300">
                          ₹{totals.totalCost.toFixed(2)}
                        </p>
                      </div>
                      {formData.yield && Number(formData.yield) > 0 && (
                        <div className="bg-gradient-to-br from-green-50 dark:from-green-900/20 to-green-100/50 dark:to-green-900/10 rounded-lg p-4 border border-green-200 dark:border-green-800/30">
                          <p className="text-xs font-semibold text-green-600 dark:text-green-400 uppercase tracking-wide mb-2">
                            Price Per Unit (Yield: {formData.yield})
                          </p>
                          <p className="text-2xl font-bold text-green-700 dark:text-green-300">
                            ₹{totals.pricePerUnit.toFixed(2)}
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ) : null}
            </div>

            {/* Form Buttons */}
            <div className="flex gap-3 pt-6 border-t border-slate-200 dark:border-slate-700">
              <button
              type="submit"
              disabled={loading}
              className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 disabled:from-slate-400 disabled:to-slate-400 text-white font-semibold py-3 px-4 rounded-lg transition-all flex items-center justify-center gap-2 shadow-lg hover:shadow-xl"
            >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    <span>Saving...</span>
                  </>
                ) : (
                  <>
                    <Save className="w-4 h-4" />
                    <span>{id ? "Update Recipe" : "Create Recipe"}</span>
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => navigate("/rmc")}
                className="px-6 bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 font-semibold py-3 rounded-lg hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>

        {/* Labour Costing Sections - Only show if recipe is created AND user is not a production user */}
        {id && user?.role_id !== 7 && (
          <>
            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
              {/* Section Header */}
              <div className="px-6 py-4 bg-gradient-to-r from-slate-800 to-slate-700 flex items-center gap-3">
                <span className="text-lg">👥</span>
                <h2 className="text-base font-bold text-white">Labour & Other Costs</h2>
              </div>

              <div className="p-5 space-y-4">
                {/* Packaging & Handling Costing Calculator */}
                <CostingCalculatorForm
                  title="📦 Packaging & Handling Costing Calculator"
                  recipeId={id}
                  rmCostPerKg={
                    parseFloat(formData.batchSize) > 0
                      ? recipeItems.reduce((sum, item) => sum + item.totalPrice, 0) / parseFloat(formData.batchSize)
                      : 0
                  }
                  productionLabourCostPerKg={productionLabourCostPerKg}
                  packingLabourCostPerKg={packingLabourCostPerKg}
                  batchSize={parseFloat(formData.batchSize) || 0}
                  yield={parseFloat(formData.yield) || 100}
                />
              </div>
            </div>
          </>
        )}
      </div>
    </Layout>
  );
}



