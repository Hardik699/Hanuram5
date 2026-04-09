import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { cn } from "@/lib/utils";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import RawMaterialLogs from "@/components/RawMaterialLogs";
import {
  ArrowLeft,
  Phone,
  Eye,
  History,
  ChefHat,
  ChevronUp,
  ChevronDown,
  Edit2,
  Trash2,
  Plus,
  Check,
} from "lucide-react";

interface UnitConversion {
  fromUnitId: string;
  fromUnitName: string;
  toUnitId: string;
  toUnitName: string;
  conversionFactor: number;
  addedAt: string;
  addedBy: string;
}

interface RawMaterial {
  _id: string;
  code: string;
  name: string;
  categoryId: string;
  categoryName: string;
  subCategoryId: string;
  subCategoryName: string;
  unitId?: string;
  unitName?: string;
  brandId?: string;
  brandName?: string;
  brandIds?: string[];
  brandNames?: string[];
  hsnCode?: string;
  unitConversions?: UnitConversion[];
  createdAt: string;
  lastAddedPrice?: number;
  lastVendorName?: string;
  lastPriceDate?: string;
}

interface Vendor {
  _id: string;
  name: string;
  personName: string;
  mobileNumber: string;
  email?: string;
  location: string;
}

interface VendorPrice {
  _id: string;
  rawMaterialId: string;
  vendorId: string;
  vendorName: string;
  quantity: number;
  unitName?: string;
  price: number;
  addedDate: string;
  brandId?: string;
  brandName?: string;
}

interface Brand {
  _id: string;
  name: string;
}

interface PriceLog {
  _id: string;
  rawMaterialId: string;
  vendorId: string;
  vendorName: string;
  oldPrice: number;
  newPrice: number;
  quantity: number;
  unitName?: string;
  changeDate: string;
  changedBy: string;
}

interface RecipeWithItems {
  _id: string;
  code: string;
  name: string;
  unitName: string;
  updatedAt: string;
  rawMaterialQuantity?: number;
  rawMaterialUnit?: string;
}

interface VendorWithLastPurchase extends Vendor {
  lastPrice?: number;
  lastPurchaseDate?: string;
}

type TabType = "overview" | "vendor" | "recipe" | "conversions";

export default function RMDetail() {
  const navigate = useNavigate();
  const { id } = useParams();
  const [rawMaterial, setRawMaterial] = useState<RawMaterial | null>(null);
  const [vendors, setVendors] = useState<VendorWithLastPurchase[]>([]);
  const [allVendors, setAllVendors] = useState<Vendor[]>([]);
  const [vendorPrices, setVendorPrices] = useState<VendorPrice[]>([]);
  const [recipes, setRecipes] = useState<RecipeWithItems[]>([]);
  const [brands, setBrands] = useState<Brand[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const [selectedVendor, setSelectedVendor] =
    useState<VendorWithLastPurchase | null>(null);
  const [vendorPurchaseHistory, setVendorPurchaseHistory] = useState<
    VendorPrice[]
  >([]);
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [showEditForm, setShowEditForm] = useState(false);
  const [editFormData, setEditFormData] = useState({
    name: "",
    categoryId: "",
    subCategoryId: "",
    unitId: "",
    brandId: "",
    hsnCode: "",
  });
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState<"success" | "error">(
    "success",
  );
  const [categories, setCategories] = useState<any[]>([]);
  const [subCategories, setSubCategories] = useState<any[]>([]);
  const [units, setUnits] = useState<any[]>([]);
  const [showAddPriceForm, setShowAddPriceForm] = useState(false);
  const [addPriceFormData, setAddPriceFormData] = useState({
    vendorId: "",
    brandId: "",
    quantity: "",
    price: "",
    billNumber: "",
  });
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deletePassword, setDeletePassword] = useState("");
  const [vendorSearchInput, setVendorSearchInput] = useState("");
  const [showNewBrandInput, setShowNewBrandInput] = useState(false);
  const [newBrandName, setNewBrandName] = useState("");
  const [creatingBrand, setCreatingBrand] = useState(false);
  const [addingPrice, setAddingPrice] = useState(false);
  const [selectedBrandForAdd, setSelectedBrandForAdd] = useState("");
  const [selectedBrands, setSelectedBrands] = useState<Array<{ _id: string; name: string }>>([]);
  const [showAddConversionForm, setShowAddConversionForm] = useState(false);
  const [conversionFormData, setConversionFormData] = useState({
    toUnitId: "",
    conversionFactor: "",
  });
  const [addingConversion, setAddingConversion] = useState(false);

  // Calculate total price whenever quantity or price changes
  const totalPrice =
    addPriceFormData.quantity && addPriceFormData.price
      ? (
          parseFloat(addPriceFormData.quantity) *
          parseFloat(addPriceFormData.price)
        ).toFixed(2)
      : "0.00";

  // Filter vendors based on search input
  const filteredVendors = vendorSearchInput
    ? allVendors.filter((vendor) =>
        vendor.name.toLowerCase().includes(vendorSearchInput.toLowerCase()),
      )
    : allVendors;

  // Load static data once on mount
  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      navigate("/");
      return;
    }
    loadStaticData();
  }, []);

  // Fetch specific raw material data when id changes
  useEffect(() => {
    if (id) {
      fetchAllData();
    }
  }, [id]);

  const fetchAllData = async () => {
    if (!id) return;

    try {
      setLoading(true);

      // Fetch specific raw material directly (not all)
      const response = await fetch(`/api/raw-materials/${id}`);

      if (!response.ok) {
        throw new Error(
          `Failed to fetch raw material: ${response.status} ${response.statusText}`,
        );
      }

      const data = await response.json();

      if (data.success && data.data) {
        setRawMaterial(data.data);
        // Only fetch essential data, not static lookup data
        await Promise.all([
          fetchVendorPrices(id),
          fetchVendorsData(id),
          fetchRecipesUsingRM(id),
        ]);
      } else {
        navigate("/raw-materials");
      }
    } catch (error) {
      console.error("Error fetching raw material:", error);
      navigate("/raw-materials");
    } finally {
      setLoading(false);
    }
  };

  // Optimized: Load static data only once
  const loadStaticData = async () => {
    try {
      await Promise.all([
        fetchCategoriesData(),
        fetchSubCategoriesData(),
        fetchUnitsData(),
        fetchBrandsData(),
      ]);
    } catch (error) {
      console.error("Error loading static data:", error);
    }
  };

  // Partial updates instead of full refetch
  const updateRawMaterialOnly = async () => {
    if (!id) return;
    try {
      const response = await fetch(`/api/raw-materials/${id}`);
      if (!response.ok) return;
      const data = await response.json();
      if (data.success && data.data) {
        setRawMaterial(data.data);
      }
    } catch (error) {
      console.error("Error updating raw material:", error);
    }
  };

  const updateVendorPricesOnly = async () => {
    if (!id) return;
    try {
      await fetchVendorPrices(id);
    } catch (error) {
      console.error("Error updating vendor prices:", error);
    }
  };

  const fetchCategoriesData = async () => {
    try {
      const response = await fetch("/api/categories");
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setCategories(data.data);
      }
    } catch (error) {
      console.error("Error fetching categories:", error);
    }
  };

  const fetchSubCategoriesData = async () => {
    try {
      const response = await fetch("/api/subcategories");
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setSubCategories(data.data);
      }
    } catch (error) {
      console.error("Error fetching subcategories:", error);
    }
  };

  const fetchUnitsData = async () => {
    try {
      const response = await fetch("/api/units");
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setUnits(data.data);
      }
    } catch (error) {
      console.error("Error fetching units:", error);
    }
  };

  const fetchBrandsData = async () => {
    try {
      const response = await fetch("/api/brands");
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setBrands(data.data);
      }
    } catch (error) {
      console.error("Error fetching brands:", error);
    }
  };

  const fetchVendorPrices = async (rmId: string) => {
    try {
      const response = await fetch(`/api/raw-materials/${rmId}/vendor-prices`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setVendorPrices(data.data);
      }
    } catch (error) {
      console.error("Error fetching vendor prices:", error);
    }
  };

  const fetchVendorsData = async (rmId: string) => {
    try {
      const [vendorsRes, pricesRes] = await Promise.all([
        fetch("/api/vendors"),
        fetch(`/api/raw-materials/${rmId}/vendor-prices`),
      ]);

      if (!vendorsRes.ok)
        throw new Error(`Vendors fetch failed: HTTP ${vendorsRes.status}`);
      if (!pricesRes.ok)
        throw new Error(`Prices fetch failed: HTTP ${pricesRes.status}`);

      const vendorsData = await vendorsRes.json();
      const pricesData = await pricesRes.json();

      if (vendorsData.success && Array.isArray(vendorsData.data)) {
        const vendorsList = vendorsData.data as Vendor[];
        const pricesList = pricesData.data as VendorPrice[];

        // Set all vendors for the Add Price dropdown
        setAllVendors(vendorsList);

        // Get unique vendors from pricesList only (show only vendors with actual purchases)
        const uniqueVendors = new Map<string, VendorWithLastPurchase>();

        pricesList.forEach((price) => {
          if (!uniqueVendors.has(price.vendorId)) {
            // Find vendor details from vendorsList
            const vendorDetails = vendorsList.find(
              (v) => v._id === price.vendorId,
            );
            if (vendorDetails) {
              uniqueVendors.set(price.vendorId, {
                ...vendorDetails,
              });
            }
          }
        });

        // Now populate last prices for each vendor
        const vendorsWithPrices = Array.from(uniqueVendors.values()).map(
          (vendor) => {
            const lastPrice = pricesList
              .filter((p) => p.vendorId === vendor._id)
              .sort(
                (a, b) =>
                  new Date(b.addedDate).getTime() -
                  new Date(a.addedDate).getTime(),
              )[0];

            return {
              ...vendor,
              lastPrice: lastPrice?.price,
              lastPurchaseDate: lastPrice?.addedDate,
            };
          },
        );

        setVendors(vendorsWithPrices);
      }
    } catch (error) {
      console.error("Error fetching vendors:", error);
    }
  };

  const fetchRecipesUsingRM = async (rmId: string) => {
    try {
      const response = await fetch("/api/recipes");
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();

      if (data.success && Array.isArray(data.data)) {
        const allRecipes = data.data;

        // Parallelize all recipe item fetches (instead of sequential loop)
        const itemsPromises = allRecipes.map((recipe) =>
          fetch(`/api/recipes/${recipe._id}/items`)
            .then((res) => res.json())
            .catch((err) => {
              console.error(
                `Error fetching items for recipe ${recipe._id}:`,
                err,
              );
              return { success: false, data: [] };
            })
            .then((itemsData) => ({
              recipe,
              items: itemsData.success ? itemsData.data : [],
            }))
        );

        const results = await Promise.all(itemsPromises);

        // Find recipes that use this raw material
        const recipesWithRM: RecipeWithItems[] = results
          .filter(({ items }) => items.length > 0)
          .reduce((acc: RecipeWithItems[], { recipe, items }) => {
            const rmItem = items.find(
              (item: any) => item.rawMaterialId === rmId,
            );
            if (rmItem) {
              acc.push({
                _id: recipe._id,
                code: recipe.code,
                name: recipe.name,
                unitName: recipe.unitName,
                updatedAt: recipe.updatedAt,
                rawMaterialQuantity: rmItem.quantity,
                rawMaterialUnit: rmItem.unitName,
              });
            }
            return acc;
          }, []);

        setRecipes(recipesWithRM);
      }
    } catch (error) {
      console.error("Error fetching recipes:", error);
    }
  };

  const handleVendorClick = (vendor: VendorWithLastPurchase) => {
    setSelectedVendor(vendor);
    const history = vendorPrices.filter((p) => p.vendorId === vendor._id);
    setVendorPurchaseHistory(
      history.sort(
        (a, b) =>
          new Date(b.addedDate).getTime() - new Date(a.addedDate).getTime(),
      ),
    );
  };

  const handleEditClick = () => {
    if (rawMaterial) {
      setEditFormData({
        name: rawMaterial.name,
        categoryId: rawMaterial.categoryId,
        subCategoryId: rawMaterial.subCategoryId,
        unitId: rawMaterial.unitId || "",
        brandId: rawMaterial.brandId || "",
        hsnCode: rawMaterial.hsnCode || "",
      });

      // Initialize selected brands from rawMaterial
      if (rawMaterial.brandIds && rawMaterial.brandIds.length > 0) {
        const selectedBrandList = rawMaterial.brandIds.map((brandId, index) => ({
          _id: brandId,
          name: rawMaterial.brandNames?.[index] || "",
        })).filter(b => b._id && b.name);
        setSelectedBrands(selectedBrandList);
      } else {
        setSelectedBrands([]);
      }

      setShowEditForm(true);
    }
  };

  const handleUpdateRawMaterial = async () => {
    if (!id || !rawMaterial) return;

    if (!editFormData.name.trim()) {
      setMessage("Name is required");
      setMessageType("error");
      return;
    }

    try {
      // Find the unit name if unitId is provided
      const unitName = editFormData.unitId
        ? units.find(u => u._id === editFormData.unitId)?.name || ""
        : "";

      const response = await fetch(`/api/raw-materials/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...editFormData,
          unitName,
          brandIds: selectedBrands.map(b => b._id),
          brandNames: selectedBrands.map(b => b.name),
          changedBy: localStorage.getItem("username") || "admin",
        }),
      });

      if (!response.ok) {
        throw new Error(`Update failed: HTTP ${response.status}`);
      }

      const data = await response.json();
      if (data.success) {
        setMessage("Raw material updated successfully");
        setMessageType("success");
        setShowEditForm(false);
        setSelectedBrands([]);
        // Only update the raw material, not everything
        setTimeout(() => {
          updateRawMaterialOnly();
        }, 500);
      } else {
        setMessage(data.message || "Update failed");
        setMessageType("error");
      }
    } catch (error) {
      console.error("Error updating raw material:", error);
      setMessage("Error updating raw material");
      setMessageType("error");
    }
  };

  const handleCreateNewBrand = async () => {
    if (!newBrandName.trim()) {
      setMessage("Brand name cannot be empty");
      setMessageType("error");
      return;
    }

    setCreatingBrand(true);
    try {
      const response = await fetch("/api/brands", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newBrandName.trim() }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        const newBrand = data.data;
        setBrands([...brands, newBrand]);
        // Add the new brand to the selected brands list
        setSelectedBrands([...selectedBrands, newBrand]);
        setShowNewBrandInput(false);
        setNewBrandName("");
        setMessage("Brand created and added successfully");
        setMessageType("success");
      } else {
        setMessage(data.message || "Failed to create brand");
        setMessageType("error");
      }
    } catch (error) {
      console.error("Error creating brand:", error);
      setMessage("Error creating brand");
      setMessageType("error");
    } finally {
      setCreatingBrand(false);
    }
  };

  const handleDeleteClick = () => {
    setShowDeleteModal(true);
    setDeletePassword("");
  };

  const handleConfirmDelete = async () => {
    if (deletePassword !== "-1") {
      setMessage("Invalid password");
      setMessageType("error");
      return;
    }

    if (!id || !rawMaterial) return;

    try {
      const response = await fetch(`/api/raw-materials/${id}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          changedBy: localStorage.getItem("username") || "admin",
        }),
      });

      if (!response.ok) {
        throw new Error(`Delete failed: HTTP ${response.status}`);
      }

      const data = await response.json();
      if (data.success) {
        setMessage("Raw material deleted successfully");
        setMessageType("success");
        setShowDeleteModal(false);
        setTimeout(() => {
          navigate("/raw-materials");
        }, 500);
      } else {
        setMessage(data.message || "Delete failed");
        setMessageType("error");
      }
    } catch (error) {
      console.error("Error deleting raw material:", error);
      setMessage("Error deleting raw material");
      setMessageType("error");
    }
  };

  const formatDate = (dateString: string) => {
    if (!dateString) return "—";
    const d = new Date(dateString);
    const dd = String(d.getDate()).padStart(2, "0");
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const yyyy = d.getFullYear();
    return `${dd}/${mm}/${yyyy}`;
  };

  const handleAddPrice = async () => {
    // Prevent multiple simultaneous submissions
    if (addingPrice) {
      return;
    }

    if (!id || !addPriceFormData.vendorId) {
      setMessage("Please select a vendor");
      setMessageType("error");
      return;
    }

    if (!addPriceFormData.quantity || !addPriceFormData.price) {
      setMessage("Please enter quantity and price");
      setMessageType("error");
      return;
    }

    // Set adding state FIRST to prevent race conditions
    setAddingPrice(true);

    try {
      const selectedBrand = brands.find((b) => b._id === addPriceFormData.brandId);
      const selectedVendorForPrice = allVendors.find((v) => v._id === addPriceFormData.vendorId);

      const response = await fetch("/api/raw-materials/vendor-price", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rawMaterialId: id,
          vendorId: addPriceFormData.vendorId,
          vendorName: selectedVendorForPrice?.name || "",
          brandId: addPriceFormData.brandId,
          brandName: selectedBrand?.name,
          quantity: parseFloat(addPriceFormData.quantity),
          price: parseFloat(addPriceFormData.price),
          billNumber: addPriceFormData.billNumber,
          createdBy: localStorage.getItem("username") || "admin",
        }),
      });

      if (!response.ok) {
        setAddingPrice(false);
        throw new Error(`Add price failed: HTTP ${response.status}`);
      }

      const data = await response.json();
      if (data.success) {
        setMessage("Price added successfully");
        setMessageType("success");
        // Reset form state immediately
        setShowAddPriceForm(false);
        setAddPriceFormData({
          vendorId: "",
          brandId: "",
          quantity: "",
          price: "",
          billNumber: "",
        });
        setVendorSearchInput("");
        setAddingPrice(false);
        // Only update vendor prices, not everything
        await updateVendorPricesOnly();
        // Also refresh vendor list so new vendor appears
        await fetchVendorsData(id);
      } else {
        setAddingPrice(false);
        setMessage(data.message || "Failed to add price");
        setMessageType("error");
      }
    } catch (error) {
      console.error("Error adding price:", error);
      setAddingPrice(false);
      setMessage("Error adding price");
      setMessageType("error");
    }
  };

  const handleAddConversion = async () => {
    if (!id || !conversionFormData.toUnitId || !conversionFormData.conversionFactor) {
      setMessage("Please fill all conversion fields");
      setMessageType("error");
      return;
    }

    setAddingConversion(true);
    try {
      const toUnit = units.find((u) => u._id === conversionFormData.toUnitId);
      const response = await fetch("/api/raw-materials/unit-conversion/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rawMaterialId: id,
          fromUnitId: rawMaterial?.unitId,
          fromUnitName: rawMaterial?.unitName,
          toUnitId: conversionFormData.toUnitId,
          toUnitName: toUnit?.name,
          conversionFactor: parseFloat(conversionFormData.conversionFactor),
        }),
      });

      if (!response.ok) {
        throw new Error(`Add conversion failed: HTTP ${response.status}`);
      }

      const data = await response.json();
      if (data.success) {
        setMessage("Unit conversion added successfully");
        setMessageType("success");
        setShowAddConversionForm(false);
        setConversionFormData({ toUnitId: "", conversionFactor: "" });
        setAddingConversion(false);
        // Only update raw material (has unit conversions)
        await updateRawMaterialOnly();
      } else {
        setAddingConversion(false);
        setMessage(data.message || "Failed to add conversion");
        setMessageType("error");
      }
    } catch (error) {
      console.error("Error adding conversion:", error);
      setAddingConversion(false);
      setMessage("Error adding unit conversion");
      setMessageType("error");
    }
  };

  const handleDeleteConversion = async (index: number) => {
    if (!id) return;

    if (!window.confirm("Are you sure you want to delete this conversion?")) {
      return;
    }

    try {
      const response = await fetch("/api/raw-materials/unit-conversion/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rawMaterialId: id,
          conversionIndex: index,
        }),
      });

      if (!response.ok) {
        throw new Error(`Delete conversion failed: HTTP ${response.status}`);
      }

      const data = await response.json();
      if (data.success) {
        setMessage("Unit conversion deleted successfully");
        setMessageType("success");
        // Only update raw material
        await updateRawMaterialOnly();
      } else {
        setMessage(data.message || "Failed to delete conversion");
        setMessageType("error");
      }
    } catch (error) {
      console.error("Error deleting conversion:", error);
      setMessage("Error deleting unit conversion");
      setMessageType("error");
    }
  };

  const formatUnit = (u?: string | null) => {
    if (!u) return null;
    const s = u.toLowerCase().trim();
    if (s.includes("kg") || s.includes("kilogram")) return "kg";
    if (s === "g" || s.includes("gram")) return "g";
    if (
      s.includes("lit") ||
      s === "l" ||
      s.includes("ltr") ||
      s.includes("litre")
    )
      return "L";
    if (s.includes("ml")) return "ml";
    if (s.includes("piece") || s.includes("pc") || s === "pcs") return "pcs";
    return u;
  };

  if (loading) {
    return (
      <LoadingSpinner message="Loading raw material..." fullScreen={true} />
    );
  }

  if (!rawMaterial) {
    return (
      <Layout title="Not Found">
        <div className="text-center py-12">
          <p className="text-slate-600 dark:text-slate-400">
            Raw material not found
          </p>
          <button
            onClick={() => navigate("/raw-materials")}
            className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            Back to Raw Materials
          </button>
        </div>
      </Layout>
    );
  }

  if (selectedVendor) {
    return (
      <Layout title={`${selectedVendor.name} - Purchase History`}>
        <div className="space-y-6">
          {/* Header */}
          <div className="flex items-center gap-4 mb-6">
            <button
              onClick={() => setSelectedVendor(null)}
              className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              title="Back to vendor list"
            >
              <ArrowLeft className="w-5 h-5 text-slate-600 dark:text-slate-400" />
            </button>
            <div>
              <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
                {selectedVendor.name}
              </h1>
              <p className="text-slate-500 dark:text-slate-400 mt-1">
                Contact:{" "}
                <span className="font-semibold">
                  {selectedVendor.mobileNumber}
                </span>
              </p>
            </div>
          </div>

          {/* Vendor Info Card */}
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200/50 dark:border-slate-700/50 p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                  Person Name
                </label>
                <p className="text-sm text-slate-900 dark:text-white font-medium">
                  {selectedVendor.personName}
                </p>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                  Mobile Number
                </label>
                <p className="text-sm text-slate-900 dark:text-white font-medium flex items-center gap-2">
                  <Phone className="w-4 h-4" />
                  {selectedVendor.mobileNumber}
                </p>
              </div>
              {selectedVendor.email && (
                <div>
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                    Email
                  </label>
                  <p className="text-sm text-slate-900 dark:text-white font-medium">
                    {selectedVendor.email}
                  </p>
                </div>
              )}
              <div>
                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                  Location
                </label>
                <p className="text-sm text-slate-900 dark:text-white font-medium">
                  {selectedVendor.location}
                </p>
              </div>
            </div>
          </div>

          {/* Purchase History Table */}
          <div className="table-responsive shadow-elevation-4 animate-page-load">
            <div className="bg-white dark:bg-slate-800 border-b-2 border-slate-200 dark:border-slate-700 p-6 flex items-center justify-between">
              <h2 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-blue-700 dark:from-blue-400 dark:to-blue-500 bg-clip-text text-transparent">
                Purchase History - {rawMaterial.name}
              </h2>
              <button
                onClick={() =>
                  setSortOrder(sortOrder === "desc" ? "asc" : "desc")
                }
                className="prof-btn-secondary py-2"
              >
                {sortOrder === "desc" ? (
                  <>
                    <ChevronDown className="w-4 h-4" />
                    New to Old
                  </>
                ) : (
                  <>
                    <ChevronUp className="w-4 h-4" />
                    Old to New
                  </>
                )}
              </button>
            </div>

            {vendorPurchaseHistory.length === 0 ? (
              <div className="text-center py-12 text-slate-500 dark:text-slate-400 p-6 bg-white dark:bg-slate-800">
                <p className="font-bold">No purchase history for this vendor</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[700px]">
                  <thead className="prof-table-head">
                    <tr>
                      <th className="prof-table-head-cell">Purchase Date</th>
                      <th className="prof-table-head-cell">Quantity</th>
                      <th className="prof-table-head-cell">Price</th>
                      <th className="prof-table-head-cell">Total Amount</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {(sortOrder === "desc"
                      ? vendorPurchaseHistory
                      : [...vendorPurchaseHistory].reverse()
                    ).map((purchase, idx) => {
                      const totalAmount = purchase.quantity * purchase.price;
                      return (
                        <tr
                          key={purchase._id}
                          className={cn(
                            "prof-table-row prof-table-row-hover",
                            idx % 2 === 0 && "prof-table-row-even",
                          )}
                        >
                          <td className="prof-table-cell">
                            {formatDate(purchase.addedDate)}
                          </td>
                          <td className="prof-table-cell-bold text-slate-900 dark:text-white">
                            {purchase.quantity} {formatUnit(purchase.unitName)}
                          </td>
                          <td className="prof-table-cell">
                            <span className="prof-badge-green">
                              ₹{purchase.price.toFixed(2)}/
                              {formatUnit(purchase.unitName)}
                            </span>
                          </td>
                          <td className="prof-table-cell-bold text-blue-600 dark:text-blue-400">
                            ₹{totalAmount.toFixed(2)}
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
      </Layout>
    );
  }

  if (showEditForm && rawMaterial) {
    return (
      <Layout title={`Edit - ${rawMaterial.name}`}>
        <div className="space-y-6">
          <div className="flex items-center gap-4 mb-6">
            <button
              onClick={() => {
                setShowEditForm(false);
                setSelectedBrands([]);
              }}
              className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              title="Cancel"
            >
              <ArrowLeft className="w-5 h-5 text-slate-600 dark:text-slate-400" />
            </button>
            <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
              Edit Raw Material
            </h1>
          </div>

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

          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200/50 dark:border-slate-700/50 p-8 space-y-8">
            {/* Basic Information Section */}
            <div className="space-y-5">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                Basic Information
              </h3>

              <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-5 border border-blue-100/50 dark:border-blue-800/20">
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2.5 flex items-center gap-2">
                  <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-xs">⚙</span>
                  Raw Material Name
                </label>
                <input
                  type="text"
                  value={editFormData.name}
                  onChange={(e) =>
                    setEditFormData({ ...editFormData, name: e.target.value })
                  }
                  className="w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all shadow-sm"
                />
              </div>
            </div>

            {/* Classification Section */}
            <div className="space-y-5">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                Classification
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-5 border border-blue-100/50 dark:border-blue-800/20">
                  <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2.5 flex items-center gap-2.5">
                    <span className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-base">📁</span>
                    Category
                  </label>
                  <select
                    value={editFormData.categoryId}
                    onChange={(e) =>
                      setEditFormData({
                        ...editFormData,
                        categoryId: e.target.value,
                        subCategoryId: "",
                      })
                    }
                    className="w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all shadow-sm"
                  >
                    <option value="">Select Category</option>
                    {categories.map((cat) => (
                      <option key={cat._id} value={cat._id}>
                        {cat.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-5 border border-blue-100/50 dark:border-blue-800/20">
                  <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2.5 flex items-center gap-2.5">
                    <span className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-base">🏷</span>
                    Sub Category
                  </label>
                  <select
                    value={editFormData.subCategoryId}
                    onChange={(e) =>
                      setEditFormData({
                        ...editFormData,
                        subCategoryId: e.target.value,
                      })
                    }
                    className="w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all shadow-sm"
                  >
                    <option value="">Select Sub Category</option>
                    {subCategories
                      .filter((sc) => sc.categoryId === editFormData.categoryId)
                      .map((subcat) => (
                        <option key={subcat._id} value={subcat._id}>
                          {subcat.name}
                        </option>
                      ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Unit Section */}
            <div className="space-y-5">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                Unit of Measurement
              </h3>

              <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-5 border border-blue-100/50 dark:border-blue-800/20">
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2.5 flex items-center gap-2.5">
                  <span className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-base">⚖</span>
                  Unit
                </label>
                <select
                  value={editFormData.unitId}
                  onChange={(e) =>
                    setEditFormData({ ...editFormData, unitId: e.target.value })
                  }
                  className="w-full px-4 py-3 rounded-lg bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all shadow-sm"
                >
                  <option value="">Select Unit</option>
                  {units.map((unit) => (
                    <option key={unit._id} value={unit._id}>
                      {unit.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                Brands (Optional - Add Multiple)
              </label>
              {!showNewBrandInput ? (
                <div className="flex gap-2">
                  <select
                    value={selectedBrandForAdd}
                    onChange={(e) => {
                      const brandId = e.target.value;
                      if (brandId) {
                        const brand = brands.find(b => b._id === brandId);
                        if (brand) {
                          setSelectedBrands([...selectedBrands, brand]);
                          setSelectedBrandForAdd("");
                        }
                      }
                    }}
                    className="flex-1 px-4 py-2.5 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors"
                  >
                    <option value="">Select Brand</option>
                    {brands.filter(b => !selectedBrands.find(sb => sb._id === b._id)).map((brand) => (
                      <option key={brand._id} value={brand._id}>
                        {brand.name}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    onClick={() => setShowNewBrandInput(true)}
                    className="px-3 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors flex items-center gap-1.5 text-sm whitespace-nowrap"
                    title="Create new brand"
                  >
                    <Plus className="w-4 h-4" />
                    New
                  </button>
                </div>
              ) : (
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newBrandName}
                    onChange={(e) => setNewBrandName(e.target.value)}
                    placeholder="Enter new brand name"
                    disabled={creatingBrand}
                    className="flex-1 px-4 py-2.5 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors disabled:opacity-50"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      handleCreateNewBrand();
                      setShowNewBrandInput(false);
                    }}
                    disabled={creatingBrand}
                    className="px-4 py-2.5 bg-green-600 hover:bg-green-700 disabled:bg-slate-400 text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
                  >
                    {creatingBrand ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      </>
                    ) : (
                      <Check className="w-4 h-4" />
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowNewBrandInput(false);
                      setNewBrandName("");
                    }}
                    disabled={creatingBrand}
                    className="px-4 py-2.5 bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 font-semibold rounded-lg hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors disabled:opacity-50"
                  >
                    Cancel
                  </button>
                </div>
              )}

              {/* Selected Brands List */}
              {selectedBrands.length > 0 && (
                <div className="mt-4 space-y-2">
                  <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide">
                    Selected Brands ({selectedBrands.length})
                  </p>
                  <div className="space-y-2">
                    {selectedBrands.map((brand) => (
                      <div
                        key={brand._id}
                        onDoubleClick={() => setSelectedBrands(selectedBrands.filter(b => b._id !== brand._id))}
                        className="flex items-center justify-between bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800/30 rounded-lg px-4 py-2.5 cursor-pointer hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-colors"
                      >
                        <span className="text-sm font-medium text-slate-900 dark:text-white">
                          {brand.name}
                        </span>
                        <button
                          type="button"
                          onClick={() => setSelectedBrands(selectedBrands.filter(b => b._id !== brand._id))}
                          className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                HSN Code
              </label>
              <input
                type="text"
                value={editFormData.hsnCode}
                onChange={(e) =>
                  setEditFormData({ ...editFormData, hsnCode: e.target.value })
                }
                className="w-full px-4 py-2.5 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors"
              />
            </div>

            <div className="flex gap-3 pt-4">
              <button
                onClick={handleUpdateRawMaterial}
                className="flex-1 px-4 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
              >
                Save Changes
              </button>
              <button
                onClick={() => setShowEditForm(false)}
                className="flex-1 px-4 py-2.5 bg-slate-200 dark:bg-slate-700 text-slate-900 dark:text-white rounded-lg hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors font-medium"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout title={`${rawMaterial.code} - ${rawMaterial.name}`}>
      <RawMaterialLogs
        isOpen={showLogsModal}
        onClose={() => setShowLogsModal(false)}
        rawMaterialId={id || ""}
        rawMaterialName={rawMaterial.name}
      />

      {/* Delete Password Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-lg max-w-sm w-full p-6 space-y-4">
            <h2 className="text-lg font-bold text-slate-900 dark:text-white">
              Confirm Delete
            </h2>
            <p className="text-slate-600 dark:text-slate-400 text-sm">
              Are you sure you want to delete "{rawMaterial.name}"? This action
              cannot be undone.
            </p>
            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                Enter Password to Confirm
              </label>
              <input
                type="password"
                value={deletePassword}
                onChange={(e) => setDeletePassword(e.target.value)}
                onKeyPress={(e) => {
                  if (e.key === "Enter") {
                    handleConfirmDelete();
                  }
                }}
                placeholder="Enter password"
                className="w-full px-4 py-2.5 rounded-lg bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-red-500 transition-colors"
                autoFocus
              />
            </div>
            <div className="flex gap-3 pt-4">
              <button
                onClick={handleConfirmDelete}
                className="flex-1 px-4 py-2.5 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors font-medium"
              >
                Delete
              </button>
              <button
                onClick={() => {
                  setShowDeleteModal(false);
                  setDeletePassword("");
                }}
                className="flex-1 px-4 py-2.5 bg-slate-200 dark:bg-slate-700 text-slate-900 dark:text-white rounded-lg hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors font-medium"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-6">
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

        {/* Header */}
        <div className="flex items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate("/raw-materials")}
              className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              title="Back to Raw Materials"
            >
              <ArrowLeft className="w-5 h-5 text-slate-600 dark:text-slate-400" />
            </button>
            <div>
              <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
                {rawMaterial.name}
              </h1>
              <p className="text-slate-500 dark:text-slate-400 mt-1">
                Code: <span className="font-semibold">{rawMaterial.code}</span>
              </p>
            </div>
          </div>

          {/* Edit, Logs and Delete Buttons */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleEditClick}
              className="flex items-center gap-2 px-4 py-2.5 bg-blue-50 border border-blue-200 text-blue-700 rounded-lg hover:bg-blue-100 hover:border-blue-300 hover:shadow-md transition-all duration-200 font-semibold text-sm active:scale-95"
            >
              <Edit2 className="w-4 h-4" />
              Edit
            </button>
            <button
              onClick={handleDeleteClick}
              className="flex items-center gap-2 px-4 py-2.5 bg-blue-50 border border-blue-200 text-blue-700 rounded-lg hover:bg-blue-100 hover:border-blue-300 hover:shadow-md transition-all duration-200 font-semibold text-sm active:scale-95"
            >
              <Trash2 className="w-4 h-4" />
              Delete
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200/50 dark:border-slate-700/50 overflow-hidden">
          {/* Tab Navigation */}
          <div className="border-b border-slate-200 dark:border-slate-700">
            <div className="flex overflow-x-auto">
              <button
                onClick={() => setActiveTab("overview")}
                className={`flex-shrink-0 px-6 py-4 text-sm font-medium transition-colors border-b-2 ${
                  activeTab === "overview"
                    ? "border-blue-600 text-blue-600 dark:text-blue-400"
                    : "border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-300"
                }`}
              >
                <Eye className="w-4 h-4 inline mr-2" />
                Overview
              </button>
              <button
                onClick={() => setActiveTab("vendor")}
                className={`flex-shrink-0 px-6 py-4 text-sm font-medium transition-colors border-b-2 ${
                  activeTab === "vendor"
                    ? "border-blue-600 text-blue-600 dark:text-blue-400"
                    : "border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-300"
                }`}
              >
                Vendor
              </button>
              <button
                onClick={() => setActiveTab("recipe")}
                className={`flex-shrink-0 px-6 py-4 text-sm font-medium transition-colors border-b-2 ${
                  activeTab === "recipe"
                    ? "border-blue-600 text-blue-600 dark:text-blue-400"
                    : "border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-300"
                }`}
              >
                <ChefHat className="w-4 h-4 inline mr-2" />
                Recipe
              </button>
              <button
                onClick={() => setActiveTab("conversions")}
                className={`flex-shrink-0 px-6 py-4 text-sm font-medium transition-colors border-b-2 ${
                  activeTab === "conversions"
                    ? "border-blue-600 text-blue-600 dark:text-blue-400"
                    : "border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-300"
                }`}
              >
                ⚖️ Unit Conversions
              </button>
            </div>
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {/* Overview Tab */}
            {activeTab === "overview" && (
              <div className="space-y-8">
                {/* Classification Section */}
                <div className="space-y-4">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                    <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                    Classification
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-4 border border-blue-100/50 dark:border-blue-800/20">
                      <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2.5">
                        <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-lg">📁</span>
                        Category
                      </label>
                      <p className="text-base font-semibold text-slate-900 dark:text-white">
                        {rawMaterial.categoryName}
                      </p>
                    </div>
                    <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-4 border border-blue-100/50 dark:border-blue-800/20">
                      <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2.5">
                        <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-lg">🏷</span>
                        Sub Category
                      </label>
                      <p className="text-base font-semibold text-slate-900 dark:text-white">
                        {rawMaterial.subCategoryName}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Unit & Measurement Section */}
                <div className="space-y-4">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                    <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                    Unit of Measurement
                  </h3>
                  <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-4 border border-blue-100/50 dark:border-blue-800/20">
                    <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2.5">
                      <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-lg">⚖</span>
                      Unit
                    </label>
                    <p className="text-base font-semibold text-slate-900 dark:text-white">
                      {rawMaterial.unitName || "-"}
                    </p>
                  </div>
                </div>

                {/* Brands Section */}
                {(rawMaterial.brandNames && rawMaterial.brandNames.length > 0) || rawMaterial.brandName ? (
                  <div className="space-y-4">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                      Brands
                    </h3>
                    <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-4 border border-blue-100/50 dark:border-blue-800/20">
                      <div className="flex flex-wrap gap-2">
                        {(rawMaterial.brandNames && rawMaterial.brandNames.length > 0)
                          ? rawMaterial.brandNames.map((brand, index) => (
                              <span
                                key={index}
                                className="px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-full text-sm font-semibold shadow-sm"
                              >
                                {brand}
                              </span>
                            ))
                          : (
                              <span className="px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-full text-sm font-semibold shadow-sm">
                                {rawMaterial.brandName}
                              </span>
                            )
                        }
                      </div>
                    </div>
                  </div>
                ) : null}

                {/* Tax & Code Section */}
                {rawMaterial.hsnCode && (
                  <div className="space-y-4">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                      Tax Information
                    </h3>
                    <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-4 border border-blue-100/50 dark:border-blue-800/20">
                      <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2.5">
                        <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-lg">📋</span>
                        HSN Code
                      </label>
                      <p className="text-base font-semibold text-slate-900 dark:text-white font-mono">
                        {rawMaterial.hsnCode}
                      </p>
                    </div>
                  </div>
                )}

                {/* Pricing Section */}
                {(typeof rawMaterial.lastAddedPrice === "number" || rawMaterial.lastPriceDate) && (
                  <div className="space-y-4">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                      Pricing Information
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {typeof rawMaterial.lastAddedPrice === "number" && (
                        <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-4 border border-blue-100/50 dark:border-blue-800/20">
                          <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2.5">
                            <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-lg">💰</span>
                            Last Price
                          </label>
                          <p className="text-lg font-bold text-blue-600 dark:text-blue-400">
                            ₹{rawMaterial.lastAddedPrice.toFixed(2)}
                            {formatUnit(rawMaterial.unitName)
                              ? ` / ${formatUnit(rawMaterial.unitName)}`
                              : ""}
                          </p>
                          {rawMaterial.lastVendorName && (
                            <p className="text-xs text-slate-600 dark:text-slate-400 mt-2 font-medium">
                              From: <span className="text-slate-900 dark:text-white">{rawMaterial.lastVendorName}</span>
                            </p>
                          )}
                        </div>
                      )}
                      {rawMaterial.lastPriceDate && (
                        <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg p-4 border border-blue-100/50 dark:border-blue-800/20">
                          <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2.5">
                            <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 text-lg">📅</span>
                            Last Purchase Date
                          </label>
                          <p className="text-base font-semibold text-slate-900 dark:text-white">
                            {formatDate(rawMaterial.lastPriceDate)}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Vendor Tab */}
            {activeTab === "vendor" && (
              <div className="space-y-8">
                {/* Add Price Section */}
                <div className="space-y-4">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                    <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                    Add Vendor Price
                  </h3>

                  <button
                    onClick={() => {
                      setShowAddPriceForm(!showAddPriceForm);
                      if (showAddPriceForm) {
                        setVendorSearchInput("");
                        setAddPriceFormData({
                          vendorId: "",
                          brandId: "",
                          quantity: "",
                          price: "",
                          billNumber: "",
                        });
                      } else {
                        // Auto-populate brand when opening form
                        setAddPriceFormData({
                          vendorId: "",
                          brandId: rawMaterial?.brandId || "",
                          quantity: "",
                          price: "",
                          billNumber: "",
                        });
                      }
                    }}
                    className="px-6 py-3 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white rounded-lg transition-all shadow-sm hover:shadow-md font-semibold text-sm flex items-center gap-2 active:scale-95"
                  >
                    <span className="text-lg">+</span>
                    {showAddPriceForm ? "Cancel" : "Add Price"}
                  </button>
                </div>

                {/* Add Price Form */}
                {showAddPriceForm && (
                  <div className="bg-gradient-to-br from-blue-50/40 to-blue-50/20 dark:from-blue-900/10 dark:to-blue-900/5 rounded-lg border border-blue-100/50 dark:border-blue-800/20 p-6 space-y-5">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                          Select Vendor
                        </label>
                        <div className="relative space-y-2">
                          <input
                            type="text"
                            placeholder="🔍 Search vendor..."
                            value={vendorSearchInput}
                            onChange={(e) =>
                              setVendorSearchInput(e.target.value)
                            }
                            className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors text-sm placeholder-slate-400"
                          />

                          {/* Auto-suggestions dropdown */}
                          {vendorSearchInput && filteredVendors.length > 0 && (
                            <div className="absolute left-0 right-0 top-[100%] mt-1 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 rounded-lg shadow-lg z-10 max-h-48 overflow-y-auto">
                              {filteredVendors.map((vendor) => (
                                <button
                                  key={vendor._id}
                                  type="button"
                                  onClick={() => {
                                    setAddPriceFormData({
                                      ...addPriceFormData,
                                      vendorId: vendor._id,
                                    });
                                    setVendorSearchInput("");
                                  }}
                                  className="w-full text-left px-4 py-3 hover:bg-blue-50 dark:hover:bg-blue-900/30 transition-colors border-b border-slate-100 dark:border-slate-700 last:border-b-0 text-sm text-slate-900 dark:text-white font-medium"
                                >
                                  {vendor.name}
                                </button>
                              ))}
                            </div>
                          )}

                          {/* No results message */}
                          {vendorSearchInput && filteredVendors.length === 0 && (
                            <div className="absolute left-0 right-0 top-[100%] mt-1 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 rounded-lg shadow-lg z-10 px-4 py-3">
                              <p className="text-sm text-slate-500 dark:text-slate-400 text-center">No vendors found</p>
                            </div>
                          )}

                          {/* Selected vendor display */}
                          {addPriceFormData.vendorId && (
                            <div className="px-3 py-2 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                              <p className="text-xs text-blue-600 dark:text-blue-400 font-medium">
                                Selected: {allVendors.find(v => v._id === addPriceFormData.vendorId)?.name}
                              </p>
                              <button
                                type="button"
                                onClick={() => setAddPriceFormData({
                                  ...addPriceFormData,
                                  vendorId: "",
                                })}
                                className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 mt-1 underline"
                              >
                                Change vendor
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                          Brand (Optional)
                        </label>
                        <select
                          value={addPriceFormData.brandId}
                          onChange={(e) =>
                            setAddPriceFormData({
                              ...addPriceFormData,
                              brandId: e.target.value,
                            })
                          }
                          className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors text-sm"
                        >
                          <option value="">-- Select Brand --</option>
                          {brands
                            .filter((brand) => {
                              const assignedBrandIds = rawMaterial?.brandIds || [];
                              return assignedBrandIds.includes(brand._id);
                            })
                            .map((brand) => (
                              <option key={brand._id} value={brand._id}>
                                {brand.name}
                              </option>
                            ))}
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                          Bill Number (Optional)
                        </label>
                        <input
                          type="text"
                          value={addPriceFormData.billNumber}
                          onChange={(e) =>
                            setAddPriceFormData({
                              ...addPriceFormData,
                              billNumber: e.target.value,
                            })
                          }
                          placeholder="Enter bill number"
                          className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors text-sm"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                          Quantity
                        </label>
                        <input
                          type="number"
                          value={addPriceFormData.quantity}
                          onChange={(e) =>
                            setAddPriceFormData({
                              ...addPriceFormData,
                              quantity: e.target.value,
                            })
                          }
                          placeholder="Qty"
                          className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                          Unit
                        </label>
                        <div className="px-3 py-2 rounded-lg bg-slate-200 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white text-sm flex items-center">
                          {formatUnit(rawMaterial.unitName) || "-"}
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                          Unit Price (₹)
                        </label>
                        <input
                          type="number"
                          value={addPriceFormData.price}
                          onChange={(e) =>
                            setAddPriceFormData({
                              ...addPriceFormData,
                              price: e.target.value,
                            })
                          }
                          placeholder="Price"
                          className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">
                          Total Price (₹)
                        </label>
                        <div className="px-3 py-2 rounded-lg bg-teal-50 dark:bg-teal-900/20 border border-teal-200 dark:border-teal-700 text-teal-700 dark:text-teal-300 font-semibold text-sm flex items-center">
                          {totalPrice}
                        </div>
                      </div>
                    </div>

                    <button
                      onClick={handleAddPrice}
                      disabled={addingPrice}
                      className={`w-full px-4 py-2 rounded-lg font-medium text-sm transition-colors flex items-center justify-center gap-2 ${
                        addingPrice
                          ? "bg-slate-400 text-white cursor-not-allowed"
                          : "bg-green-600 text-white hover:bg-green-700"
                      }`}
                    >
                      {addingPrice ? (
                        <>
                          <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                          Saving...
                        </>
                      ) : (
                        "Save Price"
                      )}
                    </button>
                  </div>
                )}

                {/* Brands Section */}
                {vendorPrices.length > 0 && (
                  <div className="space-y-4">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <div className="w-1 h-4 bg-blue-600 rounded-full"></div>
                      Brands for this Product
                    </h3>
                    <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                      <table className="w-full min-w-[500px]">
                        <thead className="bg-gradient-to-r from-blue-50 to-blue-50/50 dark:from-blue-900/20 dark:to-blue-900/10 border-b border-slate-200 dark:border-slate-700">
                          <tr>
                            <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                              Brand Name
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                              Vendor
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                              Buy Qty
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                              Price/Unit
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                              Date
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                          {vendorPrices.map((price) => (
                            <tr key={price._id} className="hover:bg-slate-50 dark:hover:bg-slate-700/30">
                              <td className="px-6 py-3 text-sm text-slate-900 dark:text-slate-100 font-medium">
                                {price.brandName || "Unbranded"}
                              </td>
                              <td className="px-6 py-3 text-sm text-slate-700 dark:text-slate-300">
                                {price.vendorName}
                              </td>
                              <td className="px-6 py-3 text-sm text-slate-700 dark:text-slate-300 font-semibold">
                                {price.quantity ? `${price.quantity} ${price.unitName || rawMaterial?.unitName || ""}` : "—"}
                              </td>
                              <td className="px-6 py-3 text-sm font-semibold text-blue-600">
                                ₹{price.price}/{price.unitName || rawMaterial?.unitName || "unit"}
                              </td>
                              <td className="px-6 py-3 text-sm text-slate-600 dark:text-slate-400">
                                {new Date(price.addedDate).toLocaleDateString("en-GB")}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Vendors Table */}
                {vendors.length === 0 ? (
                  <div className="text-center py-16 rounded-lg bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-800/50 dark:to-slate-900/50">
                    <p className="text-slate-600 dark:text-slate-400 font-medium">No vendors available for this raw material</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                      <div className="w-1 h-4 bg-indigo-600 rounded-full"></div>
                      Vendor List
                    </h3>
                    <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                      <table className="w-full min-w-[700px]">
                        <thead className="bg-gradient-to-r from-indigo-50 to-indigo-50/50 dark:from-indigo-900/20 dark:to-indigo-900/10 border-b border-slate-200 dark:border-slate-700">
                          <tr>
                            <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                              Vendor Name
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                              Contact Number
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                              Last Purchase Price
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                              Last Purchase Date
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                          {vendors.map((vendor) => (
                            <tr
                              key={vendor._id}
                              onClick={() => handleVendorClick(vendor)}
                              className="hover:bg-indigo-50 dark:hover:bg-indigo-900/10 transition-colors cursor-pointer"
                            >
                              <td className="px-6 py-4 text-sm font-medium text-slate-900 dark:text-white">
                                {vendor.name}
                              </td>
                              <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400 flex items-center gap-2">
                                <Phone className="w-4 h-4" />
                                {vendor.mobileNumber}
                              </td>
                              <td className="px-6 py-4 text-sm font-semibold text-blue-600 dark:text-blue-400">
                                {vendor.lastPrice
                                  ? `₹${vendor.lastPrice.toFixed(2)}/${formatUnit(rawMaterial.unitName)}`
                                  : "-"}
                              </td>
                              <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">
                                {vendor.lastPurchaseDate
                                  ? formatDate(vendor.lastPurchaseDate)
                                  : "-"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Recipe Tab */}
            {activeTab === "recipe" && (
              <div>
                {recipes.length === 0 ? (
                  <div className="text-center py-12 text-slate-500 dark:text-slate-400">
                    <p>This raw material is not used in any recipes yet</p>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[700px]">
                      <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                            Recipe Code
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                            Recipe Name
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                            Proportion / Qty Used
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                            Updated At
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                        {recipes.map((recipe) => (
                          <tr
                            key={recipe._id}
                            className="hover:bg-blue-50 dark:hover:bg-slate-700/30 transition-colors cursor-pointer"
                            onClick={() => navigate(`/recipe/${recipe._id}`)}
                          >
                            <td className="px-6 py-4 text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline">
                              {recipe.code}
                            </td>
                            <td className="px-6 py-4 text-sm text-slate-900 dark:text-white font-medium">
                              {recipe.name}
                            </td>
                            <td className="px-6 py-4 text-sm text-teal-600 dark:text-teal-400 font-semibold">
                              {recipe.rawMaterialQuantity}
                              {recipe.rawMaterialUnit
                                ? ` ${formatUnit(recipe.rawMaterialUnit)}`
                                : ""}
                            </td>
                            <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">
                              {formatDate(recipe.updatedAt)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Unit Conversions Tab */}
            {activeTab === "conversions" && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-bold text-slate-900 dark:text-white">
                    Unit Conversions for {rawMaterial.unitName}
                  </h3>
                  <button
                    onClick={() => setShowAddConversionForm(!showAddConversionForm)}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    Add Conversion
                  </button>
                </div>

                {showAddConversionForm && (
                  <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
                    <h4 className="text-sm font-bold text-slate-900 dark:text-white mb-4">
                      Add Unit Conversion
                    </h4>
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                          Convert to Unit
                        </label>
                        <select
                          value={conversionFormData.toUnitId}
                          onChange={(e) =>
                            setConversionFormData({
                              ...conversionFormData,
                              toUnitId: e.target.value,
                            })
                          }
                          className="w-full px-4 py-2 rounded-lg bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                          <option value="">Select Unit</option>
                          {units
                            .filter((u) => u._id !== rawMaterial.unitId)
                            .map((unit) => (
                              <option key={unit._id} value={unit._id}>
                                {unit.name}
                              </option>
                            ))}
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                          Conversion Factor (1 {rawMaterial.unitName} = ? {units.find(u => u._id === conversionFormData.toUnitId)?.name})
                        </label>
                        <input
                          type="number"
                          step="0.001"
                          min="0"
                          value={conversionFormData.conversionFactor}
                          onChange={(e) =>
                            setConversionFormData({
                              ...conversionFormData,
                              conversionFactor: e.target.value,
                            })
                          }
                          placeholder="e.g., 1000 for L to ML"
                          className="w-full px-4 py-2 rounded-lg bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      <div className="flex gap-2 pt-2">
                        <button
                          onClick={handleAddConversion}
                          disabled={addingConversion || !conversionFormData.toUnitId || !conversionFormData.conversionFactor}
                          className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-400 text-white font-semibold rounded-lg transition-colors"
                        >
                          {addingConversion ? "Adding..." : "Add Conversion"}
                        </button>
                        <button
                          onClick={() => {
                            setShowAddConversionForm(false);
                            setConversionFormData({ toUnitId: "", conversionFactor: "" });
                          }}
                          className="flex-1 px-4 py-2 bg-slate-300 hover:bg-slate-400 dark:bg-slate-600 dark:hover:bg-slate-700 text-slate-900 dark:text-white font-semibold rounded-lg transition-colors"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {rawMaterial.unitConversions && rawMaterial.unitConversions.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[700px]">
                      <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                            From Unit
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                            To Unit
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                            Conversion Factor
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                            Added By
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                            Action
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                        {rawMaterial.unitConversions.map((conversion, idx) => (
                          <tr
                            key={idx}
                            className="hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors"
                          >
                            <td className="px-6 py-4 text-sm font-medium text-slate-900 dark:text-white">
                              {conversion.fromUnitName}
                            </td>
                            <td className="px-6 py-4 text-sm font-medium text-slate-900 dark:text-white">
                              {conversion.toUnitName}
                            </td>
                            <td className="px-6 py-4 text-sm text-blue-600 dark:text-blue-400 font-semibold">
                              1 {conversion.fromUnitName} = {conversion.conversionFactor} {conversion.toUnitName}
                            </td>
                            <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">
                              {conversion.addedBy}
                            </td>
                            <td className="px-6 py-4 text-sm">
                              <button
                                onClick={() => handleDeleteConversion(idx)}
                                className="inline-flex items-center gap-2 px-3 py-1 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40 rounded transition-colors"
                              >
                                <Trash2 className="w-4 h-4" />
                                Delete
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="text-center py-12 text-slate-500 dark:text-slate-400">
                    <p>No unit conversions added yet. Click "Add Conversion" to get started.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}



