import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Check, AlertCircle, Plus } from "lucide-react";
import { Layout } from "@/components/Layout";
import { LoadingSpinner } from "@/components/LoadingSpinner";

interface Category {
  _id: string;
  name: string;
}

interface SubCategory {
  _id: string;
  name: string;
  categoryId: string;
}

interface Unit {
  _id: string;
  name: string;
}

interface Brand {
  _id: string;
  name: string;
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
  hsnCode?: string;
}

export default function CreateRawMaterial() {
  const navigate = useNavigate();
  const { id } = useParams();
  const [categories, setCategories] = useState<Category[]>([]);
  const [subCategories, setSubCategories] = useState<SubCategory[]>([]);
  const [units, setUnits] = useState<Unit[]>([]);
  const [brands, setBrands] = useState<Brand[]>([]);
  const [loading, setLoading] = useState(false);
  const [pageLoading, setPageLoading] = useState(id ? true : false);
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState<"success" | "error" | "">("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [showNewBrandInput, setShowNewBrandInput] = useState(false);
  const [newBrandName, setNewBrandName] = useState("");
  const [creatingBrand, setCreatingBrand] = useState(false);
  const [searchInputs, setSearchInputs] = useState({
    category: "",
    subCategory: "",
    unit: "",
    brand: "",
  });
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    name: "",
    categoryId: "",
    subCategoryId: "",
    unitId: "",
    brandId: "",
    hsnCode: "",
  });

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      navigate("/");
      return;
    }

    Promise.all([
      fetchCategories(),
      fetchSubCategories(),
      fetchUnits(),
      fetchBrands(),
    ]).then(() => {
      if (id) {
        fetchRawMaterial(id);
      } else {
        setPageLoading(false);
      }
    });
  }, [id]);

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
      setMessage("Failed to load categories. Please refresh the page.");
      setMessageType("error");
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
      setMessage("Failed to load sub-categories. Please refresh the page.");
      setMessageType("error");
    }
  };

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
      setMessage("Failed to load units. Please refresh the page.");
      setMessageType("error");
    }
  };

  const fetchBrands = async () => {
    try {
      const response = await fetch("/api/brands");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setBrands(data.data);
      }
    } catch (error) {
      console.error("Error fetching brands:", error);
      setMessage("Failed to load brands. Please refresh the page.");
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
        setFormData({ ...formData, brandId: newBrand._id });
        setShowNewBrandInput(false);
        setNewBrandName("");
        setMessage("Brand created successfully");
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

  const fetchRawMaterial = async (rmId: string) => {
    try {
      const response = await fetch("/api/raw-materials");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        const rm = data.data.find((m: RawMaterial) => m._id === rmId);
        if (rm) {
          setFormData({
            name: rm.name,
            categoryId: rm.categoryId,
            subCategoryId: rm.subCategoryId,
            unitId: rm.unitId || "",
            brandId: rm.brandId || "",
            hsnCode: rm.hsnCode || "",
          });
        } else {
          navigate("/raw-materials");
        }
      }
    } catch (error) {
      console.error("Error fetching raw material:", error);
      navigate("/raw-materials");
    } finally {
      setPageLoading(false);
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = "Raw material name is required";
    }

    if (!formData.categoryId) {
      newErrors.categoryId = "Category is required";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const getFilteredCategories = () => {
    if (!searchInputs.category) return categories;
    return categories.filter((cat) =>
      cat.name.toLowerCase().includes(searchInputs.category.toLowerCase()),
    );
  };

  const getFilteredSubCategories = () => {
    let filtered = subCategories;
    if (formData.categoryId) {
      filtered = filtered.filter((sc) => sc.categoryId === formData.categoryId);
    }
    if (!searchInputs.subCategory) return filtered;
    return filtered.filter((sc) =>
      sc.name.toLowerCase().includes(searchInputs.subCategory.toLowerCase()),
    );
  };

  const getFilteredUnits = () => {
    if (!searchInputs.unit) return units;
    return units.filter((unit) =>
      unit.name.toLowerCase().includes(searchInputs.unit.toLowerCase()),
    );
  };

  const getFilteredBrands = () => {
    if (!searchInputs.brand) return brands;
    return brands.filter((brand) =>
      brand.name.toLowerCase().includes(searchInputs.brand.toLowerCase()),
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setLoading(true);
    setMessage("");

    try {
      const selectedCategory = categories.find(
        (c) => c._id === formData.categoryId,
      );
      const selectedSubCategory = subCategories.find(
        (sc) => sc._id === formData.subCategoryId,
      );
      const selectedUnit = units.find((u) => u._id === formData.unitId);
      const selectedBrand = brands.find((b) => b._id === formData.brandId);

      const method = id ? "PUT" : "POST";
      const url = id ? `/api/raw-materials/${id}` : "/api/raw-materials";

      const response = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: formData.name,
          categoryId: formData.categoryId,
          categoryName: selectedCategory?.name,
          subCategoryId: formData.subCategoryId,
          subCategoryName: selectedSubCategory?.name,
          unitId: formData.unitId,
          unitName: selectedUnit?.name,
          brandId: formData.brandId,
          brandName: selectedBrand?.name,
          hsnCode: formData.hsnCode,
          createdBy: "admin",
        }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage(
          id ? "Raw material updated successfully" : "Raw material created successfully",
        );
        setTimeout(() => {
          navigate("/raw-materials");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Operation failed");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error saving raw material");
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  if (pageLoading) {
    return (
      <Layout title="Loading...">
        <LoadingSpinner message="Loading..." />
      </Layout>
    );
  }

  return (
    <Layout title={id ? "Edit Raw Material" : "Create Raw Material"}>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center gap-4 mb-6">
          <button
            onClick={() => navigate("/raw-materials")}
            className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
            title="Back"
          >
            <ArrowLeft className="w-5 h-5 text-slate-600 dark:text-slate-400" />
          </button>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
            {id ? "Edit Raw Material" : "Add New Raw Material"}
          </h1>
        </div>

        {/* Form Section */}
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200/50 dark:border-slate-700/50 p-8">
          {message && (
            <div
              className={`mb-6 p-4 rounded-lg flex items-center gap-3 ${
                messageType === "success"
                  ? "bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
                  : "bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800"
              }`}
            >
              {messageType === "success" ? (
                <Check className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0" />
              )}
              <span
                className={
                  messageType === "success"
                    ? "text-green-700 dark:text-green-300"
                    : "text-red-700 dark:text-red-300"
                }
              >
                {message}
              </span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Raw Material Name */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Raw Material Name *
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
                placeholder="Enter raw material name"
                className={`w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border transition-all ${
                  errors.name
                    ? "border-red-500 dark:border-red-400"
                    : "border-slate-300 dark:border-slate-600"
                } text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-teal-500`}
              />
              {errors.name && (
                <p className="text-red-600 dark:text-red-400 text-sm mt-1">
                  {errors.name}
                </p>
              )}
            </div>

            {/* Category */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Category *
              </label>
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search or select category"
                  value={
                    openDropdown === "category"
                      ? searchInputs.category
                      : formData.categoryId
                        ? categories.find((c) => c._id === formData.categoryId)?.name || ""
                        : ""
                  }
                  onChange={(e) => {
                    setOpenDropdown("category");
                    setSearchInputs({ ...searchInputs, category: e.target.value });
                  }}
                  onFocus={() => {
                    setOpenDropdown("category");
                    setSearchInputs({ ...searchInputs, category: "" });
                  }}
                  onBlur={() => {
                    setTimeout(() => setOpenDropdown(null), 200);
                  }}
                  className={`w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border transition-all ${
                    errors.categoryId
                      ? "border-red-500 dark:border-red-400"
                      : "border-slate-300 dark:border-slate-600"
                  } text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-teal-500`}
                />
                {openDropdown === "category" && (
                  <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg shadow-lg z-10 max-h-48 overflow-y-auto">
                    {getFilteredCategories().map((cat) => (
                      <div
                        key={cat._id}
                        onClick={() => {
                          setFormData({
                            ...formData,
                            categoryId: cat._id,
                            subCategoryId: "",
                          });
                          setOpenDropdown(null);
                          setSearchInputs({ ...searchInputs, category: "" });
                        }}
                        className="px-4 py-2.5 hover:bg-teal-50 dark:hover:bg-slate-600 cursor-pointer text-slate-900 dark:text-white border-b border-slate-200 dark:border-slate-600 last:border-b-0"
                      >
                        {cat.name}
                      </div>
                    ))}
                    {getFilteredCategories().length === 0 && (
                      <div className="px-4 py-2.5 text-slate-500 dark:text-slate-400 text-center">
                        No categories found
                      </div>
                    )}
                  </div>
                )}
              </div>
              {errors.categoryId && (
                <p className="text-red-600 dark:text-red-400 text-sm mt-1">
                  {errors.categoryId}
                </p>
              )}
            </div>

            {/* Sub Category */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Sub Category (Optional)
              </label>
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search or select sub category"
                  value={
                    openDropdown === "subCategory"
                      ? searchInputs.subCategory
                      : formData.subCategoryId
                        ? subCategories.find((sc) => sc._id === formData.subCategoryId)?.name || ""
                        : ""
                  }
                  onChange={(e) => {
                    if (formData.categoryId) {
                      setOpenDropdown("subCategory");
                      setSearchInputs({ ...searchInputs, subCategory: e.target.value });
                    }
                  }}
                  onFocus={() => {
                    if (formData.categoryId) {
                      setOpenDropdown("subCategory");
                      setSearchInputs({ ...searchInputs, subCategory: "" });
                    }
                  }}
                  onBlur={() => {
                    setTimeout(() => setOpenDropdown(null), 200);
                  }}
                  disabled={!formData.categoryId}
                  className={`w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border transition-all border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-teal-500 disabled:opacity-50 disabled:cursor-not-allowed`}
                />
                {openDropdown === "subCategory" && formData.categoryId && (
                  <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg shadow-lg z-10 max-h-48 overflow-y-auto">
                    {getFilteredSubCategories().map((subcat) => (
                      <div
                        key={subcat._id}
                        onClick={() => {
                          setFormData({
                            ...formData,
                            subCategoryId: subcat._id,
                          });
                          setOpenDropdown(null);
                          setSearchInputs({ ...searchInputs, subCategory: "" });
                        }}
                        className="px-4 py-2.5 hover:bg-teal-50 dark:hover:bg-slate-600 cursor-pointer text-slate-900 dark:text-white border-b border-slate-200 dark:border-slate-600 last:border-b-0"
                      >
                        {subcat.name}
                      </div>
                    ))}
                    {getFilteredSubCategories().length === 0 && (
                      <div className="px-4 py-2.5 text-slate-500 dark:text-slate-400 text-center">
                        No sub categories found
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Unit */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Unit (Optional)
              </label>
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search or select unit"
                  value={
                    openDropdown === "unit"
                      ? searchInputs.unit
                      : formData.unitId
                        ? units.find((u) => u._id === formData.unitId)?.name || ""
                        : ""
                  }
                  onChange={(e) => {
                    setOpenDropdown("unit");
                    setSearchInputs({ ...searchInputs, unit: e.target.value });
                  }}
                  onFocus={() => {
                    setOpenDropdown("unit");
                    setSearchInputs({ ...searchInputs, unit: "" });
                  }}
                  onBlur={() => {
                    setTimeout(() => setOpenDropdown(null), 200);
                  }}
                  className="w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-teal-500"
                />
                {openDropdown === "unit" && (
                  <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg shadow-lg z-10 max-h-48 overflow-y-auto">
                    {getFilteredUnits().map((unit) => (
                      <div
                        key={unit._id}
                        onClick={() => {
                          setFormData({ ...formData, unitId: unit._id });
                          setOpenDropdown(null);
                          setSearchInputs({ ...searchInputs, unit: "" });
                        }}
                        className="px-4 py-2.5 hover:bg-teal-50 dark:hover:bg-slate-600 cursor-pointer text-slate-900 dark:text-white border-b border-slate-200 dark:border-slate-600 last:border-b-0"
                      >
                        {unit.name}
                      </div>
                    ))}
                    {getFilteredUnits().length === 0 && (
                      <div className="px-4 py-2.5 text-slate-500 dark:text-slate-400 text-center">
                        No units found
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Brand */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Brand (Optional)
              </label>
              {!showNewBrandInput ? (
                <div className="flex gap-2">
                  <div className="flex-1 relative">
                    <input
                      type="text"
                      placeholder="Search or select brand"
                      value={
                        openDropdown === "brand"
                          ? searchInputs.brand
                          : formData.brandId
                            ? brands.find((b) => b._id === formData.brandId)?.name || ""
                            : ""
                      }
                      onChange={(e) => {
                        setOpenDropdown("brand");
                        setSearchInputs({ ...searchInputs, brand: e.target.value });
                      }}
                      onFocus={() => {
                        setOpenDropdown("brand");
                        setSearchInputs({ ...searchInputs, brand: "" });
                      }}
                      onBlur={() => {
                        setTimeout(() => setOpenDropdown(null), 200);
                      }}
                      className="w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-teal-500"
                    />
                    {openDropdown === "brand" && (
                      <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg shadow-lg z-10 max-h-48 overflow-y-auto">
                        {getFilteredBrands().map((brand) => (
                          <div
                            key={brand._id}
                            onClick={() => {
                              setFormData({ ...formData, brandId: brand._id });
                              setOpenDropdown(null);
                              setSearchInputs({ ...searchInputs, brand: "" });
                            }}
                            className="px-4 py-2.5 hover:bg-teal-50 dark:hover:bg-slate-600 cursor-pointer text-slate-900 dark:text-white border-b border-slate-200 dark:border-slate-600 last:border-b-0"
                          >
                            {brand.name}
                          </div>
                        ))}
                        {getFilteredBrands().length === 0 && (
                          <div className="px-4 py-2.5 text-slate-500 dark:text-slate-400 text-center">
                            No brands found
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => setShowNewBrandInput(true)}
                    className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
                    title="Create new brand"
                  >
                    <Plus className="w-4 h-4" />
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
                    className="flex-1 px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                  />
                  <button
                    type="button"
                    onClick={handleCreateNewBrand}
                    disabled={creatingBrand}
                    className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-400 text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
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
            </div>

            {/* HSN Code */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                HSN Code (Optional)
              </label>
              <input
                type="text"
                value={formData.hsnCode}
                onChange={(e) =>
                  setFormData({ ...formData, hsnCode: e.target.value })
                }
                placeholder="Enter HSN code"
                className="w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-teal-500"
              />
            </div>

            {/* Buttons */}
            <div className="flex gap-3 pt-4">
              <button
                type="submit"
                disabled={loading}
                className="flex-1 bg-teal-600 hover:bg-teal-700 disabled:bg-slate-400 text-white font-semibold py-2.5 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    <span>Saving...</span>
                  </>
                ) : (
                  <>
                    <Plus className="w-4 h-4" />
                    <span>
                      {id ? "Update Raw Material" : "Create Raw Material"}
                    </span>
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => navigate("/raw-materials")}
                className="px-6 bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 font-semibold py-2.5 rounded-lg hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </Layout>
  );
}



