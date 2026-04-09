import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Layout } from "@/components/Layout";
import {
  ArrowLeft,
  Edit2,
  Trash2,
  Check,
  AlertCircle,
  FolderOpen,
} from "lucide-react";
import { PageHeader } from "@/components/PageHeader";

interface SubCategory {
  _id: string;
  categoryId: string;
  categoryName: string;
  name: string;
  status: "active" | "inactive";
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

interface Category {
  _id: string;
  name: string;
}

export default function SubCategoryDetail() {
  const navigate = useNavigate();
  const { id } = useParams();
  const [subCategory, setSubCategory] = useState<SubCategory | null>(null);
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);
  const [showEditForm, setShowEditForm] = useState(false);
  const [editFormData, setEditFormData] = useState({
    categoryId: "",
    name: "",
    status: "active" as "active" | "inactive",
  });
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState<"success" | "error">(
    "success",
  );
  const [saveLoading, setSaveLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      navigate("/");
      return;
    }

    if (id) {
      fetchAllData();
    }
  }, [id]);

  const fetchAllData = async () => {
    try {
      setLoading(true);
      const [subResponse, catResponse] = await Promise.all([
        fetch("/api/subcategories"),
        fetch("/api/categories"),
      ]);

      const subData = await subResponse.json();
      const catData = await catResponse.json();

      if (subData.success && Array.isArray(subData.data)) {
        const sub = subData.data.find((s: SubCategory) => s._id === id);
        if (sub) {
          setSubCategory(sub);
          setEditFormData({
            categoryId: sub.categoryId,
            name: sub.name,
            status: sub.status || "active",
          });
        } else {
          navigate("/create-subcategory");
        }
      }

      if (catData.success && Array.isArray(catData.data)) {
        setCategories(catData.data);
      }
    } catch (error) {
      console.error("Error fetching data:", error);
      setMessageType("error");
      setMessage("Failed to load subcategory details");
    } finally {
      setLoading(false);
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};
    if (!editFormData.categoryId) {
      newErrors.categoryId = "Category is required";
    }
    if (!editFormData.name.trim()) {
      newErrors.name = "SubCategory name is required";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSave = async () => {
    if (!validateForm() || !id) return;

    setSaveLoading(true);
    setMessage("");

    try {
      const response = await fetch(`/api/subcategories/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editFormData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("SubCategory updated successfully");
        setShowEditForm(false);
        setTimeout(() => {
          fetchAllData();
          setMessage("");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to update subcategory");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error updating subcategory");
      console.error(error);
    } finally {
      setSaveLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("Are you sure you want to delete this subcategory?") || !id)
      return;

    try {
      const response = await fetch(`/api/subcategories/${id}`, {
        method: "DELETE",
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("SubCategory deleted successfully");
        setTimeout(() => {
          navigate("/create-subcategory");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to delete subcategory");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error deleting subcategory");
      console.error(error);
    }
  };

  const handleCancel = () => {
    if (subCategory) {
      setEditFormData({
        categoryId: subCategory.categoryId,
        name: subCategory.name,
        status: subCategory.status || "active",
      });
    }
    setShowEditForm(false);
    setErrors({});
    setMessage("");
  };

  if (loading) {
    return (
      <Layout title="SubCategory Details">
        <div className="flex items-center justify-center p-8">
          <div className="inline-block w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-gray-600 ml-3">
            Loading subcategory...
          </p>
        </div>
      </Layout>
    );
  }

  if (!subCategory) {
    return (
      <Layout title="SubCategory Not Found">
        <div className="text-center p-8">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-600">
            SubCategory not found
          </p>
          <button
            onClick={() => navigate("/create-subcategory")}
            className="mt-4 text-blue-600 hover:text-blue-700 font-medium"
          >
            Back to SubCategories
          </button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout title="SubCategory Details">
      <div className="space-y-6">
        <PageHeader
          title={subCategory?.name || "SubCategory Details"}
          description={`Category: ${subCategory?.categoryName || "Loading..."}`}
          breadcrumbs={[
            { label: "SubCategories", href: "/create-subcategory" },
            { label: subCategory?.name ? subCategory.name.charAt(0).toUpperCase() + subCategory.name.slice(1) : "Details" },
          ]}
          icon={<FolderOpen className="w-6 h-6 text-white" />}
          showBackButton={true}
          actions={
            !showEditForm ? (
              <div className="flex gap-3">
                <button
                  onClick={() => setShowEditForm(true)}
                  className="inline-flex items-center gap-2 bg-blue-50 border border-blue-200 text-blue-700 font-semibold py-2.5 px-5 rounded-lg hover:bg-blue-100 hover:border-blue-300 hover:shadow-md transition-all duration-200 active:scale-95"
                >
                  <Edit2 className="w-4 h-4" />
                  Edit
                </button>
                <button
                  onClick={handleDelete}
                  className="inline-flex items-center gap-2 bg-blue-50 border border-blue-200 text-blue-700 font-semibold py-2.5 px-5 rounded-lg hover:bg-blue-100 hover:border-blue-300 hover:shadow-md transition-all duration-200 active:scale-95"
                >
                  <Trash2 className="w-4 h-4" />
                  Delete
                </button>
              </div>
            ) : null
          }
        />

        {message && (
          <div
            className={`p-4 rounded-lg flex items-start gap-3 border animate-slide-in-down ${
              messageType === "success"
                ? "bg-emerald-50 border-emerald-200 text-emerald-900"
                : "bg-red-50 border-red-200 text-red-900"
            }`}
          >
            {messageType === "success" ? (
              <Check className="w-5 h-5 text-emerald-600 flex-shrink-0 mt-0.5" />
            ) : (
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
            )}
            <span className="font-medium text-sm">
              {message}
            </span>
          </div>
        )}

        {!showEditForm ? (
          <div className="bg-white rounded-lg shadow-md border border-gray-200 p-8">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Sub Category Name
                </label>
                <p className="text-2xl font-bold text-gray-900 capitalize-each-word">
                  {subCategory.name}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Category
                </label>
                <p className="text-2xl font-bold text-gray-900 capitalize-each-word">
                  {subCategory.categoryName}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Status
                </label>
                <span
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-semibold capitalize-each-word ${
                    subCategory.status === "active"
                      ? "bg-emerald-100 text-emerald-700"
                      : "bg-red-100 text-red-700"
                  }`}
                >
                  <span className={`w-2 h-2 rounded-full ${subCategory.status === "active" ? "bg-emerald-600" : "bg-red-600"}`}></span>
                  {subCategory.status ? subCategory.status.charAt(0).toUpperCase() + subCategory.status.slice(1) : "—"}
                </span>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Created On
                </label>
                <p className="text-gray-900 font-semibold">
                  {new Date(subCategory.createdAt).toLocaleDateString("en-GB")}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Last Updated
                </label>
                <p className="text-gray-900 font-semibold">
                  {new Date(subCategory.updatedAt).toLocaleDateString("en-GB")}
                </p>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-white rounded-lg shadow-md border border-gray-200 p-8 animate-fade-in">
            <div className="mb-8">
              <h2 className="text-3xl font-bold text-gray-900 mb-1">
                Edit Sub Category
              </h2>
              <p className="text-gray-600">
                Update sub category information
              </p>
            </div>

            {message && (
              <div
                className={`mb-6 p-4 rounded-lg flex items-center gap-3 border animate-slide-in-down ${
                  messageType === "success"
                    ? "bg-emerald-50 border-emerald-200 text-emerald-900"
                    : "bg-red-50 border-red-200 text-red-900"
                }`}
              >
                {messageType === "success" ? (
                  <Check className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="font-medium text-sm">
                  {message}
                </span>
              </div>
            )}

            <form className="space-y-7">
              {/* Category Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Category <span className="text-red-500">*</span>
                </label>
                <select
                  value={editFormData.categoryId}
                  onChange={(e) =>
                    setEditFormData({
                      ...editFormData,
                      categoryId: e.target.value,
                    })
                  }
                  className={`w-full px-4 py-3 rounded-lg bg-white border transition-all text-gray-900 placeholder-gray-400 focus:outline-none ${
                    errors.categoryId
                      ? "border-red-500 ring-1 ring-red-500"
                      : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  }`}
                >
                  <option value="">Select a category</option>
                  {categories.map((cat) => (
                    <option key={cat._id} value={cat._id}>
                      {cat.name}
                    </option>
                  ))}
                </select>
                {errors.categoryId && (
                  <p className="text-red-600 text-sm mt-3 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    {errors.categoryId}
                  </p>
                )}
              </div>

              {/* SubCategory Name Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Sub Category Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={editFormData.name}
                  onChange={(e) =>
                    setEditFormData({ ...editFormData, name: e.target.value })
                  }
                  placeholder="e.g., Electronics Accessories..."
                  autoCapitalize="words"
                  className={`w-full px-4 py-3 rounded-lg bg-white border transition-all capitalize-each-word text-gray-900 placeholder-gray-400 focus:outline-none ${
                    errors.name
                      ? "border-red-500 ring-1 ring-red-500"
                      : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  }`}
                />
                {errors.name && (
                  <p className="text-red-600 text-sm mt-3 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    {errors.name}
                  </p>
                )}
              </div>

              {/* Status Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Status <span className="text-red-500">*</span>
                </label>
                <select
                  value={editFormData.status}
                  onChange={(e) =>
                    setEditFormData({
                      ...editFormData,
                      status: e.target.value as "active" | "inactive",
                    })
                  }
                  className="w-full px-4 py-3 rounded-lg bg-white border border-gray-300 text-gray-900 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                >
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-3 pt-6 border-t border-gray-200 mt-8">
                <button
                  type="button"
                  onClick={handleSave}
                  disabled={saveLoading}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-bold py-3 px-4 rounded-lg transition-all active:scale-95 shadow-sm hover:shadow-md flex items-center justify-center gap-2"
                >
                  {saveLoading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Saving...</span>
                    </>
                  ) : (
                    <>
                      <Check className="w-4 h-4" />
                      <span>Save Changes</span>
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={handleCancel}
                  className="px-8 bg-gray-100 hover:bg-gray-200 text-gray-700 font-semibold py-3 rounded-lg transition-all"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}
      </div>
    </Layout>
  );
}




