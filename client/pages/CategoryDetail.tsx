import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Layout } from "@/components/Layout";
import {
  ArrowLeft,
  Edit2,
  Trash2,
  Check,
  AlertCircle,
  Plus,
  Folder,
} from "lucide-react";
import { PageHeader } from "@/components/PageHeader";

interface Category {
  _id: string;
  name: string;
  description: string;
  status: "active" | "inactive";
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export default function CategoryDetail() {
  const navigate = useNavigate();
  const { id } = useParams();
  const [category, setCategory] = useState<Category | null>(null);
  const [loading, setLoading] = useState(true);
  const [showEditForm, setShowEditForm] = useState(false);
  const [editFormData, setEditFormData] = useState({
    name: "",
    description: "",
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
      fetchCategory();
    }
  }, [id]);

  const fetchCategory = async () => {
    try {
      setLoading(true);
      const response = await fetch("/api/categories");
      const data = await response.json();

      if (data.success && Array.isArray(data.data)) {
        const cat = data.data.find((c: Category) => c._id === id);
        if (cat) {
          setCategory(cat);
          setEditFormData({
            name: cat.name,
            description: cat.description,
            status: cat.status || "active",
          });
        } else {
          navigate("/create-category");
        }
      }
    } catch (error) {
      console.error("Error fetching category:", error);
      setMessageType("error");
      setMessage("Failed to load category details");
    } finally {
      setLoading(false);
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};
    if (!editFormData.name.trim()) {
      newErrors.name = "Category name is required";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSave = async () => {
    if (!validateForm() || !id) return;

    setSaveLoading(true);
    setMessage("");

    try {
      const response = await fetch(`/api/categories/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editFormData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("Category updated successfully");
        setShowEditForm(false);
        setTimeout(() => {
          fetchCategory();
          setMessage("");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to update category");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error updating category");
      console.error(error);
    } finally {
      setSaveLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("Are you sure you want to delete this category?") || !id)
      return;

    try {
      const response = await fetch(`/api/categories/${id}`, {
        method: "DELETE",
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("Category deleted successfully");
        setTimeout(() => {
          navigate("/create-category");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to delete category");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error deleting category");
      console.error(error);
    }
  };

  const handleCancel = () => {
    if (category) {
      setEditFormData({
        name: category.name,
        description: category.description,
        status: category.status || "active",
      });
    }
    setShowEditForm(false);
    setErrors({});
    setMessage("");
  };

  if (loading) {
    return (
      <Layout title="Category Details">
        <div className="flex items-center justify-center p-8">
          <div className="inline-block w-8 h-8 border-4 border-teal-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-600 dark:text-slate-400 ml-3">
            Loading category...
          </p>
        </div>
      </Layout>
    );
  }

  if (!category) {
    return (
      <Layout title="Category Not Found">
        <div className="text-center p-8">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-slate-600 dark:text-slate-400">
            Category not found
          </p>
          <button
            onClick={() => navigate("/create-category")}
            className="mt-4 text-teal-600 hover:text-teal-700 dark:text-teal-400 font-medium"
          >
            Back to Categories
          </button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout title="Category Details">
      <div className="space-y-6 animate-fade-in">
        <PageHeader
          title={category?.name ? category.name.split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()).join(' ') : "Category Details"}
          description={category?.description || "View and manage category information"}
          breadcrumbs={[
            { label: "Categories", href: "/create-category" },
            { label: category?.name || "Details" },
          ]}
          icon={<Folder className="w-6 h-6 text-white" />}
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
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200 hover:shadow-md transition-shadow">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">
                  Category Name
                </label>
                <p className="text-2xl font-bold text-gray-900 capitalize-each-word">
                  {category.name}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200 hover:shadow-md transition-shadow">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">
                  Status
                </label>
                <span
                  className={`inline-flex px-4 py-2 rounded-lg text-sm font-bold capitalize-each-word ${
                    (category.status || "active") === "active"
                      ? "bg-emerald-100 text-emerald-700"
                      : "bg-red-100 text-red-700"
                  }`}
                >
                  {(category.status || "active").charAt(0).toUpperCase() +
                    (category.status || "active").slice(1)}
                </span>
              </div>

              <div className="md:col-span-2 p-6 rounded-lg bg-gray-50 border border-gray-200 hover:shadow-md transition-shadow">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">
                  Description
                </label>
                <p className="text-gray-700 leading-relaxed capitalize-each-word">
                  {category.description || <span className="text-gray-400">No description provided</span>}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200 hover:shadow-md transition-shadow">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">
                  Created By
                </label>
                <p className="text-gray-900 font-semibold capitalize-each-word">
                  {category.createdBy}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200 hover:shadow-md transition-shadow">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">
                  Created On
                </label>
                <p className="text-gray-900 font-semibold">
                  {new Date(category.createdAt).toLocaleDateString("en-GB")}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200 hover:shadow-md transition-shadow">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">
                  Last Updated
                </label>
                <p className="text-gray-900 font-semibold">
                  {new Date(category.updatedAt).toLocaleDateString("en-GB")}
                </p>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-white rounded-lg shadow-md border border-gray-200 p-8 animate-fade-in">
            <div className="mb-8">
              <h2 className="text-3xl font-bold text-gray-900 mb-1">
                Edit Category
              </h2>
              <p className="text-gray-600">
                Update the category information below
              </p>
            </div>

            <form className="space-y-7">
              {/* Category Name Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Category Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={editFormData.name}
                  onChange={(e) =>
                    setEditFormData({ ...editFormData, name: e.target.value })
                  }
                  autoCapitalize="words"
                  placeholder="Enter category name"
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

              {/* Description Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Description <span className="text-gray-400 font-normal text-xs">(Optional)</span>
                </label>
                <textarea
                  value={editFormData.description}
                  onChange={(e) =>
                    setEditFormData({
                      ...editFormData,
                      description: e.target.value,
                    })
                  }
                  placeholder="Add details about this category..."
                  rows={4}
                  autoCapitalize="words"
                  className="w-full px-4 py-3 rounded-lg bg-white border border-gray-300 text-gray-900 placeholder-gray-400 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all resize-none capitalize-each-word"
                />
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
                  className="w-full px-4 py-3 rounded-lg bg-white border border-gray-300 text-gray-900 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all font-medium"
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




