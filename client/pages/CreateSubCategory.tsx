import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Edit2,
  Trash2,
  Check,
  AlertCircle,
  Plus,
  ChevronLeft,
  ChevronRight,
  FolderOpen,
  Search,
  History,
  Clock,
  User,
  X,
  Star,
} from "lucide-react";
import { Layout } from "@/components/Layout";
import { PageHeader } from "@/components/PageHeader";

interface Category {
  _id: string;
  name: string;
}

interface SubCategory {
  _id: string;
  categoryId: string;
  categoryName: string;
  name: string;
  status: "active" | "inactive";
  createdAt: string;
  createdBy: string;
  editLog?: Array<{
    timestamp: string;
    editedBy: string;
    changes: Record<string, { from: any; to: any }>;
  }>;
}

export default function CreateSubCategory() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState<{
    categoryId: string;
    name: string;
    status: "active" | "inactive";
  }>({
    categoryId: "",
    name: "",
    status: "active",
  });

  const [categories, setCategories] = useState<Category[]>([]);
  const [subcategories, setSubcategories] = useState<SubCategory[]>([]);
  const [loading, setLoading] = useState(false);
  const [tableLoading, setTableLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState<"success" | "error" | "">("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [showAddForm, setShowAddForm] = useState(false);

  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterStatus, setFilterStatus] = useState<"" | "active" | "inactive">("");

  // Clear all state
  const [showClearModal, setShowClearModal] = useState(false);
  const [clearPassword, setClearPassword] = useState("");

  // Log modal state
  const [logSubCategory, setLogSubCategory] = useState<SubCategory | null>(null);

  // Favourites
  const [favourites, setFavourites] = useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem("subcategory_favourites");
      return stored ? new Set(JSON.parse(stored)) : new Set();
    } catch { return new Set(); }
  });

  const toggleFavourite = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setFavourites((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      localStorage.setItem("subcategory_favourites", JSON.stringify([...next]));
      return next;
    });
  };

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      navigate("/");
      return;
    }
    fetchCategories();
    fetchSubcategories();
  }, []);

  const fetchCategories = async () => {
    try {
      const response = await fetch("/api/categories");
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setCategories(data.data);
      }
    } catch (error) {
      console.error("Error fetching categories:", error);
    }
  };

  const fetchSubcategories = async () => {
    try {
      setTableLoading(true);
      const response = await fetch("/api/subcategories");
      const data = await response.json();
      if (data.success && Array.isArray(data.data)) {
        setSubcategories(data.data);
      }
    } catch (error) {
      console.error("Error fetching subcategories:", error);
    } finally {
      setTableLoading(false);
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};
    if (!formData.categoryId) {
      newErrors.categoryId = "Category is required";
    }
    if (!formData.name.trim()) {
      newErrors.name = "Sub Category name is required";
    }
    const isDuplicate = subcategories.some(
      (sub) =>
        sub.name.toLowerCase() === formData.name.toLowerCase() &&
        sub._id !== editingId,
    );
    if (isDuplicate) {
      newErrors.name = "Sub Category with this name already exists";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;

    setLoading(true);
    setMessage("");

    try {
      const method = editingId ? "PUT" : "POST";
      const url = editingId
        ? `/api/subcategories/${editingId}`
        : "/api/subcategories";

      const response = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage(data.message);
        setFormData({ categoryId: "", name: "", status: "active" });
        setEditingId(null);
        setErrors({});

        setTimeout(() => {
          fetchSubcategories();
          setMessage("");
          setShowAddForm(false);
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Operation failed");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error saving sub category");
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (subcategory: SubCategory) => {
    setFormData({
      categoryId: subcategory.categoryId,
      name: subcategory.name,
      status: subcategory.status,
    });
    setEditingId(subcategory._id);
    setShowAddForm(true);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this sub category?")) return;

    try {
      const response = await fetch(`/api/subcategories/${id}`, {
        method: "DELETE",
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("Sub Category deleted successfully");
        setTimeout(() => {
          fetchSubcategories();
          setMessage("");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to delete sub category");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error deleting sub category");
      console.error(error);
    }
  };

  const handleCancel = () => {
    setFormData({ categoryId: "", name: "", status: "active" });
    setEditingId(null);
    setErrors({});
    setShowAddForm(false);
  };

  const getFilteredSubcategories = () => {
    const filtered = subcategories.filter((sub) => {
      if (searchTerm && !sub.name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      if (filterStatus && sub.status !== filterStatus) return false;
      return true;
    });
    return [...filtered].sort((a, b) => (favourites.has(a._id) ? 0 : 1) - (favourites.has(b._id) ? 0 : 1));
  };

  const filteredSubcategories = getFilteredSubcategories();
  const totalPages = Math.ceil(filteredSubcategories.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedSubcategories = filteredSubcategories.slice(
    startIndex,
    endIndex,
  );

  const handleItemsPerPageChange = (value: string) => {
    setItemsPerPage(parseInt(value));
    setCurrentPage(1);
  };

  const handleNextPage = () => {
    if (currentPage < totalPages) setCurrentPage(currentPage + 1);
  };

  const handleClearAllClick = () => {
    setShowClearModal(true);
    setClearPassword("");
  };

  const confirmClearAll = async () => {
    const CLEAR_PASSWORD = "1212";

    if (clearPassword !== CLEAR_PASSWORD) {
      setMessageType("error");
      setMessage("Incorrect password");
      return;
    }

    setShowClearModal(false);

    try {
      const response = await fetch("/api/subcategories/clear/all", {
        method: "DELETE",
      });

      const data = await response.json();
      if (data.success) {
        setMessageType("success");
        setMessage(data.message);
        setClearPassword("");
        setTimeout(() => {
          fetchSubcategories();
          setMessage("");
        }, 1000);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to clear subcategories");
      }
    } catch (error) {
      console.error("Error clearing subcategories:", error);
      setMessageType("error");
      setMessage("Error clearing subcategories");
    }
  };

  const handlePreviousPage = () => {
    if (currentPage > 1) setCurrentPage(currentPage - 1);
  };

  return (
    <Layout title="Sub Categories">
      <PageHeader
        title="Sub Category Management"
        description="Create, manage, and organize product sub categories"
        breadcrumbs={[{ label: "Sub Category Management" }]}
        icon={<FolderOpen className="w-6 h-6 text-white" />}
        actions={
          !showAddForm ? (
            <div className="flex items-center gap-3">
              <button
                onClick={handleClearAllClick}
                disabled={subcategories.length === 0}
                className="inline-flex items-center gap-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-semibold py-2.5 px-5 rounded-lg transition-all active:scale-95 disabled:opacity-50 shadow-sm hover:shadow-md"
              >
                <Trash2 className="w-4 h-4" />
                Clear All
              </button>
              <button
                onClick={() => setShowAddForm(true)}
                className="inline-flex items-center gap-2 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-bold py-2.5 px-6 rounded-lg transition-all shadow-md hover:shadow-lg active:scale-95 whitespace-nowrap text-sm"
              >
                <Plus className="w-4 h-4" />
                <span>Add Sub Category</span>
              </button>
            </div>
          ) : null
        }
      />

      {showAddForm ? (
        <div className="space-y-6 animate-fade-in">
          <button
            onClick={handleCancel}
            className="inline-flex items-center gap-2 text-blue-600 hover:text-blue-700 font-medium transition-colors group"
          >
            <ChevronLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
            Back to List
          </button>

          <div className="bg-white rounded-xl shadow-md border border-gray-200 p-8">
            <div className="mb-8">
              <h2 className="text-3xl font-bold text-gray-900 mb-2">
                {editingId ? "Edit Sub Category" : "Create New Sub Category"}
              </h2>
              <p className="text-gray-600">
                {editingId
                  ? "Update sub category information and settings"
                  : "Add a new sub category to organize your products"}
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

            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2.5">
                  Select Category <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.categoryId}
                  onChange={(e) =>
                    setFormData({ ...formData, categoryId: e.target.value })
                  }
                  className={`w-full px-4 py-3 rounded-lg bg-white border transition-all ${
                    errors.categoryId
                      ? "border-red-500 ring-1 ring-red-500"
                      : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  } text-gray-900 placeholder-gray-500 focus:outline-none`}
                >
                  <option value="">Choose a category</option>
                  {categories.map((cat) => (
                    <option key={cat._id} value={cat._id}>
                      {cat.name}
                    </option>
                  ))}
                </select>
                {errors.categoryId && (
                  <p className="text-red-600 text-sm mt-2 flex items-center gap-1">
                    <AlertCircle className="w-4 h-4" />
                    {errors.categoryId}
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2.5">
                  Sub Category Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                  placeholder="e.g., Electronics Accessories..."
                  autoCapitalize="words"
                  className={`w-full px-4 py-3 rounded-lg bg-white border transition-all capitalize-each-word ${
                    errors.name
                      ? "border-red-500 ring-1 ring-red-500"
                      : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  } text-gray-900 placeholder-gray-500 focus:outline-none`}
                />
                {errors.name && (
                  <p className="text-red-600 text-sm mt-2 flex items-center gap-1">
                    <AlertCircle className="w-4 h-4" />
                    {errors.name}
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2.5">
                  Status <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.status}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      status: e.target.value as "active" | "inactive",
                    })
                  }
                  className="w-full px-4 py-3 rounded-lg bg-white border border-gray-300 text-gray-900 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                >
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>

              <div className="flex gap-3 pt-6 border-t border-gray-200">
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-semibold py-3 px-4 rounded-lg transition-all active:scale-95 shadow-sm hover:shadow-md flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Saving...</span>
                    </>
                  ) : (
                    <>
                      <Check className="w-4 h-4" />
                      <span>
                        {editingId ? "Update Sub Category" : "Create Sub Category"}
                      </span>
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={handleCancel}
                  className="px-6 bg-gray-100 hover:bg-gray-200 text-gray-700 font-semibold py-3 rounded-lg transition-all"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : (
        <div className="space-y-6 animate-fade-in">
          {message && (
            <div
              className={`p-4 rounded-lg flex items-start gap-3 border ${
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

          {/* Filter Section - Modern Design */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-5 flex items-center gap-2">
              <Search className="w-5 h-5 text-blue-600" />
              Search & Filter
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Search Sub Categories
                </label>
                <div className="relative">
                  <Search className="absolute left-3 top-3 w-5 h-5 text-gray-400" />
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={(e) => {
                      setSearchTerm(e.target.value);
                      setCurrentPage(1);
                    }}
                    placeholder="Find sub categories..."
                    className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-white border border-gray-300 text-gray-900 placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Filter by Status
                </label>
                <select
                  value={filterStatus}
                  onChange={(e) => {
                    setFilterStatus(
                      e.target.value as "" | "active" | "inactive",
                    );
                    setCurrentPage(1);
                  }}
                  className="w-full px-4 py-2.5 rounded-lg bg-white border border-gray-300 text-gray-900 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                >
                  <option value="">All Status</option>
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>
            </div>
          </div>

          {/* Sub Categories Summary Card */}
          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border border-blue-200 p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-gray-900 mb-1 flex items-center gap-2">
                  <FolderOpen className="w-5 h-5 text-blue-600" />
                  Sub Categories
                </h2>
                <p className="text-sm text-gray-600">
                  <span className="font-semibold text-gray-900">
                    {filteredSubcategories.length}
                  </span>{" "}
                  sub categor{filteredSubcategories.length !== 1 ? "ies" : "y"} found
                </p>
              </div>
            </div>
          </div>

          {/* Sub Categories Grid - Light & Modern Design */}
          {/* Sub Categories Table - Vendor Style */}
          <div className="bg-white rounded-xl shadow-md border border-gray-200 overflow-hidden">
            {tableLoading ? (
              <div className="flex flex-col items-center justify-center py-16">
                <div className="inline-block w-8 h-8 border-3 border-blue-300 border-t-blue-600 rounded-full animate-spin" />
                <p className="text-gray-600 mt-3 font-medium text-sm">Loading sub categories...</p>
              </div>
            ) : paginatedSubcategories.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 px-6">
                <FolderOpen className="w-14 h-14 text-gray-300 mb-3" />
                <p className="font-bold text-gray-900 text-base">No sub categories yet</p>
                <p className="text-sm text-gray-500 mt-1">Create your first sub category to get started</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[580px]">
                  {/* Table Header */}
                  <thead className="bg-gradient-to-r from-slate-900 via-blue-800 to-slate-900 text-white sticky top-0 border-b-4 border-blue-500">
                    <tr>
                      <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-widest text-blue-100">Sub Category Name</th>
                      <th className="hidden sm:table-cell px-6 py-4 text-left text-xs font-bold uppercase tracking-widest text-blue-100">Category</th>
                      <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-widest text-blue-100">Status</th>
                      <th className="px-6 py-4 text-center text-xs font-bold uppercase tracking-widest text-blue-100">Actions</th>
                    </tr>
                  </thead>

                  {/* Table Body */}
                  <tbody className="divide-y divide-gray-200">
                    {paginatedSubcategories.map((subcategory, idx) => (
                      <tr
                        key={subcategory._id}
                        className={`hover:bg-blue-50 transition-colors duration-200 ${
                          idx % 2 === 0 ? "bg-white" : "bg-gray-50"
                        } cursor-pointer group`}
                        onClick={() => navigate(`/subcategory/${subcategory._id}`)}
                      >
                        {/* Sub Category Name */}
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 text-white font-bold text-sm flex items-center justify-center transition-all duration-300 group-hover:shadow-md group-hover:scale-110 flex-shrink-0">
                              {subcategory.name.substring(0, 1).toUpperCase()}
                            </div>
                            <div className="font-bold text-gray-900 capitalize-each-word group-hover:text-blue-600 transition-colors">
                              {subcategory.name}
                            </div>
                          </div>
                        </td>

                        {/* Category */}
                        <td className="hidden sm:table-cell px-6 py-4">
                          <span className="text-sm text-gray-600 capitalize-each-word">
                            {subcategory.categoryName || "—"}
                          </span>
                        </td>

                        {/* Status */}
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold ${
                              (subcategory.status || "active") === "active"
                                ? "bg-emerald-100 text-emerald-700"
                                : "bg-red-100 text-red-700"
                            }`}
                          >
                            <span className={`w-2 h-2 rounded-full ${(subcategory.status || "active") === "active" ? "bg-emerald-600" : "bg-red-600"}`}></span>
                            {((subcategory.status || "active").charAt(0).toUpperCase() + (subcategory.status || "active").slice(1))}
                          </span>
                        </td>

                        {/* Actions */}
                        <td className="px-6 py-4">
                          <div className="flex items-center justify-center gap-2">
                            <button
                              onClick={(e) => { e.stopPropagation(); handleEdit(subcategory); }}
                              className="inline-flex items-center justify-center p-2 rounded-lg bg-blue-100 hover:bg-blue-600 text-blue-600 hover:text-white transition-all active:scale-95"
                              title="Edit"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button
                              onClick={(e) => toggleFavourite(subcategory._id, e)}
                              className={`inline-flex items-center justify-center p-2 rounded-lg transition-all active:scale-95 ${
                                favourites.has(subcategory._id)
                                  ? "bg-yellow-400 text-white hover:bg-yellow-500"
                                  : "bg-yellow-100 text-yellow-500 hover:bg-yellow-400 hover:text-white"
                              }`}
                              title={favourites.has(subcategory._id) ? "Remove from Favourites" : "Add to Favourites"}
                            >
                              <Star className={`w-4 h-4 ${favourites.has(subcategory._id) ? "fill-current" : ""}`} />
                            </button>
                            <button
                              onClick={(e) => { e.stopPropagation(); setLogSubCategory(subcategory); }}
                              className="inline-flex items-center justify-center p-2 rounded-lg bg-purple-100 hover:bg-purple-600 text-purple-600 hover:text-white transition-all active:scale-95"
                              title="View Change Log"
                            >
                              <History className="w-4 h-4" />
                            </button>
                            <button
                              onClick={(e) => { e.stopPropagation(); handleDelete(subcategory._id); }}
                              className="inline-flex items-center justify-center p-2 rounded-lg bg-red-100 hover:bg-red-600 text-red-600 hover:text-white transition-all active:scale-95"
                              title="Delete"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination Controls */}
            <div className="mt-8 p-6 bg-gradient-to-r from-slate-50 to-blue-50 dark:from-slate-900/50 dark:to-blue-900/20 rounded-xl border border-slate-200 dark:border-slate-700 flex items-center justify-between flex-wrap gap-6">
              <div className="flex items-center gap-4">
                <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                  Items per page:
                </span>
                <select
                  value={itemsPerPage}
                  onChange={(e) => handleItemsPerPageChange(e.target.value)}
                  className="px-4 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 text-sm font-medium text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/50 transition-all hover:border-blue-400 dark:hover:border-blue-500 cursor-pointer"
                >
                  <option value="10">10</option>
                  <option value="20">20</option>
                  <option value="30">30</option>
                </select>
              </div>

              <div className="flex items-center gap-6">
                <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                  <span className="text-blue-600 dark:text-blue-400">
                    {startIndex + 1}–{Math.min(endIndex, filteredSubcategories.length)}
                  </span>
                  {" "}of{" "}
                  <span className="text-slate-900 dark:text-white">
                    {filteredSubcategories.length}
                  </span>
                </span>
                <div className="flex items-center gap-2 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-1">
                  <button
                    onClick={handlePreviousPage}
                    disabled={currentPage === 1}
                    className="inline-flex items-center justify-center p-2 rounded-md text-slate-700 dark:text-slate-300 hover:bg-blue-100 dark:hover:bg-blue-900/30 hover:text-blue-600 dark:hover:text-blue-400 disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:bg-transparent transition-all"
                    title="Previous Page"
                  >
                    <ChevronLeft className="w-5 h-5" />
                  </button>
                  <span className="text-sm font-bold text-slate-900 dark:text-white min-w-[50px] text-center px-2 py-1 bg-slate-100 dark:bg-slate-700/50 rounded">
                    {currentPage} / {totalPages || 1}
                  </span>
                  <button
                    onClick={handleNextPage}
                    disabled={currentPage === totalPages || totalPages === 0}
                    className="inline-flex items-center justify-center p-2 rounded-md text-slate-700 dark:text-slate-300 hover:bg-blue-100 dark:hover:bg-blue-900/30 hover:text-blue-600 dark:hover:text-blue-400 disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:bg-transparent transition-all"
                    title="Next Page"
                  >
                    <ChevronRight className="w-5 h-5" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Clear All Confirmation Modal - Modern Design */}
      {showClearModal && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-white rounded-xl shadow-2xl max-w-md w-full border border-gray-200 animate-slide-in-up">
            <div className="p-6 border-b border-gray-200 bg-red-50">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-lg bg-red-100 flex items-center justify-center">
                  <AlertCircle className="w-6 h-6 text-red-600" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-gray-900">
                    Confirm Clear All
                  </h3>
                  <p className="text-sm text-red-700 mt-1">This action cannot be undone</p>
                </div>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <p className="text-sm text-gray-600">
                Enter the password to delete ALL sub categories permanently. This will remove all sub category data from the system.
              </p>

              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">
                  Password
                </label>
                <input
                  type="password"
                  value={clearPassword}
                  onChange={(e) => setClearPassword(e.target.value)}
                  onKeyPress={(e) => {
                    if (e.key === "Enter") {
                      confirmClearAll();
                    }
                  }}
                  placeholder="••••••••"
                  className="w-full px-4 py-2.5 rounded-lg bg-white border border-gray-300 text-gray-900 placeholder-gray-500 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500 transition-all"
                  autoFocus
                />
              </div>

              <div className="flex items-center gap-3 pt-2 border-t border-gray-200">
                <button
                  onClick={() => {
                    setShowClearModal(false);
                    setClearPassword("");
                  }}
                  className="flex-1 px-4 py-2.5 rounded-lg bg-gray-100 hover:bg-gray-200 text-gray-700 font-semibold transition-all"
                >
                  Cancel
                </button>
                <button
                  onClick={confirmClearAll}
                  disabled={!clearPassword}
                  className="flex-1 px-4 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-semibold transition-all active:scale-95"
                >
                  Delete All
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Change Log Modal */}
      {logSubCategory && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 backdrop-blur-sm" onClick={() => setLogSubCategory(null)}>
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-lg w-full border border-gray-200 dark:border-slate-700 max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="p-5 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                  <History className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-gray-900 dark:text-white">Change Log</h3>
                  <p className="text-xs text-gray-500 dark:text-slate-400 capitalize">{logSubCategory.name}</p>
                </div>
              </div>
              <button onClick={() => setLogSubCategory(null)} className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-500 dark:text-slate-400 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="px-5 py-3 bg-blue-50 dark:bg-blue-900/20 border-b border-blue-100 dark:border-blue-800 flex items-center gap-2 text-xs text-blue-700 dark:text-blue-300">
              <User className="w-3.5 h-3.5" />
              <span>Created by <span className="font-semibold">{logSubCategory.createdBy || "admin"}</span></span>
              <span className="mx-1">·</span>
              <Clock className="w-3.5 h-3.5" />
              <span>{new Date(logSubCategory.createdAt).toLocaleString("en-IN", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}</span>
            </div>
            <div className="overflow-y-auto flex-1 p-5">
              {!logSubCategory.editLog || logSubCategory.editLog.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-10 text-center">
                  <History className="w-10 h-10 text-gray-300 mb-3" />
                  <p className="text-sm font-semibold text-gray-500 dark:text-slate-400">No changes recorded</p>
                  <p className="text-xs text-gray-400 dark:text-slate-500 mt-1">Edit history will appear here</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {[...logSubCategory.editLog].reverse().map((entry, idx) => (
                    <div key={idx} className="border border-gray-200 dark:border-slate-700 rounded-lg p-4 bg-gray-50 dark:bg-slate-900/50">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="w-7 h-7 rounded-full bg-purple-100 dark:bg-purple-900/40 flex items-center justify-center text-xs font-bold text-purple-600 dark:text-purple-400">
                          {(entry.editedBy || "?")[0].toUpperCase()}
                        </div>
                        <div className="flex-1 min-w-0">
                          <span className="text-sm font-semibold text-gray-800 dark:text-white">{entry.editedBy || "admin"}</span>
                          <div className="flex items-center gap-1 text-xs text-gray-500 dark:text-slate-400 mt-0.5">
                            <Clock className="w-3 h-3" />
                            {new Date(entry.timestamp).toLocaleString("en-IN", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                          </div>
                        </div>
                      </div>
                      {Object.keys(entry.changes).length === 0 ? (
                        <p className="text-xs text-gray-400 italic">No field changes recorded</p>
                      ) : (
                        <div className="space-y-2">
                          {Object.entries(entry.changes).map(([field, val]) => (
                            <div key={field} className="text-xs">
                              <span className="font-semibold text-gray-600 dark:text-slate-300 capitalize">{field}:</span>
                              <div className="flex items-center gap-2 mt-1 flex-wrap">
                                <span className="bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 px-2 py-0.5 rounded line-through">{String(val.from ?? "—")}</span>
                                <span className="text-gray-400">→</span>
                                <span className="bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 px-2 py-0.5 rounded">{String(val.to ?? "—")}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}




