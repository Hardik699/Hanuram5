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
  X,
  Settings,
  Search,
  History,
  Clock,
  User,
  Star,
} from "lucide-react";
import { Layout } from "@/components/Layout";
import { PageHeader } from "@/components/PageHeader";

interface Unit {
  _id: string;
  name: string;
  shortCode: string;
  createdAt: string;
  createdBy: string;
  editLog?: Array<{
    timestamp: string;
    editedBy: string;
    changes: Record<string, { from: any; to: any }>;
  }>;
}

export default function CreateUnit() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: "",
    shortCode: "",
  });

  const [units, setUnits] = useState<Unit[]>([]);
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

  // Clear all state
  const [showClearModal, setShowClearModal] = useState(false);
  const [clearPassword, setClearPassword] = useState("");

  // Log modal state
  const [logUnit, setLogUnit] = useState<Unit | null>(null);

  // Favourites
  const [favourites, setFavourites] = useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem("unit_favourites");
      return stored ? new Set(JSON.parse(stored)) : new Set();
    } catch { return new Set(); }
  });

  const toggleFavourite = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setFavourites((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      localStorage.setItem("unit_favourites", JSON.stringify([...next]));
      return next;
    });
  };

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      navigate("/");
      return;
    }
    fetchUnits();
  }, []);

  const fetchUnits = async () => {
    try {
      setTableLoading(true);
      const response = await fetch("/api/units");
      const data = await response.json();
      if (data.success) {
        setUnits(data.data);
      }
    } catch (error) {
      console.error("Error fetching units:", error);
    } finally {
      setTableLoading(false);
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = "Unit name is required";
    }

    if (!formData.shortCode.trim()) {
      newErrors.shortCode = "Unit short code is required";
    }

    const isDuplicate = units.some(
      (unit) =>
        unit.name.toLowerCase() === formData.name.toLowerCase() &&
        unit._id !== editingId,
    );
    if (isDuplicate) {
      newErrors.name = "Unit with this name already exists";
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
      const method = editingId ? "PUT" : "POST";
      const url = editingId ? `/api/units/${editingId}` : "/api/units";

      const response = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage(data.message);
        setFormData({ name: "", shortCode: "" });
        setEditingId(null);
        setErrors({});

        setTimeout(() => {
          fetchUnits();
          setMessage("");
          setShowAddForm(false);
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Operation failed");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error saving unit");
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (unit: Unit) => {
    setFormData({
      name: unit.name,
      shortCode: unit.shortCode,
    });
    setEditingId(unit._id);
    setShowAddForm(true);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this unit?")) return;

    try {
      const response = await fetch(`/api/units/${id}`, {
        method: "DELETE",
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("Unit deleted successfully");
        setTimeout(() => {
          fetchUnits();
          setMessage("");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to delete unit");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error deleting unit");
      console.error(error);
    }
  };

  const handleCancel = () => {
    setFormData({ name: "", shortCode: "" });
    setEditingId(null);
    setErrors({});
    setShowAddForm(false);
  };

  const getFilteredUnits = () => {
    const filtered = units.filter((unit) => {
      if (searchTerm && !unit.name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      return true;
    });
    return [...filtered].sort((a, b) => (favourites.has(a._id) ? 0 : 1) - (favourites.has(b._id) ? 0 : 1));
  };

  const filteredUnits = getFilteredUnits();
  const totalPages = Math.ceil(filteredUnits.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedUnits = filteredUnits.slice(startIndex, endIndex);

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
      const response = await fetch("/api/units/clear/all", {
        method: "DELETE",
      });

      const data = await response.json();
      if (data.success) {
        setMessageType("success");
        setMessage(data.message);
        setClearPassword("");
        setTimeout(() => {
          fetchUnits();
          setMessage("");
        }, 1000);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to clear units");
      }
    } catch (error) {
      console.error("Error clearing units:", error);
      setMessageType("error");
      setMessage("Error clearing units");
    }
  };

  const handlePreviousPage = () => {
    if (currentPage > 1) setCurrentPage(currentPage - 1);
  };

  return (
    <Layout title="Units">
      <PageHeader
        title="Unit Management"
        description="Manage measurement units for products"
        breadcrumbs={[{ label: "Unit Management" }]}
        icon={<Settings className="w-6 h-6 text-white" />}
        actions={
          !showAddForm ? (
            <div className="flex items-center gap-2">
              <button
                onClick={handleClearAllClick}
                disabled={units.length === 0}
                className="flex items-center gap-2 bg-red-600 hover:bg-red-700 disabled:bg-slate-300 dark:disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-bold py-2.5 px-5 rounded-xl transition-all shadow-elevation-2 hover:shadow-elevation-4 transform hover:scale-105 hover:-translate-y-0.5"
              >
                <Trash2 className="w-4 h-4" />
                Clear All
              </button>
              <button
                onClick={() => setShowAddForm(true)}
                className="flex items-center gap-2 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-bold py-2.5 px-5 rounded-xl transition-all shadow-elevation-3 hover:shadow-elevation-5 transform hover:scale-105 hover:-translate-y-0.5 whitespace-nowrap text-sm"
              >
                <Plus className="w-4 h-4" />
                <span>Add Unit</span>
              </button>
            </div>
          ) : null
        }
      />
      {showAddForm ? (
        <div className="space-y-6">
          <button
            onClick={handleCancel}
            className="flex items-center gap-2 text-purple-600 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300 font-medium"
          >
            ← Back to List
          </button>

          <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-lg border border-slate-200/50 dark:border-slate-700/50 p-8">
            <div className="mb-8">
              <h2 className="text-3xl font-bold text-gray-900 mb-1">
                {editingId ? "Edit Unit" : "Add New Unit"}
              </h2>
              <p className="text-gray-600">
                {editingId ? "Update unit information" : "Create a new measurement unit"}
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

            <form onSubmit={handleSubmit} className="space-y-7">
              {/* Unit Name Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Unit Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                  placeholder="e.g., Kilogram, Liter, Piece"
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

              {/* Short Code Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Short Code <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.shortCode}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      shortCode: e.target.value.toUpperCase(),
                    })
                  }
                  placeholder="e.g., KG, LTR, PCS"
                  className={`w-full px-4 py-3 rounded-lg bg-white border transition-all text-gray-900 placeholder-gray-400 focus:outline-none font-semibold text-center ${
                    errors.shortCode
                      ? "border-red-500 ring-1 ring-red-500"
                      : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  }`}
                />
                {errors.shortCode && (
                  <p className="text-red-600 text-sm mt-3 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    {errors.shortCode}
                  </p>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex gap-3 pt-6 border-t border-gray-200 mt-8">
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-bold py-3 px-4 rounded-lg transition-all active:scale-95 shadow-sm hover:shadow-md flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Saving...</span>
                    </>
                  ) : (
                    <>
                      <Check className="w-4 h-4" />
                      <span>{editingId ? "Update Unit" : "Create Unit"}</span>
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
        </div>
      ) : (
        <div className="space-y-6">
          {message && (
            <div
              className={`p-4 rounded-lg flex items-start gap-3 border animate-in fade-in slide-in-from-top-2 duration-300 ${
                messageType === "success"
                  ? "bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800/50"
                  : "bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800/50"
              }`}
            >
              {messageType === "success" ? (
                <Check className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
              )}
              <span
                className={
                  messageType === "success"
                    ? "text-green-800 dark:text-green-300 font-medium text-sm"
                    : "text-red-800 dark:text-red-300 font-medium text-sm"
                }
              >
                {message}
              </span>
            </div>
          )}

          {/* Search Section - Modern Design */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-5 flex items-center gap-2">
              <Search className="w-5 h-5 text-blue-600" />
              Search & Filter
            </h3>
            <div className="relative">
              <Search className="absolute left-4 top-3 w-5 h-5 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Find units by name..."
                className="w-full pl-11 pr-4 py-2.5 rounded-lg bg-white border border-gray-300 text-gray-900 placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
              />
            </div>
          </div>

          {/* Units Summary Card */}
          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border border-blue-200 p-6 mb-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-gray-900 mb-1 flex items-center gap-2">
                  <Settings className="w-5 h-5 text-blue-600" />
                  Units
                </h2>
                <p className="text-sm text-gray-600">
                  <span className="font-semibold text-gray-900">
                    {filteredUnits.length}
                  </span>{" "}
                  unit{filteredUnits.length !== 1 ? "s" : ""} found
                </p>
              </div>
            </div>
          </div>

          {/* Units Table - Vendor Style */}
          <div className="bg-white rounded-xl shadow-md border border-gray-200 overflow-hidden">
            {tableLoading ? (
              <div className="flex flex-col items-center justify-center py-16">
                <div className="inline-block w-8 h-8 border-3 border-blue-300 border-t-blue-600 rounded-full animate-spin" />
                <p className="text-gray-600 mt-3 font-medium text-sm">Loading units...</p>
              </div>
            ) : paginatedUnits.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 px-6">
                <Settings className="w-14 h-14 text-gray-300 mb-3" />
                <p className="font-bold text-gray-900 text-base">No units yet</p>
                <p className="text-sm text-gray-500 mt-1">Create your first unit to get started</p>
              </div>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm">
                <table className="w-full min-w-[400px]">
                  {/* Table Header */}
                  <thead className="bg-gradient-to-r from-blue-50 to-slate-50 dark:from-blue-900/30 dark:to-slate-900/30 border-b-2 border-blue-200 dark:border-blue-800 sticky top-0">
                    <tr>
                      <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-widest text-slate-700 dark:text-slate-300">Unit Name</th>
                      <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-widest text-slate-700 dark:text-slate-300">Short Code</th>
                      <th className="px-6 py-4 text-center text-xs font-bold uppercase tracking-widest text-slate-700 dark:text-slate-300">Actions</th>
                    </tr>
                  </thead>

                  {/* Table Body */}
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {paginatedUnits.map((unit, idx) => (
                      <tr
                        key={unit._id}
                        className="hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors duration-150 cursor-pointer group border-l-4 border-l-transparent hover:border-l-blue-500"
                        onClick={() => navigate(`/unit/${unit._id}`)}
                      >
                        {/* Unit Name */}
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 text-white font-bold text-sm flex items-center justify-center transition-all duration-300 group-hover:shadow-lg group-hover:scale-105 flex-shrink-0">
                              {unit.name.substring(0, 1).toUpperCase()}
                            </div>
                            <div className="font-semibold text-slate-900 dark:text-white capitalize-each-word group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                              {unit.name}
                            </div>
                          </div>
                        </td>

                        {/* Short Code */}
                        <td className="px-6 py-4">
                          <span className="font-semibold text-slate-700 dark:text-slate-300 uppercase text-sm bg-slate-100 dark:bg-slate-800 px-3 py-1 rounded-full">
                            {unit.shortCode}
                          </span>
                        </td>

                        {/* Actions */}
                        <td className="px-6 py-4">
                          <div className="flex items-center justify-center gap-2">
                            <button
                              onClick={(e) => { e.stopPropagation(); handleEdit(unit); }}
                              className="inline-flex items-center justify-center p-2 rounded-lg bg-blue-100 dark:bg-blue-900/30 hover:bg-blue-600 text-blue-600 dark:text-blue-400 hover:text-white transition-all active:scale-95 shadow-sm hover:shadow-md"
                              title="Edit"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button
                              onClick={(e) => toggleFavourite(unit._id, e)}
                              className={`inline-flex items-center justify-center p-2 rounded-lg transition-all active:scale-95 shadow-sm hover:shadow-md ${
                                favourites.has(unit._id)
                                  ? "bg-yellow-400 text-white hover:bg-yellow-500"
                                  : "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-500 hover:bg-yellow-400 hover:text-white"
                              }`}
                              title={favourites.has(unit._id) ? "Remove from Favourites" : "Add to Favourites"}
                            >
                              <Star className={`w-4 h-4 ${favourites.has(unit._id) ? "fill-current" : ""}`} />
                            </button>
                            <button
                              onClick={(e) => { e.stopPropagation(); setLogUnit(unit); }}
                              className="inline-flex items-center justify-center p-2 rounded-lg bg-purple-100 dark:bg-purple-900/30 hover:bg-purple-600 text-purple-600 dark:text-purple-400 hover:text-white transition-all active:scale-95 shadow-sm hover:shadow-md"
                              title="View Change Log"
                            >
                              <History className="w-4 h-4" />
                            </button>
                            <button
                              onClick={(e) => { e.stopPropagation(); handleDelete(unit._id); }}
                              className="inline-flex items-center justify-center p-2 rounded-lg bg-red-100 dark:bg-red-900/30 hover:bg-red-600 text-red-600 dark:text-red-400 hover:text-white transition-all active:scale-95 shadow-sm hover:shadow-md"
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
                    {startIndex + 1}–{Math.min(endIndex, filteredUnits.length)}
                  </span>
                  {" "}of{" "}
                  <span className="text-slate-900 dark:text-white">
                    {filteredUnits.length}
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

      {/* Clear All Confirmation Modal */}
      {showClearModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-800 rounded-3xl shadow-2xl max-w-md w-full border border-slate-200/50 dark:border-slate-700/50">
            <div className="p-6 border-b border-slate-200 dark:border-slate-700">
              <div className="flex items-center gap-3 mb-2">
                <AlertCircle className="w-6 h-6 text-red-600 dark:text-red-400" />
                <h3 className="text-2xl font-bold text-slate-900 dark:text-white">
                  Confirm Clear All
                </h3>
              </div>
              <p className="text-sm text-slate-600 dark:text-slate-400 mt-2">
                This will delete ALL units. This action cannot be undone.
              </p>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">
                  Enter password to confirm
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
                  placeholder="Enter password"
                  className="w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border-2 border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-all"
                  autoFocus
                />
              </div>

              <div className="flex items-center gap-3 pt-4">
                <button
                  onClick={() => {
                    setShowClearModal(false);
                    setClearPassword("");
                  }}
                  className="flex-1 px-4 py-2.5 rounded-lg bg-slate-100 dark:bg-slate-700 text-slate-900 dark:text-white font-semibold hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={confirmClearAll}
                  disabled={!clearPassword}
                  className="flex-1 px-4 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 disabled:bg-slate-400 disabled:cursor-not-allowed text-white font-semibold transition-colors"
                >
                  Clear All
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Change Log Modal */}
      {logUnit && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 backdrop-blur-sm" onClick={() => setLogUnit(null)}>
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-lg w-full border border-gray-200 dark:border-slate-700 max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="p-5 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                  <History className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-gray-900 dark:text-white">Change Log</h3>
                  <p className="text-xs text-gray-500 dark:text-slate-400 capitalize">{logUnit.name}</p>
                </div>
              </div>
              <button onClick={() => setLogUnit(null)} className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-500 dark:text-slate-400 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="px-5 py-3 bg-blue-50 dark:bg-blue-900/20 border-b border-blue-100 dark:border-blue-800 flex items-center gap-2 text-xs text-blue-700 dark:text-blue-300">
              <User className="w-3.5 h-3.5" />
              <span>Created by <span className="font-semibold">{logUnit.createdBy || "admin"}</span></span>
              <span className="mx-1">·</span>
              <Clock className="w-3.5 h-3.5" />
              <span>{new Date(logUnit.createdAt).toLocaleString("en-IN", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}</span>
            </div>
            <div className="overflow-y-auto flex-1 p-5">
              {!logUnit.editLog || logUnit.editLog.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-10 text-center">
                  <History className="w-10 h-10 text-gray-300 mb-3" />
                  <p className="text-sm font-semibold text-gray-500 dark:text-slate-400">No changes recorded</p>
                  <p className="text-xs text-gray-400 dark:text-slate-500 mt-1">Edit history will appear here</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {[...logUnit.editLog].reverse().map((entry, idx) => (
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



