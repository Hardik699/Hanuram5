import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  Trash2,
  Plus,
  Mail,
  Phone,
  MapPin,
  Building2,
  ChevronLeft,
  ChevronRight,
  Check,
  AlertCircle,
  Search,
  Edit2,
  History,
  Clock,
  User,
  X,
  Star,
} from "lucide-react";
import { Layout } from "@/components/Layout";
import { PageHeader } from "@/components/PageHeader";

interface Vendor {
  _id: string;
  name: string;
  personName: string;
  mobileNumber: string;
  email: string;
  location: string;
  gstNumber?: string;
  createdAt: string;
  createdBy: string;
  editLog?: Array<{
    timestamp: string;
    editedBy: string;
    changes: Record<string, { from: any; to: any }>;
  }>;
}

export default function CreateVendor() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: "",
    personName: "",
    mobileNumber: "",
    email: "",
    location: "",
    gstNumber: "",
  });

  const [vendors, setVendors] = useState<Vendor[]>([]);
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

  // Log modal state
  const [logVendor, setLogVendor] = useState<Vendor | null>(null);

  // Favourites
  const [favourites, setFavourites] = useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem("vendor_favourites");
      return stored ? new Set(JSON.parse(stored)) : new Set();
    } catch { return new Set(); }
  });

  const toggleFavourite = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setFavourites((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      localStorage.setItem("vendor_favourites", JSON.stringify([...next]));
      return next;
    });
  };

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      navigate("/");
      return;
    }
    fetchVendors();
  }, []);

  const fetchVendors = async () => {
    try {
      setTableLoading(true);
      const response = await fetch("/api/vendors");
      const data = await response.json();
      if (data.success) {
        setVendors(data.data);
      }
    } catch (error) {
      console.error("Error fetching vendors:", error);
    } finally {
      setTableLoading(false);
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = "Vendor name is required";
    }

    if (!formData.personName.trim()) {
      newErrors.personName = "Person name is required";
    }

    if (!formData.location.trim()) {
      newErrors.location = "Location/Address is required";
    }

    if (formData.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = "Invalid email address";
    }

    const isDuplicate = vendors.some(
      (vendor) =>
        vendor.name.toLowerCase() === formData.name.toLowerCase() &&
        vendor._id !== editingId,
    );
    if (isDuplicate) {
      newErrors.name = "Vendor with this name already exists";
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
      const url = editingId ? `/api/vendors/${editingId}` : "/api/vendors";

      const response = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage(data.message);
        setFormData({
          name: "",
          personName: "",
          mobileNumber: "",
          email: "",
          location: "",
          gstNumber: "",
        });
        setEditingId(null);
        setErrors({});

        setTimeout(() => {
          fetchVendors();
          setMessage("");
          setShowAddForm(false);
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Operation failed");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error saving vendor");
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (vendor: Vendor) => {
    setFormData({
      name: vendor.name,
      personName: vendor.personName,
      mobileNumber: vendor.mobileNumber,
      email: vendor.email,
      location: vendor.location,
      gstNumber: vendor.gstNumber || "",
    });
    setEditingId(vendor._id);
    setShowAddForm(true);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this vendor?")) return;

    try {
      const response = await fetch(`/api/vendors/${id}`, {
        method: "DELETE",
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("Vendor deleted successfully");
        setTimeout(() => {
          fetchVendors();
          setMessage("");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to delete vendor");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error deleting vendor");
      console.error(error);
    }
  };

  const handleCancel = () => {
    setFormData({
      name: "",
      personName: "",
      mobileNumber: "",
      email: "",
      location: "",
      gstNumber: "",
    });
    setEditingId(null);
    setErrors({});
    setShowAddForm(false);
  };

  const getFilteredVendors = () => {
    const filtered = vendors.filter((vendor) => {
      if (
        searchTerm &&
        !vendor.name.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !vendor.personName.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !vendor.location.toLowerCase().includes(searchTerm.toLowerCase())
      ) return false;
      return true;
    });
    return [...filtered].sort((a, b) => (favourites.has(a._id) ? 0 : 1) - (favourites.has(b._id) ? 0 : 1));
  };

  const filteredVendors = getFilteredVendors();
  const totalPages = Math.ceil(filteredVendors.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedVendors = filteredVendors.slice(startIndex, endIndex);

  const handleItemsPerPageChange = (value: string) => {
    setItemsPerPage(parseInt(value));
    setCurrentPage(1);
  };

  const handleNextPage = () => {
    if (currentPage < totalPages) setCurrentPage(currentPage + 1);
  };

  const handlePreviousPage = () => {
    if (currentPage > 1) setCurrentPage(currentPage - 1);
  };

  return (
    <Layout title="Vendors">
      <PageHeader
        title="Vendor Management"
        description="Create, manage, and organize vendors and suppliers"
        breadcrumbs={[{ label: "Vendor Management" }]}
        icon={<Building2 className="w-6 h-6 text-white" />}
        actions={
          !showAddForm ? (
            <div className="flex items-center gap-3">
              <button
                onClick={handleCancel}
                disabled={vendors.length === 0}
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
                <span>Add Vendor</span>
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
                {editingId ? "Edit Vendor" : "Add New Vendor"}
              </h2>
              <p className="text-gray-600">
                {editingId
                  ? "Update vendor information and details"
                  : "Create a new vendor/supplier profile"}
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
              {/* Vendor Name Field */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2.5">
                  Vendor Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                  placeholder="e.g., ABC Supply Co..."
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

              {/* Contact Person Field */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2.5">
                  Contact Person <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.personName}
                  onChange={(e) =>
                    setFormData({ ...formData, personName: e.target.value })
                  }
                  placeholder="e.g., John Doe..."
                  autoCapitalize="words"
                  className={`w-full px-4 py-3 rounded-lg bg-white border transition-all capitalize-each-word ${
                    errors.personName
                      ? "border-red-500 ring-1 ring-red-500"
                      : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  } text-gray-900 placeholder-gray-500 focus:outline-none`}
                />
                {errors.personName && (
                  <p className="text-red-600 text-sm mt-2 flex items-center gap-1">
                    <AlertCircle className="w-4 h-4" />
                    {errors.personName}
                  </p>
                )}
              </div>

              {/* Mobile Number Field */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2.5">
                  Mobile Number
                </label>
                <div className="relative">
                  <Phone className="absolute left-3 top-3.5 w-4 h-4 text-gray-400" />
                  <input
                    type="tel"
                    value={formData.mobileNumber}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        mobileNumber: e.target.value,
                      })
                    }
                    placeholder="Enter mobile number"
                    className="w-full pl-10 pr-4 py-3 rounded-lg bg-white border border-gray-300 text-gray-900 placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                  />
                </div>
              </div>

              {/* Email Field */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2.5">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-3.5 w-4 h-4 text-gray-400" />
                  <input
                    type="email"
                    value={formData.email}
                    onChange={(e) =>
                      setFormData({ ...formData, email: e.target.value })
                    }
                    placeholder="Enter email address"
                    className={`w-full pl-10 pr-4 py-3 rounded-lg bg-white border transition-all ${
                      errors.email
                        ? "border-red-500 ring-1 ring-red-500"
                        : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                    } text-gray-900 placeholder-gray-500 focus:outline-none`}
                  />
                </div>
                {errors.email && (
                  <p className="text-red-600 text-sm mt-2 flex items-center gap-1">
                    <AlertCircle className="w-4 h-4" />
                    {errors.email}
                  </p>
                )}
              </div>

              {/* Location Field */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2.5">
                  Location / Address <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <MapPin className="absolute left-3 top-3.5 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    value={formData.location}
                    onChange={(e) =>
                      setFormData({ ...formData, location: e.target.value })
                    }
                    placeholder="Enter full address"
                    autoCapitalize="words"
                    className={`w-full pl-10 pr-4 py-3 rounded-lg bg-white border transition-all capitalize-each-word ${
                      errors.location
                        ? "border-red-500 ring-1 ring-red-500"
                        : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                    } text-gray-900 placeholder-gray-500 focus:outline-none`}
                  />
                </div>
                {errors.location && (
                  <p className="text-red-600 text-sm mt-2 flex items-center gap-1">
                    <AlertCircle className="w-4 h-4" />
                    {errors.location}
                  </p>
                )}
              </div>

              {/* GST Number Field */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2.5">
                  GST Number <span className="text-gray-400 font-normal">(Optional)</span>
                </label>
                <input
                  type="text"
                  value={formData.gstNumber}
                  onChange={(e) =>
                    setFormData({ ...formData, gstNumber: e.target.value })
                  }
                  placeholder="Enter GST number"
                  className="w-full px-4 py-3 rounded-lg bg-white border border-gray-300 text-gray-900 placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                />
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
                        {editingId ? "Update Vendor" : "Create Vendor"}
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

          {/* Filter Section */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-5 flex items-center gap-2">
              <Search className="w-5 h-5 text-blue-600" />
              Search & Filter
            </h3>
            <div className="relative">
              <Search className="absolute left-3 top-3 w-5 h-5 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Find vendors by name, person, or location..."
                className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-white border border-gray-300 text-gray-900 placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
              />
            </div>
          </div>

          {/* Vendors Summary Card */}
          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border border-blue-200 p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-gray-900 mb-1 flex items-center gap-2">
                  <Building2 className="w-5 h-5 text-blue-600" />
                  Vendors
                </h2>
                <p className="text-sm text-gray-600">
                  <span className="font-semibold text-gray-900">
                    {filteredVendors.length}
                  </span>{" "}
                  vendor{filteredVendors.length !== 1 ? "s" : ""} found
                </p>
              </div>
            </div>
          </div>

          {/* Vendors Table */}
          <div className="bg-white rounded-xl shadow-md border border-gray-200 overflow-hidden">
            {tableLoading ? (
              <div className="flex flex-col items-center justify-center py-16">
                <div className="inline-block w-8 h-8 border-3 border-blue-300 border-t-blue-600 rounded-full animate-spin" />
                <p className="text-gray-600 mt-3 font-medium text-sm">Loading vendors...</p>
              </div>
            ) : paginatedVendors.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 px-6">
                <Building2 className="w-14 h-14 text-gray-300 mb-3" />
                <p className="font-bold text-gray-900 text-base">No vendors yet</p>
                <p className="text-sm text-gray-500 mt-1">Create your first vendor to get started</p>
              </div>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm">
                <table className="w-full min-w-[650px]">
                  {/* Table Header */}
                  <thead className="bg-gradient-to-r from-blue-50 to-slate-50 dark:from-blue-900/30 dark:to-slate-900/30 border-b-2 border-blue-200 dark:border-blue-800 sticky top-0">
                    <tr>
                      <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-widest text-slate-700 dark:text-slate-300">Vendor Name</th>
                      <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-widest text-slate-700 dark:text-slate-300">Mobile</th>
                      <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-widest text-slate-700 dark:text-slate-300">Email</th>
                      {paginatedVendors.some(v => v.gstNumber) && (
                        <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-widest text-slate-700 dark:text-slate-300">GST</th>
                      )}
                      <th className="px-6 py-4 text-center text-xs font-bold uppercase tracking-widest text-slate-700 dark:text-slate-300">Actions</th>
                    </tr>
                  </thead>

                  {/* Table Body */}
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {paginatedVendors.map((vendor, idx) => (
                      <tr
                        key={vendor._id}
                        className="hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors duration-150 cursor-pointer group border-l-4 border-l-transparent hover:border-l-blue-500"
                        onClick={() => navigate(`/vendor/${vendor._id}`)}
                      >
                        {/* Vendor Name */}
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 text-white font-bold text-sm flex items-center justify-center transition-all duration-300 group-hover:shadow-lg group-hover:scale-105 flex-shrink-0">
                              {vendor.name.substring(0, 1).toUpperCase()}
                            </div>
                            <div className="font-semibold text-slate-900 dark:text-white capitalize-each-word group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                              {vendor.name}
                            </div>
                          </div>
                        </td>

                        {/* Mobile */}
                        <td className="px-6 py-4">
                          {vendor.mobileNumber ? (
                            <a
                              href={`tel:${vendor.mobileNumber}`}
                              onClick={(e) => e.stopPropagation()}
                              className="font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
                            >
                              {vendor.mobileNumber}
                            </a>
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </td>

                        {/* Email */}
                        <td className="px-6 py-4">
                          {vendor.email ? (
                            <a
                              href={`mailto:${vendor.email}`}
                              onClick={(e) => e.stopPropagation()}
                              className="font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors truncate max-w-xs block"
                              title={vendor.email}
                            >
                              {vendor.email}
                            </a>
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </td>

                        {/* GST */}
                        {paginatedVendors.some(v => v.gstNumber) && (
                          <td className="px-6 py-4">
                            <span className="font-semibold text-slate-900 dark:text-white">
                              {vendor.gstNumber || "—"}
                            </span>
                          </td>
                        )}

                        {/* Actions */}
                        <td className="px-6 py-4">
                          <div className="flex items-center justify-center gap-2">
                            <button
                              onClick={(e) => { e.stopPropagation(); handleEdit(vendor); }}
                              className="inline-flex items-center justify-center p-2 rounded-lg bg-blue-100 dark:bg-blue-900/30 hover:bg-blue-600 text-blue-600 dark:text-blue-400 hover:text-white transition-all active:scale-95 shadow-sm hover:shadow-md"
                              title="Edit"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button
                              onClick={(e) => toggleFavourite(vendor._id, e)}
                              className={`inline-flex items-center justify-center p-2 rounded-lg transition-all active:scale-95 shadow-sm hover:shadow-md ${
                                favourites.has(vendor._id)
                                  ? "bg-yellow-400 text-white hover:bg-yellow-500"
                                  : "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-500 hover:bg-yellow-400 hover:text-white"
                              }`}
                              title={favourites.has(vendor._id) ? "Remove from Favourites" : "Add to Favourites"}
                            >
                              <Star className={`w-4 h-4 ${favourites.has(vendor._id) ? "fill-current" : ""}`} />
                            </button>
                            <button
                              onClick={(e) => { e.stopPropagation(); setLogVendor(vendor); }}
                              className="inline-flex items-center justify-center p-2 rounded-lg bg-purple-100 dark:bg-purple-900/30 hover:bg-purple-600 text-purple-600 dark:text-purple-400 hover:text-white transition-all active:scale-95 shadow-sm hover:shadow-md"
                              title="View Change Log"
                            >
                              <History className="w-4 h-4" />
                            </button>
                            <button
                              onClick={(e) => { e.stopPropagation(); handleDelete(vendor._id); }}
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
                    {startIndex + 1}–{Math.min(endIndex, filteredVendors.length)}
                  </span>
                  {" "}of{" "}
                  <span className="text-slate-900 dark:text-white">
                    {filteredVendors.length}
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

      {/* Change Log Modal */}
      {logVendor && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 backdrop-blur-sm" onClick={() => setLogVendor(null)}>
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-lg w-full border border-gray-200 dark:border-slate-700 max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="p-5 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                  <History className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-gray-900 dark:text-white">Change Log</h3>
                  <p className="text-xs text-gray-500 dark:text-slate-400 capitalize">{logVendor.name}</p>
                </div>
              </div>
              <button onClick={() => setLogVendor(null)} className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-500 dark:text-slate-400 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="px-5 py-3 bg-blue-50 dark:bg-blue-900/20 border-b border-blue-100 dark:border-blue-800 flex items-center gap-2 text-xs text-blue-700 dark:text-blue-300">
              <User className="w-3.5 h-3.5" />
              <span>Created by <span className="font-semibold">{logVendor.createdBy || "admin"}</span></span>
              <span className="mx-1">·</span>
              <Clock className="w-3.5 h-3.5" />
              <span>{new Date(logVendor.createdAt).toLocaleString("en-IN", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}</span>
            </div>
            <div className="overflow-y-auto flex-1 p-5">
              {!logVendor.editLog || logVendor.editLog.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-10 text-center">
                  <History className="w-10 h-10 text-gray-300 mb-3" />
                  <p className="text-sm font-semibold text-gray-500 dark:text-slate-400">No changes recorded</p>
                  <p className="text-xs text-gray-400 dark:text-slate-500 mt-1">Edit history will appear here</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {[...logVendor.editLog].reverse().map((entry, idx) => (
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



