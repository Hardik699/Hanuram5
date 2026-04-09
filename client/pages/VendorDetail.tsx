import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Layout } from "@/components/Layout";
import {
  ArrowLeft,
  Edit2,
  Trash2,
  Check,
  AlertCircle,
  Mail,
  Phone,
  MapPin,
  User,
  Building2,
} from "lucide-react";
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
  updatedAt: string;
  createdBy: string;
}

export default function VendorDetail() {
  const navigate = useNavigate();
  const { id } = useParams();
  const [vendor, setVendor] = useState<Vendor | null>(null);
  const [loading, setLoading] = useState(true);
  const [showEditForm, setShowEditForm] = useState(false);
  const [editFormData, setEditFormData] = useState({
    name: "",
    personName: "",
    mobileNumber: "",
    email: "",
    location: "",
    gstNumber: "",
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
      fetchVendor();
    }
  }, [id]);

  const fetchVendor = async () => {
    try {
      setLoading(true);
      const response = await fetch("/api/vendors");
      const data = await response.json();

      if (data.success && Array.isArray(data.data)) {
        const v = data.data.find((v: Vendor) => v._id === id);
        if (v) {
          setVendor(v);
          setEditFormData({
            name: v.name,
            personName: v.personName,
            mobileNumber: v.mobileNumber,
            email: v.email,
            location: v.location,
            gstNumber: v.gstNumber || "",
          });
        } else {
          navigate("/create-vendor");
        }
      }
    } catch (error) {
      console.error("Error fetching vendor:", error);
      setMessageType("error");
      setMessage("Failed to load vendor details");
    } finally {
      setLoading(false);
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};
    if (!editFormData.name.trim()) {
      newErrors.name = "Vendor name is required";
    }
    if (!editFormData.personName.trim()) {
      newErrors.personName = "Contact person name is required";
    }
    if (!editFormData.location.trim()) {
      newErrors.location = "Location is required";
    }
    if (editFormData.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(editFormData.email)) {
      newErrors.email = "Invalid email address";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSave = async () => {
    if (!validateForm() || !id) return;

    setSaveLoading(true);
    setMessage("");

    try {
      const response = await fetch(`/api/vendors/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editFormData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("Vendor updated successfully");
        setShowEditForm(false);
        setTimeout(() => {
          fetchVendor();
          setMessage("");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to update vendor");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error updating vendor");
      console.error(error);
    } finally {
      setSaveLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("Are you sure you want to delete this vendor?") || !id) return;

    try {
      const response = await fetch(`/api/vendors/${id}`, {
        method: "DELETE",
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("Vendor deleted successfully");
        setTimeout(() => {
          navigate("/create-vendor");
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
    if (vendor) {
      setEditFormData({
        name: vendor.name,
        personName: vendor.personName,
        mobileNumber: vendor.mobileNumber,
        email: vendor.email,
        location: vendor.location,
        gstNumber: vendor.gstNumber || "",
      });
    }
    setShowEditForm(false);
    setErrors({});
    setMessage("");
  };

  if (loading) {
    return (
      <Layout title="Vendor Details">
        <div className="flex items-center justify-center p-8">
          <div className="inline-block w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-gray-600 ml-3">
            Loading vendor...
          </p>
        </div>
      </Layout>
    );
  }

  if (!vendor) {
    return (
      <Layout title="Vendor Not Found">
        <div className="text-center p-8">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-600">Vendor not found</p>
          <button
            onClick={() => navigate("/create-vendor")}
            className="mt-4 text-blue-600 hover:text-blue-700 font-medium"
          >
            Back to Vendors
          </button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout title="Vendor Details">
      <div className="space-y-6">
        <PageHeader
          title={vendor?.name || "Vendor Details"}
          description={`Contact: ${vendor?.personName || "Loading..."}`}
          breadcrumbs={[
            { label: "Vendors", href: "/create-vendor" },
            { label: vendor?.name ? vendor.name.charAt(0).toUpperCase() + vendor.name.slice(1) : "Details" },
          ]}
          icon={<Building2 className="w-6 h-6 text-white" />}
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
                  Vendor Name
                </label>
                <p className="text-2xl font-bold text-gray-900 capitalize-each-word">
                  {vendor.name}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Contact Person
                </label>
                <p className="text-2xl font-bold text-gray-900 capitalize-each-word">
                  {vendor.personName}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Mobile Number
                </label>
                <a
                  href={`tel:${vendor.mobileNumber}`}
                  className="text-2xl font-bold text-blue-600 hover:text-blue-700 transition-colors"
                >
                  {vendor.mobileNumber}
                </a>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Email Address
                </label>
                <a
                  href={`mailto:${vendor.email}`}
                  className="text-sm font-bold text-blue-600 hover:text-blue-700 break-all"
                >
                  {vendor.email}
                </a>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Location
                </label>
                <p className="text-gray-900 font-semibold capitalize-each-word">
                  {vendor.location}
                </p>
              </div>

              {vendor.gstNumber && (
                <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                  <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                    GST Number
                  </label>
                  <p className="text-gray-900 font-semibold">
                    {vendor.gstNumber}
                  </p>
                </div>
              )}

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Created On
                </label>
                <p className="text-gray-900 font-semibold">
                  {new Date(vendor.createdAt).toLocaleDateString("en-GB")}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Last Updated
                </label>
                <p className="text-gray-900 font-semibold">
                  {new Date(vendor.updatedAt).toLocaleDateString("en-GB")}
                </p>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-white rounded-lg shadow-md border border-gray-200 p-8 animate-fade-in">
            <div className="mb-8">
              <h2 className="text-3xl font-bold text-gray-900 mb-1">
                Edit Vendor
              </h2>
              <p className="text-gray-600">
                Update vendor information and details
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
              {/* Vendor Name Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Vendor Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={editFormData.name}
                  onChange={(e) =>
                    setEditFormData({ ...editFormData, name: e.target.value })
                  }
                  placeholder="e.g., ABC Supply Co..."
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

              {/* Contact Person Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Contact Person <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={editFormData.personName}
                  onChange={(e) =>
                    setEditFormData({
                      ...editFormData,
                      personName: e.target.value,
                    })
                  }
                  placeholder="e.g., John Doe..."
                  autoCapitalize="words"
                  className={`w-full px-4 py-3 rounded-lg bg-white border transition-all capitalize-each-word text-gray-900 placeholder-gray-400 focus:outline-none ${
                    errors.personName
                      ? "border-red-500 ring-1 ring-red-500"
                      : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  }`}
                />
                {errors.personName && (
                  <p className="text-red-600 text-sm mt-3 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    {errors.personName}
                  </p>
                )}
              </div>

              {/* Mobile Number Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Mobile Number
                </label>
                <div className="relative">
                  <Phone className="absolute left-4 top-4 w-4 h-4 text-gray-400" />
                  <input
                    type="tel"
                    value={editFormData.mobileNumber}
                    onChange={(e) =>
                      setEditFormData({
                        ...editFormData,
                        mobileNumber: e.target.value,
                      })
                    }
                    placeholder="Enter mobile number"
                    className="w-full pl-12 pr-4 py-3 rounded-lg bg-white border border-gray-300 text-gray-900 placeholder-gray-400 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                  />
                </div>
              </div>

              {/* Email Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="absolute left-4 top-4 w-4 h-4 text-gray-400" />
                  <input
                    type="email"
                    value={editFormData.email}
                    onChange={(e) =>
                      setEditFormData({ ...editFormData, email: e.target.value })
                    }
                    placeholder="Enter email address"
                    className={`w-full pl-12 pr-4 py-3 rounded-lg bg-white border transition-all text-gray-900 placeholder-gray-400 focus:outline-none ${
                      errors.email
                        ? "border-red-500 ring-1 ring-red-500"
                        : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                    }`}
                  />
                </div>
                {errors.email && (
                  <p className="text-red-600 text-sm mt-3 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    {errors.email}
                  </p>
                )}
              </div>

              {/* Location Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Location <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <MapPin className="absolute left-4 top-4 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    value={editFormData.location}
                    onChange={(e) =>
                      setEditFormData({
                        ...editFormData,
                        location: e.target.value,
                      })
                    }
                    placeholder="Enter full address"
                    autoCapitalize="words"
                    className={`w-full pl-12 pr-4 py-3 rounded-lg bg-white border transition-all capitalize-each-word text-gray-900 placeholder-gray-400 focus:outline-none ${
                      errors.location
                        ? "border-red-500 ring-1 ring-red-500"
                        : "border-gray-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                    }`}
                  />
                </div>
                {errors.location && (
                  <p className="text-red-600 text-sm mt-3 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    {errors.location}
                  </p>
                )}
              </div>

              {/* GST Number Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  GST Number <span className="text-gray-400 font-normal">(Optional)</span>
                </label>
                <input
                  type="text"
                  value={editFormData.gstNumber}
                  onChange={(e) =>
                    setEditFormData({
                      ...editFormData,
                      gstNumber: e.target.value,
                    })
                  }
                  placeholder="Enter GST number"
                  className="w-full px-4 py-3 rounded-lg bg-white border border-gray-300 text-gray-900 placeholder-gray-400 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                />
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



