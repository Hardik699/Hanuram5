import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Layout } from "@/components/Layout";
import {
  ArrowLeft,
  Edit2,
  Trash2,
  Check,
  AlertCircle,
  Settings,
} from "lucide-react";
import { PageHeader } from "@/components/PageHeader";

interface Unit {
  _id: string;
  name: string;
  shortCode: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export default function UnitDetail() {
  const navigate = useNavigate();
  const { id } = useParams();
  const [unit, setUnit] = useState<Unit | null>(null);
  const [loading, setLoading] = useState(true);
  const [showEditForm, setShowEditForm] = useState(false);
  const [editFormData, setEditFormData] = useState({
    name: "",
    shortCode: "",
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
      fetchUnit();
    }
  }, [id]);

  const fetchUnit = async () => {
    try {
      setLoading(true);
      const response = await fetch("/api/units");
      const data = await response.json();

      if (data.success && Array.isArray(data.data)) {
        const u = data.data.find((u: Unit) => u._id === id);
        if (u) {
          setUnit(u);
          setEditFormData({
            name: u.name,
            shortCode: u.shortCode,
          });
        } else {
          navigate("/create-unit");
        }
      }
    } catch (error) {
      console.error("Error fetching unit:", error);
      setMessageType("error");
      setMessage("Failed to load unit details");
    } finally {
      setLoading(false);
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};
    if (!editFormData.name.trim()) {
      newErrors.name = "Unit name is required";
    }
    if (!editFormData.shortCode.trim()) {
      newErrors.shortCode = "Short code is required";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSave = async () => {
    if (!validateForm() || !id) return;

    setSaveLoading(true);
    setMessage("");

    try {
      const response = await fetch(`/api/units/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editFormData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("Unit updated successfully");
        setShowEditForm(false);
        setTimeout(() => {
          fetchUnit();
          setMessage("");
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Failed to update unit");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error updating unit");
      console.error(error);
    } finally {
      setSaveLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("Are you sure you want to delete this unit?") || !id) return;

    try {
      const response = await fetch(`/api/units/${id}`, {
        method: "DELETE",
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage("Unit deleted successfully");
        setTimeout(() => {
          navigate("/create-unit");
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
    if (unit) {
      setEditFormData({
        name: unit.name,
        shortCode: unit.shortCode,
      });
    }
    setShowEditForm(false);
    setErrors({});
    setMessage("");
  };

  if (loading) {
    return (
      <Layout title="Unit Details">
        <div className="flex items-center justify-center p-8">
          <div className="inline-block w-8 h-8 border-4 border-teal-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-600 dark:text-slate-400 ml-3">
            Loading unit...
          </p>
        </div>
      </Layout>
    );
  }

  if (!unit) {
    return (
      <Layout title="Unit Not Found">
        <div className="text-center p-8">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-slate-600 dark:text-slate-400">Unit not found</p>
          <button
            onClick={() => navigate("/create-unit")}
            className="mt-4 text-blue-600 hover:text-blue-700 dark:text-blue-400 font-medium"
          >
            Back to Units
          </button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout title="Unit Details">
      <div className="space-y-6">
        <PageHeader
          title={unit?.name || "Unit Details"}
          description={`Short Code: ${unit?.shortCode || "Loading..."}`}
          breadcrumbs={[
            { label: "Units", href: "/create-unit" },
            { label: unit?.name ? unit.name.charAt(0).toUpperCase() + unit.name.slice(1) : "Details" },
          ]}
          icon={<Settings className="w-6 h-6 text-white" />}
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
                  Unit Name
                </label>
                <p className="text-2xl font-bold text-gray-900 capitalize-each-word">
                  {unit.name}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Short Code
                </label>
                <p className="text-2xl font-bold text-gray-900 capitalize-each-word">
                  {unit.shortCode}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Created On
                </label>
                <p className="text-gray-900 font-semibold">
                  {new Date(unit.createdAt).toLocaleDateString("en-GB")}
                </p>
              </div>

              <div className="p-6 rounded-lg bg-gray-50 border border-gray-200">
                <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
                  Last Updated
                </label>
                <p className="text-gray-900 font-semibold">
                  {new Date(unit.updatedAt).toLocaleDateString("en-GB")}
                </p>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-white rounded-lg shadow-md border border-gray-200 p-8 animate-fade-in">
            <div className="mb-8">
              <h2 className="text-3xl font-bold text-gray-900 mb-1">
                Edit Unit
              </h2>
              <p className="text-gray-600">
                Update unit information
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
              {/* Unit Name Field */}
              <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                <label className="block text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider">
                  Unit Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={editFormData.name}
                  onChange={(e) =>
                    setEditFormData({ ...editFormData, name: e.target.value })
                  }
                  placeholder="e.g., Kilogram"
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
                  value={editFormData.shortCode}
                  onChange={(e) =>
                    setEditFormData({
                      ...editFormData,
                      shortCode: e.target.value.toUpperCase(),
                    })
                  }
                  placeholder="e.g., KG"
                  className={`w-full px-4 py-3 rounded-lg bg-white border transition-all text-gray-900 placeholder-gray-400 focus:outline-none font-semibold text-center tracking-widest ${
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
                  type="button"
                  onClick={handleSave}
                  disabled={saveLoading}
                  className="flex-1 bg-blue-50 border border-blue-200 text-blue-700 font-bold py-3 px-4 rounded-lg hover:bg-blue-100 hover:border-blue-300 hover:shadow-md transition-all duration-200 active:scale-95 disabled:bg-gray-100 disabled:border-gray-200 disabled:text-gray-500 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {saveLoading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
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
                  className="px-8 bg-gray-50 border border-gray-200 text-gray-700 font-semibold py-3 rounded-lg hover:bg-gray-100 hover:border-gray-300 hover:shadow-md transition-all duration-200 active:scale-95"
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



