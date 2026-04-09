import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ChevronLeft, Plus, AlertCircle, Check, Users } from "lucide-react";
import { Layout } from "@/components/Layout";
import { PageHeader } from "@/components/PageHeader";
import { toast } from "sonner";

interface Labour {
  _id?: string;
  code?: string;
  name: string;
  department: string;
  salaryPerDay: number;
}

export default function CreateLabour() {
  const navigate = useNavigate();
  const { id } = useParams();

  const [formData, setFormData] = useState<Labour>({
    name: "",
    department: "",
    salaryPerDay: 0,
  });

  const [loading, setLoading] = useState(false);
  const [pageLoading, setPageLoading] = useState(id ? true : false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState<"success" | "error" | "">("");

  // Fetch labour data if editing
  useEffect(() => {
    if (id) {
      fetchLabourData();
    }
  }, [id]);

  const fetchLabourData = async () => {
    try {
      const token = localStorage.getItem("auth_token");
      const response = await fetch(`/api/labour/${id}`, {
        headers: {
          "Authorization": `Bearer ${token}`,
        },
      });
      const data = await response.json();

      if (data.success && data.data) {
        setFormData({
          name: data.data.name,
          department: data.data.department,
          salaryPerDay: data.data.salaryPerDay,
        });
      } else {
        toast.error("Failed to load labour data");
        navigate("/labour");
      }
    } catch (error) {
      console.error("Error fetching labour:", error);
      toast.error("Failed to load labour data");
      navigate("/labour");
    } finally {
      setPageLoading(false);
    }
  };

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.name?.trim()) {
      newErrors.name = "Labour name is required";
    }

    if (!formData.department?.trim()) {
      newErrors.department = "Department is required";
    }

    if (!formData.salaryPerDay || formData.salaryPerDay <= 0) {
      newErrors.salaryPerDay = "Salary per day must be greater than 0";
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
      const method = id ? "PUT" : "POST";
      const url = id ? `/api/labour/${id}` : "/api/labour";
      const token = localStorage.getItem("auth_token");

      const response = await fetch(url, {
        method,
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: formData.name,
          department: formData.department,
          salaryPerDay: parseFloat(formData.salaryPerDay.toString()),
        }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setMessageType("success");
        setMessage(
          data.message ||
            (id ? "Labour updated successfully" : "Labour added successfully"),
        );

        setTimeout(() => {
          navigate("/labour");
          toast.success(
            id ? "Labour updated successfully" : "Labour added successfully",
          );
        }, 1500);
      } else {
        setMessageType("error");
        setMessage(data.message || "Operation failed");
      }
    } catch (error) {
      setMessageType("error");
      setMessage("Error saving labour");
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleBack = () => {
    navigate("/labour");
  };

  if (pageLoading) {
    return (
      <Layout title={id ? "Edit Labour" : "Add Labour"}>
        <div className="flex items-center justify-center min-h-screen">
          <div className="text-center">
            <div className="w-12 h-12 border-4 border-blue-200 dark:border-blue-800 border-t-blue-500 dark:border-t-blue-400 rounded-full animate-spin mx-auto mb-4" />
            <p className="text-slate-600 dark:text-slate-400 font-medium">
              Loading...
            </p>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout title={id ? "Edit Labour" : "Add Labour"}>
      <PageHeader
        title={id ? "Edit Labour" : "Add Labour"}
        description={
          id ? "Update labour information" : "Create a new labour record"
        }
        breadcrumbs={[
          { label: "Labour", href: "/labour" },
          { label: id ? "Edit" : "Add Labour" },
        ]}
        icon={<Users className="w-6 h-6 text-white" />}
      />

      <div className="space-y-6">
        {/* Back Button */}
        <button
          onClick={handleBack}
          className="flex items-center gap-2 text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 font-medium transition-colors"
        >
          <ChevronLeft className="w-5 h-5" />
          Back to Labour List
        </button>

        {/* Form Card */}
        <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-lg border border-slate-200/50 dark:border-slate-700/50 p-8">
          <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-6">
            {id ? "Edit Labour Details" : "Add New Labour"}
          </h2>

          {message && (
            <div
              className={`mb-6 p-4 rounded-lg flex items-center gap-3 border animate-in fade-in slide-in-from-top-2 duration-300 ${
                messageType === "success"
                  ? "bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-700 dark:text-green-300"
                  : "bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300"
              }`}
            >
              {messageType === "success" ? (
                <Check className="w-5 h-5 flex-shrink-0" />
              ) : (
                <AlertCircle className="w-5 h-5 flex-shrink-0" />
              )}
              <span className="font-medium">{message}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Labour Name */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Labour Name *
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
                placeholder="Enter labour name"
                className={`w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border transition-all ${
                  errors.name
                    ? "border-red-500 dark:border-red-400 focus:ring-red-500"
                    : "border-slate-300 dark:border-slate-600 focus:ring-blue-500"
                } text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2`}
              />
              {errors.name && (
                <p className="text-red-600 dark:text-red-400 text-sm mt-1">
                  {errors.name}
                </p>
              )}
            </div>

            {/* Department */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Department *
              </label>
              <input
                type="text"
                value={formData.department}
                onChange={(e) =>
                  setFormData({ ...formData, department: e.target.value })
                }
                placeholder="e.g., Production, Packaging, Quality"
                className={`w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border transition-all ${
                  errors.department
                    ? "border-red-500 dark:border-red-400 focus:ring-red-500"
                    : "border-slate-300 dark:border-slate-600 focus:ring-blue-500"
                } text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2`}
              />
              {errors.department && (
                <p className="text-red-600 dark:text-red-400 text-sm mt-1">
                  {errors.department}
                </p>
              )}
            </div>

            {/* Salary Per Day */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Salary Per Day (₹) *
              </label>
              <input
                type="number"
                value={formData.salaryPerDay}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    salaryPerDay: parseFloat(e.target.value) || 0,
                  })
                }
                placeholder="Enter daily salary"
                step="0.01"
                min="0"
                className={`w-full px-4 py-2.5 rounded-lg bg-white dark:bg-slate-700 border transition-all ${
                  errors.salaryPerDay
                    ? "border-red-500 dark:border-red-400 focus:ring-red-500"
                    : "border-slate-300 dark:border-slate-600 focus:ring-blue-500"
                } text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2`}
              />
              {errors.salaryPerDay && (
                <p className="text-red-600 dark:text-red-400 text-sm mt-1">
                  {errors.salaryPerDay}
                </p>
              )}
            </div>

            {/* Action Buttons */}
            <div className="flex flex-col sm:flex-row gap-3 pt-6 border-t border-slate-200 dark:border-slate-700">
              <button
                type="submit"
                disabled={loading}
                className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 disabled:bg-slate-400 dark:disabled:bg-slate-600 text-white font-bold py-2.5 px-4 rounded-lg transition-all shadow-md hover:shadow-lg transform hover:scale-105 hover:-translate-y-0.5 flex items-center justify-center gap-2 disabled:cursor-not-allowed disabled:scale-100 text-sm sm:text-base"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    <span>Saving...</span>
                  </>
                ) : (
                  <>
                    <Plus className="w-4 h-4" />
                    <span>{id ? "Update Labour" : "Create Labour"}</span>
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={handleBack}
                className="sm:px-6 px-4 bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 font-semibold py-2.5 rounded-lg hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors text-sm sm:text-base"
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



