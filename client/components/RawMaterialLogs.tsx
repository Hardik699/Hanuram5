import { useState, useEffect } from "react";
import { X, ChevronDown, ChevronUp } from "lucide-react";

interface RawMaterialLog {
  _id: string;
  rawMaterialId: string;
  actionType: string;
  fieldName?: string;
  oldValue?: any;
  newValue?: any;
  changedByUserName: string;
  changedAt: string;
}

interface RawMaterialLogsProps {
  isOpen: boolean;
  onClose: () => void;
  rawMaterialId: string;
  rawMaterialName: string;
}

export default function RawMaterialLogs({
  isOpen,
  onClose,
  rawMaterialId,
  rawMaterialName,
}: RawMaterialLogsProps) {
  const [logs, setLogs] = useState<RawMaterialLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  useEffect(() => {
    if (isOpen) {
      fetchLogs();
    }
  }, [isOpen, rawMaterialId]);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const url = `/api/raw-materials/${rawMaterialId}/logs`;
      console.log("Fetching logs from:", url);
      const response = await fetch(url);

      console.log("Response status:", response.status);
      console.log("Response headers:", response.headers.get("content-type"));

      if (!response.ok) {
        const text = await response.text();
        console.error("Error response:", text);
        throw new Error(`HTTP ${response.status}: ${text.substring(0, 100)}`);
      }

      const data = await response.json();
      console.log("Logs data:", data);
      if (data.success && Array.isArray(data.data)) {
        setLogs(data.data);
      }
    } catch (error) {
      console.error("Error fetching logs:", error);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-GB");
  };

  const getActionLabel = (actionType: string, fieldName?: string) => {
    const actionMap: { [key: string]: string } = {
      RAW_MATERIAL_EDIT: "Edited",
      UNIT_UPDATE: "Unit Changed",
      RAW_MATERIAL_DELETE: "Deleted",
      PRICE_UPDATE: "Price Changed",
      VENDOR_UPDATE: "Vendor Changed",
    };
    return actionMap[actionType] || actionType;
  };

  const getFieldLabel = (fieldName?: string) => {
    const fieldMap: { [key: string]: string } = {
      name: "Name",
      categoryId: "Category",
      subCategoryId: "Sub Category",
      unitId: "Unit",
      hsnCode: "HSN Code",
      status: "Status",
    };
    return fieldMap[fieldName || ""] || fieldName || "";
  };

  const formatValue = (val: any) => {
    if (val === null || val === undefined) return "-";
    if (typeof val === "object") return JSON.stringify(val);
    return String(val);
  };

  const sortedLogs = sortOrder === "desc" ? logs : [...logs].reverse();

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/50" onClick={onClose} />

      {/* Modal */}
      <div className="relative min-h-screen flex items-center justify-center p-4">
        <div className="relative bg-white dark:bg-slate-800 rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] flex flex-col border border-slate-200 dark:border-slate-700">
          {/* Header */}
          <div className="border-b border-slate-200 dark:border-slate-700 p-6 flex items-center justify-between sticky top-0 bg-white dark:bg-slate-800">
            <div>
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                Change History
              </h2>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                {rawMaterialName}
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-slate-600 dark:text-slate-400" />
            </button>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto">
            {loading ? (
              <div className="p-6 text-center">
                <p className="text-slate-500 dark:text-slate-400">
                  Loading logs...
                </p>
              </div>
            ) : logs.length === 0 ? (
              <div className="p-6 text-center">
                <p className="text-slate-500 dark:text-slate-400">
                  No change history yet
                </p>
              </div>
            ) : (
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                    Total Changes: {logs.length}
                  </h3>
                  <button
                    onClick={() =>
                      setSortOrder(sortOrder === "desc" ? "asc" : "desc")
                    }
                    className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-300 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700/50 transition-colors"
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

                <div className="overflow-x-auto">
                  <table className="w-full min-w-[900px]">
                    <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                          Date & Time
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                          User
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                          Action
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                          Old Value
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                          New Value
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                      {sortedLogs.map((log) => (
                        <tr
                          key={log._id}
                          className="hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors"
                        >
                          <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400 whitespace-nowrap">
                            {formatDate(log.changedAt)}
                          </td>
                          <td className="px-4 py-3 text-sm font-medium text-slate-900 dark:text-white">
                            {log.changedByUserName}
                          </td>
                          <td className="px-4 py-3 text-sm text-slate-900 dark:text-white">
                            <span className="inline-block px-2.5 py-1 bg-teal-100 dark:bg-teal-900/30 text-teal-700 dark:text-teal-300 rounded-full text-xs font-medium">
                              {getActionLabel(log.actionType, log.fieldName)}
                            </span>
                            {log.fieldName && (
                              <span className="ml-2 text-slate-500 dark:text-slate-400 text-xs">
                                ({getFieldLabel(log.fieldName)})
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                            {log.oldValue ? (
                              <span className="px-2 py-1 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 rounded text-xs font-medium">
                                {formatValue(log.oldValue)}
                              </span>
                            ) : (
                              <span className="text-slate-400">-</span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                            {log.newValue ? (
                              <span className="px-2 py-1 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 rounded text-xs font-medium">
                                {formatValue(log.newValue)}
                              </span>
                            ) : (
                              <span className="text-slate-400">-</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-slate-200 dark:border-slate-700 p-6 flex justify-end">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-200 dark:bg-slate-700 text-slate-900 dark:text-white rounded-lg hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors font-medium text-sm"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

