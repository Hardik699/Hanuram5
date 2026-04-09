import { useState, useEffect } from "react";
import { Layout } from "@/components/Layout";
import { PageHeader } from "@/components/PageHeader";
import { LogIn } from "lucide-react";
import { toast } from "sonner";

interface LoginLog {
  _id: string;
  username: string;
  email?: string;
  ipAddress: string;
  userAgent?: string;
  loginTime: string;
  status: "success" | "failed";
  failureReason?: string;
}

export default function LoginLogs() {
  const [logs, setLogs] = useState<LoginLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(50);

  useEffect(() => {
    fetchLoginLogs();
  }, [page]);

  const fetchLoginLogs = async () => {
    try {
      setLoading(true);
      const skip = (page - 1) * limit;
      const response = await fetch(`/api/login-logs?limit=${limit}&skip=${skip}`);
      
      if (!response.ok) {
        console.error("Response status:", response.status);
        toast.error(`Failed to fetch login logs: ${response.status}`);
        setLogs([]);
        setTotal(0);
        return;
      }
      
      const data = await response.json();
      console.log("Login logs response:", data);
      
      if (data.success) {
        setLogs(data.data || []);
        setTotal(data.total || 0);
      } else {
        console.error("API error:", data.error);
        toast.error(data.error || "Failed to fetch login logs");
        setLogs([]);
        setTotal(0);
      }
    } catch (error) {
      console.error("Error fetching login logs:", error);
      toast.error("Error fetching login logs: " + (error instanceof Error ? error.message : "Unknown error"));
      setLogs([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString("en-IN", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <Layout title="Login Logs">
      <div className="space-y-6">
        <PageHeader
          title="Login Logs"
          description="View all user login attempts and activities"
          breadcrumbs={[{ label: "Login Logs" }]}
          icon={<LogIn className="w-6 h-6 text-white" />}
        />

        <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="inline-block w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin" />
              <p className="text-slate-600 dark:text-slate-400 ml-3 font-medium">Loading logs...</p>
            </div>
          ) : logs.length === 0 ? (
            <div className="flex items-center justify-center py-12">
              <p className="text-slate-600 dark:text-slate-400 font-medium">No login logs found</p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-slate-100 dark:bg-slate-700 border-b border-slate-200 dark:border-slate-600">
                      <th className="px-6 py-3 text-left font-semibold text-slate-900 dark:text-white">Username</th>
                      <th className="px-6 py-3 text-left font-semibold text-slate-900 dark:text-white">Email</th>
                      <th className="px-6 py-3 text-left font-semibold text-slate-900 dark:text-white">IP Address</th>
                      <th className="px-6 py-3 text-left font-semibold text-slate-900 dark:text-white">Login Time</th>
                      <th className="px-6 py-3 text-left font-semibold text-slate-900 dark:text-white">Status</th>
                      <th className="px-6 py-3 text-left font-semibold text-slate-900 dark:text-white">Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((log) => (
                      <tr
                        key={log._id}
                        className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
                      >
                        <td className="px-6 py-3 text-slate-900 dark:text-white font-medium">{log.username}</td>
                        <td className="px-6 py-3 text-slate-600 dark:text-slate-400">{log.email || "-"}</td>
                        <td className="px-6 py-3 text-slate-600 dark:text-slate-400 font-mono text-xs">{log.ipAddress}</td>
                        <td className="px-6 py-3 text-slate-600 dark:text-slate-400 text-xs">{formatDate(log.loginTime)}</td>
                        <td className="px-6 py-3">
                          <span
                            className={`inline-block px-3 py-1 rounded-full text-xs font-semibold ${
                              log.status === "success"
                                ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400"
                                : "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400"
                            }`}
                          >
                            {log.status === "success" ? "✓ Success" : "✗ Failed"}
                          </span>
                        </td>
                        <td className="px-6 py-3 text-slate-600 dark:text-slate-400 text-xs">{log.failureReason || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="flex items-center justify-between px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-700/50">
                <div className="text-sm text-slate-600 dark:text-slate-400">
                  Showing {(page - 1) * limit + 1} to {Math.min(page * limit, total)} of {total} logs
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage(Math.max(1, page - 1))}
                    disabled={page === 1}
                    className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    Previous
                  </button>
                  <div className="flex items-center gap-2">
                    {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                      const pageNum = i + 1;
                      return (
                        <button
                          key={pageNum}
                          onClick={() => setPage(pageNum)}
                          className={`px-3 py-2 rounded-lg transition-colors ${
                            page === pageNum
                              ? "bg-indigo-600 text-white"
                              : "border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-600"
                          }`}
                        >
                          {pageNum}
                        </button>
                      );
                    })}
                  </div>
                  <button
                    onClick={() => setPage(Math.min(totalPages, page + 1))}
                    disabled={page === totalPages}
                    className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </Layout>
  );
}
