import { useState } from "react";
import { DatabaseBackup, CheckCircle, XCircle } from "lucide-react";

type State = "idle" | "loading" | "success" | "error";

export function BackupButton() {
  const [state, setState] = useState<State>("idle");
  const [percent, setPercent] = useState(0);
  const [statusMsg, setStatusMsg] = useState("");
  const [finalMsg, setFinalMsg] = useState("");

  const handleBackup = async () => {
    setState("loading");
    setPercent(0);
    setStatusMsg("Starting backup...");
    setFinalMsg("");

    try {
      const token = localStorage.getItem("token");
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      // Start backup job
      const startRes = await fetch("/api/backup", { method: "POST", headers });
      const { jobId } = await startRes.json();

      // Poll progress every 600ms
      const poll = setInterval(async () => {
        try {
          const res = await fetch(`/api/backup/progress/${jobId}`, { headers });
          const data = await res.json();

          setPercent(data.percent ?? 0);
          setStatusMsg(data.message ?? "");

          if (data.done) {
            clearInterval(poll);
            setPercent(100);
            setFinalMsg(data.finalMessage || data.message);
            setState(data.success ? "success" : "error");
          }
        } catch {
          clearInterval(poll);
          setState("error");
          setFinalMsg("Failed to get progress");
        }
      }, 600);
    } catch (err: any) {
      setState("error");
      setFinalMsg(err?.message || "Network error");
    }
  };

  const reset = () => {
    setState("idle");
    setPercent(0);
    setStatusMsg("");
    setFinalMsg("");
  };

  return (
    <div className="relative">
      <button
        onClick={state === "idle" ? handleBackup : state !== "loading" ? reset : undefined}
        disabled={state === "loading"}
        title={state !== "idle" ? "Click to dismiss" : "Backup to MongoDB Atlas"}
        className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-all border active:scale-95
          disabled:cursor-not-allowed
          ${state === "success" ? "bg-green-50 border-green-200 text-green-700 hover:bg-green-100" :
            state === "error"   ? "bg-red-50 border-red-200 text-red-700 hover:bg-red-100" :
                                  "bg-blue-50 border-blue-200 text-blue-700 hover:bg-blue-100"}`}
      >
        {state === "success" ? <CheckCircle size={15} /> :
         state === "error"   ? <XCircle size={15} /> :
                               <DatabaseBackup size={15} className={state === "loading" ? "animate-pulse" : ""} />}
        <span className="hidden sm:inline">
          {state === "loading" ? `${percent}%` :
           state === "success" ? "Done" :
           state === "error"   ? "Failed" : "DB Backup"}
        </span>
      </button>

      {/* Loading Progress Popup */}
      {state === "loading" && (
        <div className="absolute right-0 top-full mt-2 z-50 w-80 bg-white border border-blue-200 rounded-xl shadow-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-blue-700">Backing up to MongoDB Atlas</span>
            <span className="text-xs font-bold text-blue-600">{percent}%</span>
          </div>
          {/* Progress Bar */}
          <div className="w-full bg-blue-100 rounded-full h-2.5 mb-3 overflow-hidden">
            <div
              className="h-2.5 rounded-full bg-gradient-to-r from-blue-500 to-blue-600 transition-all duration-500"
              style={{ width: `${percent}%` }}
            />
          </div>
          <p className="text-xs text-gray-500 truncate">{statusMsg}</p>
        </div>
      )}

      {/* Result Popup */}
      {(state === "success" || state === "error") && finalMsg && (
        <div className={`absolute right-0 top-full mt-2 z-50 w-80 rounded-xl shadow-xl p-4 border
          ${state === "success" ? "bg-green-50 border-green-200" : "bg-red-50 border-red-200"}`}>
          <div className="flex items-start gap-2">
            {state === "success"
              ? <CheckCircle size={16} className="text-green-600 mt-0.5 flex-shrink-0" />
              : <XCircle size={16} className="text-red-500 mt-0.5 flex-shrink-0" />}
            <p className={`text-xs ${state === "success" ? "text-green-800" : "text-red-800"}`}>
              {finalMsg}
            </p>
          </div>
          <p className="text-xs text-gray-400 mt-2 text-right">Click button to dismiss</p>
        </div>
      )}
    </div>
  );
}

