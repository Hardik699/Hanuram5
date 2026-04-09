import { useEffect, useState } from "react";
import { AlertCircle, Check, RefreshCw } from "lucide-react";

type DBStatus = "connected" | "disconnected" | "connecting";

export function DBStatusIndicator() {
  const [status, setStatus] = useState<DBStatus>("connecting");
  const [message, setMessage] = useState("Connecting...");

  useEffect(() => {
    const checkDBStatus = async () => {
      try {
        const response = await fetch("/api/db-status");

        if (!response.ok) {
          console.error("DB Status API returned error:", response.status, response.statusText);
          setStatus("disconnected");
          setMessage(`API Error: ${response.status}`);
          return;
        }

        const data = await response.json();
        setStatus(data.status);
        setMessage(data.message);
      } catch (error) {
        console.error("Failed to check DB status:", error);
        setStatus("disconnected");
        setMessage("Unable to connect to API");
      }
    };

    // Check status on mount
    checkDBStatus();

    // Poll every 5 seconds
    const interval = setInterval(checkDBStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const statusConfig = {
    connected: {
      icon: Check,
      bgColor: "bg-green-50 dark:bg-green-950",
      textColor: "text-green-700 dark:text-green-200",
      dotColor: "bg-green-500",
      label: "DB Connected",
    },
    disconnected: {
      icon: AlertCircle,
      bgColor: "bg-red-50 dark:bg-red-950",
      textColor: "text-red-700 dark:text-red-200",
      dotColor: "bg-red-500",
      label: "DB Disconnected",
    },
    connecting: {
      icon: RefreshCw,
      bgColor: "bg-yellow-50 dark:bg-yellow-950",
      textColor: "text-yellow-700 dark:text-yellow-200",
      dotColor: "bg-yellow-500",
      label: "Syncing...",
    },
  };

  const config = statusConfig[status];
  const Icon = config.icon;
  const isAnimating = status === "connecting";

  return (
    <div
      className={`flex items-center gap-2 px-3 py-1.5 rounded-lg ${config.bgColor}`}
    >
      <div className="relative flex items-center justify-center w-4 h-4">
        <Icon
          className={`w-4 h-4 ${config.textColor} ${isAnimating ? "animate-db-sync" : ""}`}
        />
        {status === "connected" && (
          <div
            className={`absolute w-2 h-2 rounded-full ${config.dotColor} animate-pulse`}
          />
        )}
      </div>
      <span className={`text-xs font-medium ${config.textColor}`}>
        {status === "connected"
          ? "DB Connected"
          : status === "disconnected"
            ? "DB Disconnected"
            : "Syncing..."}
      </span>
    </div>
  );
}

