import { useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { LogOut, User } from "lucide-react";

export function UserMenu() {
  const { user, logout } = useAuth();
  const [isOpen, setIsOpen] = useState(false);

  if (!user) return null;

  return (
    <div className="relative">
      {/* User Profile Button - Modern Design */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-slate-100 active:scale-95 transition-all"
      >
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center text-white font-semibold text-sm">
          {user.username.charAt(0).toUpperCase()}
        </div>
        <span className="text-sm font-medium text-gray-900 hidden sm:inline max-w-[100px] truncate">
          {user.username}
        </span>
      </button>

      {/* Dropdown Menu - Modern Popover */}
      {isOpen && (
        <div
          className="absolute right-0 mt-3 w-56 bg-white rounded-lg shadow-xl border z-50 overflow-hidden animate-slide-in-down"
          style={{ borderColor: "#e2e8f0" }}
          onClick={() => setIsOpen(false)}
        >
          {/* Header Section */}
          <div className="p-4 border-b" style={{ borderColor: "#e2e8f0" }}>
            <p className="text-sm font-semibold text-gray-900">
              {user.username}
            </p>
            <p className="text-xs text-gray-500 mt-1">
              {user.email}
            </p>
          </div>

          {/* Menu Items */}
          <div className="p-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                logout();
                setIsOpen(false);
              }}
              className="w-full flex items-center gap-3 px-3 py-2.5 text-sm text-red-600 hover:bg-red-50 rounded-lg transition-colors"
            >
              <LogOut size={16} className="flex-shrink-0" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

