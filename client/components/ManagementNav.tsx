import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { ChevronDown, Package } from "lucide-react";

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
}

export function ManagementNav() {
  const navigate = useNavigate();
  const location = useLocation();
  const [isOpen, setIsOpen] = useState(false);

  const navItems: NavItem[] = [
    {
      label: "Category",
      path: "/create-category",
      icon: <Package className="w-5 h-5" />,
    },
    {
      label: "Unit",
      path: "/create-unit",
      icon: <Package className="w-5 h-5" />,
    },
    {
      label: "Sub Category",
      path: "/create-subcategory",
      icon: <Package className="w-5 h-5" />,
    },
    {
      label: "Vendor",
      path: "/create-vendor",
      icon: <Package className="w-5 h-5" />,
    },
  ];

  const getCurrentLabel = () => {
    const currentItem = navItems.find(
      (item) => location.pathname === item.path,
    );
    return currentItem?.label || "Management";
  };

  const handleNavigate = (path: string) => {
    navigate(path);
    setIsOpen(false);
  };

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full flex items-center justify-between px-4 py-3 text-sm font-medium transition-all rounded-lg ${
          isOpen
            ? "text-blue-600 bg-blue-50"
            : "text-gray-600 hover:text-gray-900 hover:bg-gray-50"
        }`}
      >
        <div className="flex items-center gap-3">
          <Package className={`w-5 h-5 transition-colors ${isOpen ? "text-blue-600" : "text-gray-500"}`} />
          <div className="text-left">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Master Data
            </p>
            <p className="text-sm font-bold text-gray-900">
              {getCurrentLabel()}
            </p>
          </div>
        </div>
        <ChevronDown
          className={`w-5 h-5 transition-transform flex-shrink-0 ${
            isOpen ? "rotate-180 text-blue-600" : "text-gray-500"
          }`}
        />
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute top-full left-0 right-0 mt-2 bg-white rounded-lg shadow-lg border border-gray-200 overflow-hidden z-50 min-w-[280px]">
          <div className="p-2 space-y-1">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path;
              return (
                <button
                  key={item.path}
                  onClick={() => handleNavigate(item.path)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all text-left text-sm font-medium ${
                    isActive
                      ? "bg-blue-50 text-blue-600"
                      : "text-gray-600 hover:text-gray-900 hover:bg-gray-50"
                  }`}
                >
                  <div
                    className={`flex-shrink-0 ${
                      isActive ? "text-blue-600" : "text-gray-500"
                    }`}
                  >
                    {item.icon}
                  </div>
                  <div className="flex-1">
                    <p>{item.label}</p>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Overlay to close dropdown */}
      {isOpen && (
        <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
      )}
    </div>
  );
}

