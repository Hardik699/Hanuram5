import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  ChevronDown,
  Package,
  List,
  Menu,
  X,
  Users,
  Calculator,
} from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

export function Sidebar() {
  const location = useLocation();
  const { hasPermission, canAccess, user } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [expandedMenu, setExpandedMenu] = useState<string | null>("Master Data Management");

  const toggleMenu = (menuName: string) => {
    setExpandedMenu(expandedMenu === menuName ? null : menuName);
  };

  const isActive = (path: string) => {
    return (
      location.pathname === path || location.pathname.startsWith(path + "/")
    );
  };

  const checkAccess = (item: any) => {
    if (item.module) {
      return canAccess(item.module);
    }
    if (item.permission) {
      return hasPermission(item.permission);
    }
    return true;
  };

  const isProductionUser = user?.role_id === 7;

  useEffect(() => {
    setExpandedMenu(isProductionUser ? "Management" : "Master Data Management");
  }, [isProductionUser]);

  const managementItems = [
    { label: "Category List", path: "/create-category" },
    { label: "Unit List", path: "/create-unit" },
    { label: "Sub Category List", path: "/create-subcategory" },
    { label: "Vendor List", path: "/create-vendor" },
  ];

  const menuItems = isProductionUser
    ? [
        {
          label: "Management",
          path: null,
          icon: Package,
          submenu: managementItems,
        },
        {
          label: "Raw Material",
          path: "/raw-materials",
          icon: Package,
        },
        {
          label: "Recipe",
          path: "/rmc",
          icon: List,
        },
      ]
    : [
        {
          label: "Master Data Management",
          path: null,
          icon: Package,
          submenu: managementItems,
        },
        {
          label: "Raw Material",
          path: "/raw-materials",
          icon: Package,
        },
        {
          label: "Raw Material Costing",
          path: "/rmc",
          icon: List,
        },
        {
          label: "OP Cost Management",
          path: "/op-cost",
          icon: Calculator,
        },
      ];

  return (
    <>
      {/* Mobile menu button - Modern Design */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed top-4 left-4 z-50 md:hidden bg-brand text-white p-2.5 rounded-lg hover:bg-brand-dark active:scale-95 transition-all shadow-lg"
      >
        {isOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>

      {/* Sidebar overlay for mobile */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/30 z-30 md:hidden backdrop-blur-sm"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Sidebar - Modern Flat Design */}
      <aside
        className={`fixed left-0 top-0 h-screen bg-slate-50 border-r transition-transform duration-300 overflow-y-auto z-40 flex flex-col ${
          isOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        }`}
        style={{ width: "260px", borderColor: "#e2e8f0" }}
      >
        {/* Logo/Brand Section */}
        <div className="px-4 py-6 border-b" style={{ borderColor: "#e2e8f0" }}>
          <div className="flex items-center gap-3 px-3 py-2">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 via-blue-600 to-blue-700 flex items-center justify-center text-white font-bold text-sm flex-shrink-0 shadow-md">
              HF
            </div>
            <div className="text-left">
              <p className="text-xs font-bold text-gray-500 uppercase tracking-wider">
                Hanuram
              </p>
              <h2 className="text-sm font-bold text-gray-900">Foods</h2>
            </div>
          </div>
        </div>

        {/* Menu Label */}
        <div className="px-4 py-4">
          <p className="text-xs font-bold text-gray-400 uppercase tracking-widest pl-1">
            Menu
          </p>
        </div>

        {/* Menu Items - Scrollable */}
        <nav className="flex-1 px-3 space-y-1 overflow-y-auto">
          {menuItems
            .filter((item) => checkAccess(item))
            .map((item, index) => {
              const itemActive = isActive(item.path || "");

              return (
                <div key={index}>
                  {item.submenu ? (
                    <div>
                      <button
                        onClick={() => toggleMenu(item.label)}
                        className={`w-full flex items-center justify-between px-3 py-2.5 text-sm font-medium transition-all rounded-lg mb-1 gap-2 ${
                          expandedMenu === item.label
                            ? "text-brand bg-blue-100"
                            : "text-gray-700 hover:text-gray-900"
                        }`}
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          {item.icon && (
                            <item.icon
                              className={`w-5 h-5 flex-shrink-0 transition-colors ${
                                expandedMenu === item.label
                                  ? "text-brand"
                                  : "text-gray-600"
                              }`}
                            />
                          )}
                          <span className="truncate">{item.label}</span>
                        </div>
                        <ChevronDown
                          className={`w-4 h-4 flex-shrink-0 transition-transform ${
                            expandedMenu === item.label ? "rotate-180" : ""
                          }`}
                        />
                      </button>

                      {expandedMenu === item.label && (
                        <div className="ml-2 pl-3 border-l-2 space-y-1 mb-1" style={{ borderColor: "#cbd5e1" }}>
                          {item.submenu.map((subitem: any, subindex: number) => (
                            <Link
                              key={subindex}
                              to={subitem.path}
                              onClick={() => setIsOpen(false)}
                              className={`block px-3 py-2 text-sm font-medium rounded-lg transition-all ${
                                isActive(subitem.path)
                                  ? "text-white bg-brand font-semibold"
                                  : "text-gray-700 hover:text-gray-900 hover:bg-gray-200"
                              }`}
                            >
                              {subitem.label}
                            </Link>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <Link
                      to={item.path!}
                      onClick={() => setIsOpen(false)}
                      className={`flex items-center gap-3 px-3 py-2.5 text-sm font-medium transition-all rounded-lg mb-1 ${
                        itemActive
                          ? "text-white bg-brand shadow-md"
                          : "text-gray-700 hover:text-gray-900 hover:bg-gray-200"
                      }`}
                    >
                      {item.icon && (
                        <item.icon
                          className={`w-5 h-5 flex-shrink-0 transition-colors ${
                            itemActive
                              ? "text-white"
                              : "text-gray-600"
                          }`}
                        />
                      )}
                      <span className="flex-1 text-left">{item.label}</span>
                    </Link>
                  )}
                </div>
              );
            })}
        </nav>

        {/* Footer spacer */}
        <div className="h-4" />
      </aside>

      {/* Main content wrapper - offset from sidebar */}
      <div className="hidden md:block md:ml-64" />
    </>
  );
}

