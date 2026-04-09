import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  BarChart3,
  Users,
  FileText,
  Settings,
  Clock,
  LayoutDashboard,
} from "lucide-react";
import { Layout } from "@/components/Layout";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { PageHeader } from "@/components/PageHeader";

interface DashboardUser {
  username: string;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [user, setUser] = useState<DashboardUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is authenticated
    const token = localStorage.getItem("auth_token");
    const username = localStorage.getItem("username");

    if (!token || !username) {
      navigate("/");
      return;
    }

    setUser({ username });
    setLoading(false);
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 flex items-center justify-center">
        <LoadingSpinner message="Loading dashboard..." />
      </div>
    );
  }

  return (
    <Layout title={`Welcome back, ${user?.username}!`}>
      <div className="space-y-6">
        {/* Page Header */}
        <PageHeader
          title="Dashboard"
          description="Welcome to your Hanuram Foods management system. Here's an overview of your operations."
          icon={
            <LayoutDashboard className="w-6 h-6 text-indigo-600 dark:text-indigo-400" />
          }
        />

        {/* Stats grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8 animate-fade-in-up">
          <StatCard
            icon={Users}
            title="Users"
            value="0"
            change="+0 this week"
            color="blue"
          />
          <StatCard
            icon={FileText}
            title="Documents"
            value="0"
            change="+0 this week"
            color="purple"
          />
          <StatCard
            icon={BarChart3}
            title="Analytics"
            value="0"
            change="View details"
            color="green"
          />
          <StatCard
            icon={Clock}
            title="Activity"
            value="Real-time"
            change="All synced"
            color="orange"
          />
        </div>

        {/* Content sections */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in-up">
          {/* Main section */}
          <div className="lg:col-span-2 bg-white dark:bg-slate-800 rounded-2xl shadow-elevation-2 p-8 border border-slate-200 dark:border-slate-700 hover:shadow-elevation-4 transition-all">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
              <span className="w-1 h-1 bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full"></span>
              Getting Started
            </h3>
            <div className="space-y-4 text-slate-600 dark:text-slate-400">
              <p className="leading-relaxed">
                Welcome to Hanuram Foods management system! This is your admin
                portal where you can manage all aspects of your raw materials,
                vendors, and operations.
              </p>
              <ul className="space-y-3 pl-5 list-disc marker:text-blue-500 dark:marker:text-blue-400">
                <li>Database is connected and all features are available</li>
                <li>All data is synced in real-time across users</li>
                <li>Access raw materials, pricing, and costing tools</li>
              </ul>
              <p className="pt-4 text-sm italic text-blue-600 dark:text-blue-400">
                💡 Tip: Use the sidebar to navigate between different modules.
              </p>
            </div>
          </div>

          {/* Sidebar section */}
          <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-elevation-2 p-8 border border-slate-200 dark:border-slate-700 hover:shadow-elevation-4 transition-all">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-5 flex items-center gap-2">
              <Settings className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              Quick Actions
            </h3>
            <div className="space-y-3">
              <button className="w-full px-4 py-3 bg-gradient-to-r from-indigo-50 to-indigo-100 dark:from-indigo-900/20 dark:to-indigo-900/10 text-indigo-700 dark:text-indigo-300 rounded-xl hover:from-indigo-100 hover:to-indigo-200 dark:hover:from-indigo-900/30 dark:hover:to-indigo-900/20 transition-all font-semibold text-sm text-left border border-indigo-200 dark:border-indigo-800/50 transform hover:scale-105 hover:shadow-elevation-2">
                ⚙️ Settings
              </button>
              <button className="w-full px-4 py-3 bg-gradient-to-r from-slate-100 to-slate-50 dark:from-slate-700/50 dark:to-slate-800/50 text-slate-700 dark:text-slate-300 rounded-xl hover:from-slate-200 hover:to-slate-100 dark:hover:from-slate-700 dark:hover:to-slate-700/70 transition-all font-semibold text-sm text-left border border-slate-200 dark:border-slate-700 transform hover:scale-105 hover:shadow-elevation-2">
                📚 Documentation
              </button>
              <button className="w-full px-4 py-3 bg-gradient-to-r from-slate-100 to-slate-50 dark:from-slate-700/50 dark:to-slate-800/50 text-slate-700 dark:text-slate-300 rounded-xl hover:from-slate-200 hover:to-slate-100 dark:hover:from-slate-700 dark:hover:to-slate-700/70 transition-all font-semibold text-sm text-left border border-slate-200 dark:border-slate-700 transform hover:scale-105 hover:shadow-elevation-2">
                🤝 Support
              </button>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}

interface StatCardProps {
  icon: React.ComponentType<{ className: string }>;
  title: string;
  value: string;
  change: string;
  color: "blue" | "purple" | "green" | "orange";
}

function StatCard({ icon: Icon, title, value, change, color }: StatCardProps) {
  const colorClasses = {
    blue: {
      bg: "bg-blue-50 dark:bg-blue-900/20",
      text: "text-blue-600 dark:text-blue-400",
      border: "border-blue-200 dark:border-blue-800/50",
      gradient: "from-blue-600 to-blue-700",
    },
    purple: {
      bg: "bg-purple-50 dark:bg-purple-900/20",
      text: "text-purple-600 dark:text-purple-400",
      border: "border-purple-200 dark:border-purple-800/50",
      gradient: "from-purple-600 to-purple-700",
    },
    green: {
      bg: "bg-emerald-50 dark:bg-emerald-900/20",
      text: "text-emerald-600 dark:text-emerald-400",
      border: "border-emerald-200 dark:border-emerald-800/50",
      gradient: "from-emerald-600 to-emerald-700",
    },
    orange: {
      bg: "bg-orange-50 dark:bg-orange-900/20",
      text: "text-orange-600 dark:text-orange-400",
      border: "border-orange-200 dark:border-orange-800/50",
      gradient: "from-orange-600 to-orange-700",
    },
  };

  const colorConfig = colorClasses[color];

  return (
    <div
      className={`bg-white dark:bg-slate-800 rounded-2xl shadow-elevation-2 p-6 border ${colorConfig.border} hover:shadow-elevation-4 transition-all duration-300 hover:-translate-y-1 group`}
    >
      <div
        className={`w-14 h-14 rounded-xl flex items-center justify-center mb-4 ${colorConfig.bg} ${colorConfig.text} group-hover:scale-110 transition-transform`}
      >
        <Icon className="w-6 h-6" />
      </div>
      <h3 className="text-xs font-bold text-slate-600 dark:text-slate-400 mb-2 uppercase tracking-widest">
        {title}
      </h3>
      <div className="flex items-baseline justify-between mb-3">
        <p
          className={`text-3xl font-bold ${colorConfig.text} bg-clip-text text-transparent bg-gradient-to-r ${colorConfig.gradient}`}
        >
          {value}
        </p>
      </div>
      <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
        {change}
      </p>
    </div>
  );
}



