import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Eye,
  EyeOff,
  Lock,
  User,
  AlertCircle,
  CheckCircle,
} from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

export default function Login() {
  const navigate = useNavigate();
  const { login, isAuthenticated, loading: authLoading } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    // Check if user is already logged in
    if (isAuthenticated && !authLoading) {
      navigate("/raw-materials");
    }
  }, [isAuthenticated, authLoading]);


  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess(false);

    if (!username.trim() || !password) {
      setError("Please enter both username and password");
      return;
    }

    setLoading(true);

    try {
      const success = await login(username.trim(), password);

      if (success) {
        setSuccess(true);
        // Show success message briefly then navigate
        setTimeout(() => {
          // Always navigate to raw-materials by default
          // Production users (role_id 7) will only see data they have access to
          navigate("/raw-materials");
        }, 500);
      } else {
        setError("Invalid username or password");
      }
    } catch (err) {
      const errorMessage =
        err instanceof Error
          ? err.message
          : "Connection error. Please try again.";
      setError(errorMessage);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-blue-100 dark:from-slate-900 dark:via-slate-900 dark:to-slate-950 flex flex-col items-center justify-center p-4 sm:p-6 animate-fade-in-up">
      {/* Main login container */}
      <div className="w-full max-w-sm sm:max-w-md">
        {/* Logo/Brand area */}
        <div className="text-center mb-8 animate-scale-in">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-brand to-brand-dark dark:from-brand-dark dark:to-brand text-white mb-4 shadow-elevation-4 transform hover:scale-110 transition-transform">
            <Lock className="w-8 h-8" />
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-brand to-brand-dark dark:from-brand dark:to-brand-dark bg-clip-text text-transparent mb-2">
            Hanuram Foods
          </h1>
          <p className="text-slate-600 dark:text-slate-400 font-medium">
            Management System
          </p>
        </div>

        {/* Login card */}
        <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-elevation-4 p-8 mb-6 border border-slate-200 dark:border-slate-700 animate-fade-in-up">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Success Message */}
            {success && (
              <div className="flex items-center gap-3 p-4 bg-emerald-50 dark:bg-emerald-950/20 rounded-xl border border-emerald-200 dark:border-emerald-800/50 animate-bounce-gentle">
                <CheckCircle className="w-5 h-5 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
                <span className="text-sm font-semibold text-emerald-700 dark:text-emerald-300">
                  Login successful! Redirecting...
                </span>
              </div>
            )}

            {/* Error Message */}
            {error && (
              <div className="flex items-center gap-3 p-4 bg-red-50 dark:bg-red-950/20 rounded-xl border border-red-200 dark:border-red-800/50">
                <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0" />
                <span className="text-sm font-semibold text-red-700 dark:text-red-300">
                  {error}
                </span>
              </div>
            )}

            {/* Username field */}
            <div className="space-y-2.5">
              <label
                htmlFor="username"
                className="block text-sm font-bold text-slate-700 dark:text-slate-300 uppercase tracking-widest text-brand dark:text-brand"
              >
                Username
              </label>
              <div className="relative group">
                <User className="absolute left-4 top-3.5 w-5 h-5 text-slate-400 dark:text-slate-500 group-focus-within:text-brand dark:group-focus-within:text-brand transition-colors pointer-events-none" />
                <input
                  id="username"
                  type="text"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={loading}
                  className="w-full pl-12 pr-4 py-3 bg-slate-50 dark:bg-slate-700/50 border-2 border-slate-200 dark:border-slate-600 rounded-xl text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand dark:focus:border-brand disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm"
                />
              </div>
            </div>

            {/* Password field */}
            <div className="space-y-2.5">
              <label
                htmlFor="password"
                className="block text-sm font-bold text-slate-700 dark:text-slate-300 uppercase tracking-widest text-brand dark:text-brand"
              >
                Password
              </label>
              <div className="relative group">
                <Lock className="absolute left-4 top-3.5 w-5 h-5 text-slate-400 dark:text-slate-500 group-focus-within:text-brand dark:group-focus-within:text-brand transition-colors pointer-events-none" />
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                  className="w-full pl-12 pr-12 py-3 bg-slate-50 dark:bg-slate-700/50 border-2 border-slate-200 dark:border-slate-600 rounded-xl text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand dark:focus:border-brand disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={loading}
                  className="absolute right-4 top-3.5 text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors hover:scale-110 transform"
                >
                  {showPassword ? (
                    <EyeOff className="w-5 h-5" />
                  ) : (
                    <Eye className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>

            {/* Login button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-brand to-brand-dark hover:from-brand-dark hover:to-brand disabled:from-slate-400 disabled:to-slate-400 text-white font-bold py-3 px-4 rounded-xl transition-all duration-200 transform hover:scale-105 hover:-translate-y-0.5 disabled:hover:scale-100 disabled:cursor-not-allowed shadow-elevation-3 hover:shadow-elevation-5 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Logging in...</span>
                </>
              ) : (
                "Sign In"
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}



