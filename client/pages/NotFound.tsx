import { useLocation, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { Home } from "lucide-react";

const NotFound = () => {
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    console.error(
      "404 Error: User attempted to access non-existent route:",
      location.pathname,
    );
  }, [location.pathname]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-blue-100 dark:from-slate-900 dark:via-slate-900 dark:to-slate-950 flex items-center justify-center p-4 animate-fade-in-up">
      <div className="text-center max-w-md mx-auto">
        <div className="mb-6 animate-bounce-gentle">
          <div className="inline-flex items-center justify-center w-24 h-24 rounded-2xl bg-gradient-to-br from-blue-600 to-blue-700 dark:from-blue-700 dark:to-blue-800 text-white shadow-elevation-4">
            <h1 className="text-5xl font-bold">404</h1>
          </div>
        </div>
        <h2 className="text-3xl font-bold bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent mb-3">
          Page Not Found
        </h2>
        <p className="text-slate-600 dark:text-slate-400 mb-8 text-base leading-relaxed">
          Sorry, the page you're looking for doesn't exist or has been moved. Please check the URL or navigate back.
        </p>
        <button
          onClick={() => navigate("/")}
          className="inline-flex items-center justify-center px-8 py-3 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-bold rounded-xl transition-all duration-200 transform hover:scale-105 hover:-translate-y-0.5 shadow-elevation-3 hover:shadow-elevation-5"
        >
          <Home className="w-5 h-5 mr-2" />
          Go to Home
        </button>
      </div>
    </div>
  );
};

export default NotFound;



