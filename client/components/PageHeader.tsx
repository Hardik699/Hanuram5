import { ChevronRight, Home, ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";

interface Breadcrumb {
  label: string;
  path?: string;
  href?: string;
}

interface PageHeaderProps {
  title: string;
  description?: string;
  breadcrumbs?: Breadcrumb[];
  actions?: React.ReactNode;
  icon?: React.ReactNode;
  showBackButton?: boolean;
}

export function PageHeader({
  title,
  description,
  breadcrumbs,
  actions,
  icon,
  showBackButton,
}: PageHeaderProps) {
  const navigate = useNavigate();

  return (
    <div className="mb-6 sm:mb-8 animate-material-fade-in">
      {/* Breadcrumbs - Material Design */}
      {breadcrumbs && breadcrumbs.length > 0 && (
        <div className="flex items-center gap-2 mb-4 text-sm">
          <button
            onClick={() => navigate("/")}
            className="text-muted-foreground hover:text-foreground dark:hover:text-sidebar-foreground transition-colors duration-200"
            title="Home"
          >
            <Home className="w-4 h-4" />
          </button>
          {breadcrumbs.map((crumb, index) => (
            <div key={index} className="flex items-center gap-2">
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              {crumb.path || crumb.href ? (
                <button
                  onClick={() => navigate(crumb.path || crumb.href || "/")}
                  className="text-muted-foreground hover:text-primary dark:hover:text-primary transition-colors duration-200 capitalize"
                >
                  {crumb.label}
                </button>
              ) : (
                <span className="text-foreground font-medium capitalize">
                  {crumb.label}
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Header Content */}
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 sm:gap-4">
        <div className="flex items-center gap-3 sm:gap-4 min-w-0">
          {showBackButton && (
            <button
              onClick={() => navigate(-1)}
              className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-400 transition-all flex-shrink-0"
              title="Go back"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
          )}
          {icon && (
            <div className="flex items-center justify-center w-10 h-10 sm:w-14 sm:h-14 rounded-xl sm:rounded-2xl bg-gradient-to-br from-blue-500 to-blue-600 shadow-lg flex-shrink-0">
              <div className="text-white">{icon}</div>
            </div>
          )}
          <div className="min-w-0">
            <h1 className="text-xl sm:text-2xl md:text-3xl font-light text-foreground dark:text-white truncate">
              {title}
            </h1>
            {description && (
              <p className="text-xs sm:text-sm text-muted-foreground mt-0.5 font-normal line-clamp-2">
                {description}
              </p>
            )}
          </div>
        </div>

        {/* Actions */}
        {actions && (
          <div className="flex items-center gap-2 flex-wrap">
            {actions}
          </div>
        )}
      </div>
    </div>
  );
}

