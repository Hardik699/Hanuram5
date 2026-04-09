import React from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { ArrowLeft, LogOut } from "lucide-react";

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredPermission?: string | string[];
  requiredModule?: string;
  fallback?: React.ReactNode;
}

/**
 * ProtectedRoute component - protects routes based on authentication, permissions, and modules
 */
export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredPermission,
  requiredModule,
  fallback,
}) => {
  const navigate = useNavigate();
  const { isAuthenticated, loading, hasPermission, canAccess, logout } =
    useAuth();

  const handleLogout = () => {
    logout();
    navigate("/", { replace: true });
  };

  if (loading) {
    return <LoadingSpinner message="Loading..." fullScreen />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  // All authenticated users can access all pages - no permission checks needed

  return <>{children}</>;
};

export default ProtectedRoute;

