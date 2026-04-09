import React from "react";
import { useAuth } from "@/hooks/useAuth";

interface PermissionGateProps {
  permission: string | string[];
  children: React.ReactNode;
  fallback?: React.ReactNode;
  requireAll?: boolean;
}

/**
 * PermissionGate component - conditionally renders content based on user permissions
 *
 * @param permission - Single permission string or array of permissions
 * @param children - Content to render if permission is granted
 * @param fallback - Content to render if permission is denied (default: null)
 * @param requireAll - If true and multiple permissions, all must be present (default: false, requires any)
 */
export const PermissionGate: React.FC<PermissionGateProps> = ({
  permission,
  children,
  fallback = null,
  requireAll = false,
}) => {
  const { user } = useAuth();

  if (!user) {
    return <>{fallback}</>;
  }

  const hasPermission = (perms: string[]) => {
    const permissions = Array.isArray(permission) ? permission : [permission];

    if (requireAll) {
      return permissions.every((p) => perms.includes(p));
    } else {
      return permissions.some((p) => perms.includes(p));
    }
  };

  const canAccess = hasPermission(user.permissions || []);

  return <>{canAccess ? children : fallback}</>;
};

export default PermissionGate;

