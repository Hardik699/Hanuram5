import React, { createContext, useState, useCallback, useEffect } from "react";

export interface User {
  id: string;
  username: string;
  email: string;
  role_id: number;
  permissions: string[];
  modules?: string[];
}

export interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  isAuthenticated: boolean;
  hasPermission: (permission: string | string[]) => boolean;
  canAccess: (module: string) => boolean;
}

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined,
);

interface AuthProviderProps {
  children: React.ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Load user from localStorage on mount
  useEffect(() => {
    const storedUser = localStorage.getItem("user");
    const storedToken = localStorage.getItem("auth_token");

    if (storedUser && storedToken) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (error) {
        console.error("Error loading stored user:", error);
        localStorage.removeItem("user");
        localStorage.removeItem("auth_token");
      }
    }

    setLoading(false);
  }, []);

  const login = useCallback(
    async (username: string, password: string): Promise<boolean> => {
      try {
        setLoading(true);

        const response = await fetch("/api/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ username, password }),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || "Login failed");
        }

        const data = await response.json();

        if (data.success && data.user) {
          setUser(data.user);
          localStorage.setItem("user", JSON.stringify(data.user));
          localStorage.setItem("auth_token", data.token);
          localStorage.setItem("username", data.user.username);
          return true;
        }

        return false;
      } catch (error) {
        console.error("Login error:", error);
        return false;
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  const logout = useCallback(() => {
    setUser(null);
    localStorage.removeItem("user");
    localStorage.removeItem("auth_token");
    localStorage.removeItem("username");
  }, []);

  const hasPermission = useCallback(
    (permission: string | string[]): boolean => {
      if (!user) return false;

      // Admin user always has all permissions
      if (user.username === "admin") return true;

      const permissions = Array.isArray(permission) ? permission : [permission];
      return permissions.some((p) => user.permissions?.includes(p));
    },
    [user],
  );

  const canAccess = useCallback(
    (module: string): boolean => {
      if (!user) return false;

      // Admin user can access all modules
      if (user.username === "admin") return true;

      // Check if user has the module in their modules array
      return user.modules?.includes(module) || false;
    },
    [user],
  );

  const value: AuthContextType = {
    user,
    loading,
    login,
    logout,
    isAuthenticated: !!user,
    hasPermission,
    canAccess,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export default AuthProvider;
