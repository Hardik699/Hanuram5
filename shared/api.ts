/**
 * Shared code between client and server
 * Useful to share types between client and server
 * and/or small pure JS functions that can be used on both client and server
 */

/**
 * Example response type for /api/demo
 */
export interface DemoResponse {
  message: string;
}

/**
 * Login request/response types
 */
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  success: boolean;
  message: string;
  user?: {
    id: string;
    username: string;
    email: string;
    role_id: number;
    permissions: string[];
  };
  token?: string;
}

/**
 * Database status response type
 */
export interface DBStatusResponse {
  status: "connected" | "disconnected" | "connecting";
  message: string;
}

/**
 * RBAC Types
 */
export interface User {
  _id?: string;
  username: string;
  email: string;
  password?: string;
  role_id: number;
  status: "active" | "blocked";
  createdAt: Date;
}

export interface Role {
  _id?: number;
  role_name: string;
}

export interface Permission {
  _id?: number;
  permission_key: string;
  description: string;
}

export interface RolePermission {
  role_id: number;
  permission_id: number;
}

export interface UserWithPermissions extends User {
  permissions: string[];
}
