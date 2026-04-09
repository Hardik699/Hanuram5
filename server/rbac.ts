import { getDB } from "./db";
import { UserWithPermissions } from "@shared/api";

/**
 * Get all permissions for a user based on their role
 */
export async function getUserPermissions(roleId: number): Promise<string[]> {
  const db = getDB();
  if (!db) return [];

  try {
    // Get role permissions
    const rolePermissions = await db
      .collection("role_permissions")
      .find({ role_id: roleId })
      .toArray();

    const permissionIds = rolePermissions.map((rp: any) => rp.permission_id);

    if (permissionIds.length === 0) return [];

    // Get permission keys - query by permission_id, not _id
    const permissions = await db
      .collection("permissions")
      .find({ permission_id: { $in: permissionIds } })
      .toArray();

    return permissions.map((p: any) => p.permission_key);
  } catch (error) {
    console.error("Error getting user permissions:", error);
    return [];
  }
}

/**
 * Check if a user has a specific permission
 */
export async function hasPermission(
  roleId: number,
  requiredPermission: string,
): Promise<boolean> {
  const permissions = await getUserPermissions(roleId);
  return permissions.includes(requiredPermission);
}

/**
 * Check if a user has any of the required permissions
 */
export async function hasAnyPermission(
  roleId: number,
  requiredPermissions: string[],
): Promise<boolean> {
  const permissions = await getUserPermissions(roleId);
  return requiredPermissions.some((perm) => permissions.includes(perm));
}

/**
 * Check if a user has all of the required permissions
 */
export async function hasAllPermissions(
  roleId: number,
  requiredPermissions: string[],
): Promise<boolean> {
  const permissions = await getUserPermissions(roleId);
  return requiredPermissions.every((perm) => permissions.includes(perm));
}

/**
 * Get user with permissions
 */
export async function getUserWithPermissions(
  userId: string,
): Promise<UserWithPermissions | null> {
  const db = getDB();
  if (!db) return null;

  try {
    const { ObjectId } = await import("mongodb");
    const user = await db.collection("users").findOne({
      _id: new ObjectId(userId),
    });
    if (!user) return null;

    const permissions = await getUserPermissions(user.role_id);
    return {
      _id: user._id?.toString(),
      username: user.username,
      email: user.email,
      password: user.password,
      role_id: user.role_id,
      status: user.status,
      createdAt: user.createdAt,
      permissions,
    } as UserWithPermissions;
  } catch (error) {
    console.error("Error getting user with permissions:", error);
    return null;
  }
}

/**
 * Get all modules assigned to a user (module-based access control)
 */
export async function getUserModules(userId: string): Promise<string[]> {
  const db = getDB();
  if (!db) return [];

  try {
    const modules = await db
      .collection("user_modules")
      .find({ user_id: userId })
      .toArray();

    return modules.map((m: any) => m.module_key);
  } catch (error) {
    console.error("Error getting user modules:", error);
    return [];
  }
}

/**
 * Check if a user has access to a module
 */
export async function canAccessModule(
  userId: string,
  moduleKey: string,
): Promise<boolean> {
  // Admin user has access to all modules
  if (userId === "admin") return true;

  const modules = await getUserModules(userId);
  return modules.includes(moduleKey);
}
