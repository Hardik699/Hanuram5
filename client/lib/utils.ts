import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format date to dd/mm/yyyy
 */
export function formatDate(date: string | Date | null | undefined): string {
  if (!date) return "—";
  const d = new Date(date);
  if (isNaN(d.getTime())) return "—";
  const dd = String(d.getDate()).padStart(2, "0");
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const yyyy = d.getFullYear();
  return `${dd}/${mm}/${yyyy}`;
}

/**
 * Interface for unit conversions
 */
export interface UnitConversion {
  fromUnitId: string;
  fromUnitName: string;
  toUnitId: string;
  toUnitName: string;
  conversionFactor: number;
  addedAt?: string;
  addedBy?: string;
}

/**
 * Convert quantity from one unit to another
 * @param quantity - The quantity to convert
 * @param fromUnitId - The source unit ID
 * @param toUnitId - The target unit ID
 * @param conversions - Array of available unit conversions
 * @returns The converted quantity, or the original quantity if no conversion found
 */
export function convertUnits(
  quantity: number,
  fromUnitId: string,
  toUnitId: string,
  conversions: UnitConversion[] = []
): number {
  // If converting to the same unit, return as is
  if (fromUnitId === toUnitId) {
    return quantity;
  }

  // Find the conversion from source unit to target unit
  const directConversion = conversions.find(
    (c) => c.fromUnitId === fromUnitId && c.toUnitId === toUnitId
  );

  if (directConversion) {
    return quantity * directConversion.conversionFactor;
  }

  // If no direct conversion found, return the original quantity
  // In a production app, you might want to log a warning here
  return quantity;
}

/**
 * Enhanced fetch wrapper with better error handling and logging
 * Provides more detailed error messages for debugging network issues
 */
export async function apiFetch(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

  try {
    console.log(`📡 API Request: ${options.method || "GET"} ${url}`);

    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn(
        `⚠️ API Response Error: ${response.status} ${response.statusText} for ${url}`,
      );
    } else {
      console.log(`✅ API Response: ${response.status} for ${url}`);
    }

    return response;
  } catch (error) {
    clearTimeout(timeoutId);

    if (error instanceof TypeError) {
      // Network error - more common in production
      console.error(`❌ Network Error (Failed to fetch):`, {
        url,
        method: options.method || "GET",
        error: error.message,
        timestamp: new Date().toISOString(),
      });

      // Check if it's a timeout
      if (error.message.includes("aborted")) {
        throw new Error(`Request timeout: ${url} took longer than 30 seconds`);
      }

      throw new Error(
        `Failed to connect to ${url}. Please check your internet connection and ensure the server is running.`,
      );
    } else if (error instanceof Error) {
      console.error(`❌ API Error for ${url}:`, error.message);
      throw error;
    } else {
      console.error(`❌ Unknown error fetching ${url}:`, error);
      throw new Error("An unknown error occurred while fetching data");
    }
  }
}
