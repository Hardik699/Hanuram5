import { Request, Response, NextFunction } from "express";

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  timestamp?: string;
}

// Custom error class for API errors
export class ApiError extends Error {
  constructor(
    public statusCode: number,
    public message: string,
    public data?: any,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// Standardized error response helper
export function errorResponse(
  res: Response,
  statusCode: number,
  message: string,
  error?: any,
): ApiResponse {
  const isDevelopment = process.env.NODE_ENV === "development";
  
  console.error(
    `[ERROR ${statusCode}] ${message}`,
    isDevelopment ? error : "",
  );

  const response: ApiResponse = {
    success: false,
    message,
    timestamp: new Date().toISOString(),
  };

  if (isDevelopment && error) {
    response.error = error instanceof Error ? error.message : String(error);
  }

  res.status(statusCode).json(response);
  return response;
}

// Standardized success response helper
export function successResponse<T>(
  res: Response,
  data: T,
  message = "Request successful",
  statusCode = 200,
): ApiResponse<T> {
  const response: ApiResponse<T> = {
    success: true,
    message,
    data,
    timestamp: new Date().toISOString(),
  };

  res.status(statusCode).json(response);
  return response;
}

// Global error handling middleware
export function errorHandler(
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction,
) {
  // Handle ApiError instances
  if (err instanceof ApiError) {
    return errorResponse(res, err.statusCode, err.message, err.data);
  }

  // Handle JSON parsing errors
  if (err instanceof SyntaxError && "body" in err) {
    return errorResponse(res, 400, "Invalid JSON in request body", err);
  }

  // Handle validation errors
  if (err.name === "ValidationError") {
    return errorResponse(res, 400, "Validation failed", err.message);
  }

  // Handle MongoDB errors
  if (err.name === "MongoError" || err.name === "MongooseError") {
    return errorResponse(res, 500, "Database operation failed", err);
  }

  // Handle timeout errors
  if (err.code === "ETIMEDOUT") {
    return errorResponse(res, 408, "Request timeout", err);
  }

  // Default error handling
  const statusCode = err.statusCode || 500;
  const message = err.message || "An unexpected error occurred";

  return errorResponse(res, statusCode, message, err);
}

// Async route wrapper to catch errors automatically
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Logger utility
export class Logger {
  static info(message: string, data?: any) {
    console.log(`[INFO] ${new Date().toISOString()} - ${message}`, data || "");
  }

  static warn(message: string, data?: any) {
    console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, data || "");
  }

  static error(message: string, error?: any) {
    console.error(
      `[ERROR] ${new Date().toISOString()} - ${message}`,
      error || "",
    );
  }

  static debug(message: string, data?: any) {
    if (process.env.NODE_ENV === "development") {
      console.debug(`[DEBUG] ${new Date().toISOString()} - ${message}`, data || "");
    }
  }
}

// Validation error response
export function validationError(
  res: Response,
  field: string,
  message: string,
): ApiResponse {
  return errorResponse(res, 400, `Validation error: ${field} - ${message}`);
}

// Not found error response
export function notFoundError(res: Response, resource: string): ApiResponse {
  return errorResponse(res, 404, `${resource} not found`);
}

// Unauthorized error response
export function unauthorizedError(res: Response): ApiResponse {
  return errorResponse(res, 401, "Unauthorized access");
}

// Forbidden error response
export function forbiddenError(res: Response): ApiResponse {
  return errorResponse(res, 403, "Access forbidden");
}

// Internal server error response
export function internalServerError(res: Response, error?: any): ApiResponse {
  return errorResponse(res, 500, "Internal server error", error);
}
