import { Request, Response, NextFunction } from "express";

// Sanitize input to prevent XSS attacks
export function sanitizeInput(input: string): string {
  if (typeof input !== "string") return input;
  
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

// Validate email format
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Validate phone number (basic check)
export function isValidPhoneNumber(phone: string): boolean {
  const phoneRegex = /^[\d\s\-\+\(\)]*$/;
  return phone.length >= 7 && phoneRegex.test(phone);
}

// Validate MongoDB ObjectId format
export function isValidObjectId(id: string): boolean {
  return /^[0-9a-f]{24}$/i.test(id);
}

// Security headers middleware
export function securityHeaders(_req: Request, res: Response, next: NextFunction) {
  // Prevent XSS attacks
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  
  // Prevent clickjacking
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
  
  // Disable content type sniffing
  res.setHeader("Content-Security-Policy-Report-Only", "default-src 'self'");
  
  // HSTS (HTTP Strict Transport Security)
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  
  next();
}

// Rate limiting - simple implementation
const requestCounts = new Map<string, Array<number>>();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 300; // reduced from 1000

export function simpleRateLimit(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || "unknown";

  // Skip rate limiting for localhost (development environment)
  if (ip === "127.0.0.1" || ip === "localhost" || ip?.startsWith("::1")) {
    return next();
  }

  const now = Date.now();

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, []);
  }

  const timestamps = requestCounts.get(ip)!;

  // Remove old timestamps outside the window
  const recentTimestamps = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW);

  if (recentTimestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({
      success: false,
      message: "Too many requests. Please try again later.",
    });
  }

  recentTimestamps.push(now);
  requestCounts.set(ip, recentTimestamps);

  next();
}

// Input validation middleware
export function validateInput(req: Request, res: Response, next: NextFunction) {
  // Validate request body if present
  if (req.body && typeof req.body === "object") {
    for (const [key, value] of Object.entries(req.body)) {
      if (typeof value === "string") {
        // Basic length check to prevent buffer overflow
        if (value.length > 10000) {
          return res.status(400).json({
            success: false,
            message: `Field "${key}" exceeds maximum length`,
          });
        }
      }
    }
  }
  
  // Validate query parameters
  if (req.query && typeof req.query === "object") {
    for (const [key, value] of Object.entries(req.query)) {
      if (typeof value === "string" && value.length > 1000) {
        return res.status(400).json({
          success: false,
          message: `Query parameter "${key}" exceeds maximum length`,
        });
      }
    }
  }
  
  next();
}

// CSRF Protection - basic token validation
const csrfTokens = new Set<string>();

export function generateCSRFToken(): string {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

export function validateCSRFToken(token: string): boolean {
  return csrfTokens.has(token);
}

export function registerCSRFToken(token: string): void {
  csrfTokens.add(token);
  
  // Clean up old tokens periodically (keep last 1000)
  if (csrfTokens.size > 1000) {
    const tokensArray = Array.from(csrfTokens);
    csrfTokens.clear();
    tokensArray.slice(-1000).forEach((t) => csrfTokens.add(t));
  }
}

// Prevent NoSQL injection
export function preventNoSQLInjection(obj: any): any {
  if (obj === null || obj === undefined) return obj;
  
  if (typeof obj === "string") {
    // Check for common NoSQL operators
    if (obj.startsWith("$") || obj.startsWith("{") || obj.startsWith("[")) {
      throw new Error("Potentially malicious input detected");
    }
    return obj;
  }
  
  if (typeof obj === "object") {
    if (Array.isArray(obj)) {
      return obj.map(preventNoSQLInjection);
    }
    
    const cleaned: any = {};
    for (const [key, value] of Object.entries(obj)) {
      if (key.startsWith("$")) {
        throw new Error("Potentially malicious input detected");
      }
      cleaned[key] = preventNoSQLInjection(value);
    }
    return cleaned;
  }
  
  return obj;
}

// Password validation
export function isValidPassword(password: string): boolean {
  // Minimum 8 characters, at least one uppercase, one lowercase, one number
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
  return passwordRegex.test(password);
}
