import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./client/**/*.{ts,tsx}"],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        /* Brand Logo Color */
        brand: {
          DEFAULT: "#2563eb",
          dark: "#1e40af",
        },
        /* Material Design Color System */
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        surface: "hsl(var(--surface))",
        "surface-variant": "hsl(var(--surface-variant))",

        /* Primary Color - Deep Orange */
        primary: {
          DEFAULT: "hsl(var(--primary))",
          dark: "hsl(var(--primary-dark))",
          light: "hsl(var(--primary-light))",
          foreground: "hsl(var(--primary-foreground))",
        },

        /* Secondary Color - Light Blue */
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          dark: "hsl(var(--secondary-dark))",
          light: "hsl(var(--secondary-light))",
          foreground: "hsl(var(--secondary-foreground))",
        },

        /* Status Colors */
        success: {
          DEFAULT: "hsl(var(--success))",
          light: "hsl(123 100% 50%)",
          dark: "hsl(123 100% 30%)",
        },
        error: {
          DEFAULT: "hsl(var(--error))",
          light: "hsl(0 84% 70%)",
          dark: "hsl(0 84% 50%)",
        },
        warning: {
          DEFAULT: "hsl(var(--warning))",
          light: "hsl(33 100% 62%)",
          dark: "hsl(33 100% 42%)",
        },
        info: {
          DEFAULT: "hsl(var(--info))",
          light: "hsl(206 100% 60%)",
          dark: "hsl(206 100% 40%)",
        },

        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar-background))",
          foreground: "hsl(var(--sidebar-foreground))",
          primary: "hsl(var(--sidebar-primary))",
          "primary-foreground": "hsl(var(--sidebar-primary-foreground))",
          accent: "hsl(var(--sidebar-accent))",
          "accent-foreground": "hsl(var(--sidebar-accent-foreground))",
          border: "hsl(var(--sidebar-border))",
          ring: "hsl(var(--sidebar-ring))",
        },
      },

      /* Material Design Elevation System */
      boxShadow: {
        "elevation-0": "var(--elevation-0)",
        "elevation-1": "var(--elevation-1)",
        "elevation-2": "var(--elevation-2)",
        "elevation-3": "var(--elevation-3)",
        "elevation-4": "var(--elevation-4)",
        "elevation-6": "var(--elevation-6)",
        "elevation-8": "var(--elevation-8)",
        "elevation-12": "var(--elevation-12)",
        "elevation-16": "var(--elevation-16)",
        "elevation-24": "var(--elevation-24)",
      },

      /* Material Design Typography */
      fontFamily: {
        sans: ["Roboto", "Helvetica Neue", "Helvetica", "Arial", "sans-serif"],
        mono: ["Roboto Mono", "Courier New", "monospace"],
      },

      /* Material Design Spacing */
      spacing: {
        "0.5": "0.125rem" /* 2px */,
        "1": "0.25rem" /* 4px */,
        "1.5": "0.375rem" /* 6px */,
        "2": "0.5rem" /* 8px */,
        "2.5": "0.625rem" /* 10px */,
        "3": "0.75rem" /* 12px */,
        "3.5": "0.875rem" /* 14px */,
        "4": "1rem" /* 16px */,
        "5": "1.25rem" /* 20px */,
        "6": "1.5rem" /* 24px */,
        "7": "1.75rem" /* 28px */,
        "8": "2rem" /* 32px */,
      },

      borderRadius: {
        none: "0px",
        sm: "0.25rem" /* 4px */,
        DEFAULT: "0.5rem" /* 8px - Material Design standard */,
        md: "0.5rem" /* 8px */,
        lg: "0.75rem" /* 12px */,
        xl: "1rem" /* 16px */,
        "2xl": "1.5rem" /* 24px */,
        "3xl": "2rem" /* 32px */,
        full: "9999px",
      },

      transitionDuration: {
        default: "300ms",
        fast: "150ms",
        standard: "300ms",
        deceleration: "200ms",
        acceleration: "150ms",
      },

      transitionTimingFunction: {
        "material-standard": "cubic-bezier(0.4, 0, 0.2, 1)",
        "material-deceleration": "cubic-bezier(0, 0, 0.2, 1)",
        "material-acceleration": "cubic-bezier(0.4, 0, 1, 1)",
      },

      keyframes: {
        "accordion-down": {
          from: {
            height: "0",
          },
          to: {
            height: "var(--radix-accordion-content-height)",
          },
        },
        "accordion-up": {
          from: {
            height: "var(--radix-accordion-content-height)",
          },
          to: {
            height: "0",
          },
        },

        /* Material Design Animations */
        ripple: {
          "0%": { transform: "scale(0)", opacity: "1" },
          "100%": { transform: "scale(4)", opacity: "0" },
        },
        "material-fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "material-scale-up": {
          from: { opacity: "0", transform: "scale(0.95)" },
          to: { opacity: "1", transform: "scale(1)" },
        },
        "fade-in-up": {
          from: { opacity: "0", transform: "translateY(12px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "slide-in-right": {
          from: { opacity: "0", transform: "translateX(24px)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        "slide-in-left": {
          from: { opacity: "0", transform: "translateX(-24px)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        "slide-in-down": {
          from: { opacity: "0", transform: "translateY(-24px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "success-pulse": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.8" },
        },
        "page-load": {
          from: { opacity: "0", transform: "translateY(20px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "scale-in": {
          from: { opacity: "0", transform: "scale(0.9)" },
          to: { opacity: "1", transform: "scale(1)" },
        },
        bounce: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-10px)" },
        },
        pulse: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.5" },
        },
        "db-sync": {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        shimmer: {
          "0%": { "background-position": "-1000px 0" },
          "100%": { "background-position": "1000px 0" },
        },
      },

      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        ripple: "ripple 0.6s ease-out",
        "material-fade-in":
          "material-fade-in var(--animation-deceleration) ease-out",
        "material-scale-up":
          "material-scale-up var(--animation-standard) cubic-bezier(0.4, 0, 0.2, 1)",
        "fade-in-up": "fade-in-up var(--animation-standard) ease-out both",
        "slide-in-right": "slide-in-right var(--animation-standard) ease-out",
        "slide-in-left": "slide-in-left var(--animation-standard) ease-out",
        "slide-in-down": "slide-in-down var(--animation-standard) ease-out",
        "scale-in": "scale-in var(--animation-standard) ease-out",
        "page-load": "page-load 0.5s ease-out",
        "success-pulse": "success-pulse 2s ease-in-out infinite",
        "bounce-gentle": "bounce 2s infinite",
        pulse: "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "db-sync": "db-sync 1s linear infinite",
        shimmer: "shimmer 2s infinite",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
} satisfies Config;
