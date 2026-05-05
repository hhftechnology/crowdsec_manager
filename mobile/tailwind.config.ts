import type { Config } from "tailwindcss";
import tailwindcssAnimate from "tailwindcss-animate";

export default {
  darkMode: ["class"],
  content: ["./pages/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./app/**/*.{ts,tsx}", "./src/**/*.{ts,tsx}"],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "1rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      fontFamily: {
        display: ["var(--font-display)"],
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
      colors: {
        // shadcn aliases
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
          active: "hsl(var(--primary-active))",
          disabled: "hsl(var(--primary-disabled))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        success: {
          DEFAULT: "hsl(var(--success))",
          foreground: "hsl(var(--success-foreground))",
        },
        warning: {
          DEFAULT: "hsl(var(--warning))",
          foreground: "hsl(var(--warning-foreground))",
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

        // Anthropic-tinted tokens
        canvas: "hsl(var(--canvas))",
        "surface-soft": "hsl(var(--surface-soft))",
        "surface-card": "hsl(var(--surface-card))",
        "surface-cream-strong": "hsl(var(--surface-cream-strong))",
        "surface-dark": "hsl(var(--surface-dark))",
        "surface-dark-elevated": "hsl(var(--surface-dark-elevated))",
        "surface-dark-soft": "hsl(var(--surface-dark-soft))",
        hairline: "hsl(var(--hairline))",
        "hairline-soft": "hsl(var(--hairline-soft))",
        ink: "hsl(var(--ink))",
        "body-strong": "hsl(var(--body-strong))",
        body: "hsl(var(--body))",
        "muted-soft": "hsl(var(--muted-soft))",
        "on-primary": "hsl(var(--on-primary))",
        "on-dark": "hsl(var(--on-dark))",
        "on-dark-soft": "hsl(var(--on-dark-soft))",
        "accent-teal": "hsl(var(--accent-teal))",
        "accent-amber": "hsl(var(--accent-amber))",
        error: "hsl(var(--error))",
      },
      fontSize: {
        "display-xl": ["64px", { lineHeight: "1.05", letterSpacing: "0" }],
        "display-lg": ["48px", { lineHeight: "1.1", letterSpacing: "0" }],
        "display-md": ["28px", { lineHeight: "1.15", letterSpacing: "0" }],
        "display-sm": ["22px", { lineHeight: "1.2", letterSpacing: "0" }],
        "title-lg": ["18px", { lineHeight: "1.3" }],
        "title-md": ["16px", { lineHeight: "1.4" }],
        "title-sm": ["14px", { lineHeight: "1.4" }],
        "body-md": ["15px", { lineHeight: "1.55" }],
        "body-sm": ["13px", { lineHeight: "1.55" }],
        caption: ["12px", { lineHeight: "1.4" }],
        "caption-uppercase": ["10px", { lineHeight: "1.4", letterSpacing: "0" }],
        code: ["12px", { lineHeight: "1.6" }],
        button: ["13px", { lineHeight: "1" }],
        "nav-link": ["14px", { lineHeight: "1.4" }],
      },
      spacing: {
        xxs: "4px",
        xs: "8px",
        sm: "12px",
        md: "16px",
        lg: "24px",
        xl: "32px",
        xxl: "48px",
        section: "96px",
      },
      borderRadius: {
        xs: "4px",
        sm: "calc(var(--radius) - 4px)",
        md: "calc(var(--radius) - 2px)",
        lg: "var(--radius)",
        xl: "16px",
        pill: "9999px",
      },
      boxShadow: {
        subtle: "0 1px 3px rgba(20,20,19,0.08)",
        "focus-ring": "0 0 0 3px hsl(var(--primary) / 0.15)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "fade-in": {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "slide-up": {
          from: { opacity: "0", transform: "translateY(16px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-soft": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.6" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "fade-in": "fade-in 0.3s ease-out",
        "slide-up": "slide-up 0.4s ease-out",
        "pulse-soft": "pulse-soft 2s ease-in-out infinite",
      },
    },
  },
  plugins: [tailwindcssAnimate],
} satisfies Config;
