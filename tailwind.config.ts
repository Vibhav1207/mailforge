import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      fontFamily: {
        sans: ["var(--font-geist-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "monospace"],
      },
      colors: {
        // Postvane Resend-Inspired Palette
        pv: {
          bg: "#08090A",
          secondary: "#0D0F11",
          surface: "#111315",
          elevated: "#171A1D",
          hover: "#1D2125",
          border: "#262A2E",
          "border-subtle": "#1C2024",
          text: "#F5F5F5",
          secondaryText: "#A1A1AA",
          muted: "#71717A",
          disabled: "#45494E",
          accent: "#FFFFFF",
          "accent-hover": "#E5E7EB",
          success: "#22C55E",
          "success-muted": "#102719",
          warning: "#F59E0B",
          error: "#EF4444",
          info: "#60A5FA",
        },
        border: "var(--border)",
        input: "var(--input)",
        ring: "var(--ring)",
        background: "var(--background)",
        foreground: "var(--foreground)",
      },
      borderRadius: {
        DEFAULT: "6px",
        md: "8px",
        lg: "10px",
        xl: "12px",
      },
    },
  },
  plugins: [],
};

export default config;
