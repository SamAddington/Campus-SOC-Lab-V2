import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "monospace",
        ],
      },
      colors: {
        // SIEM-like neutral surface scale
        base:    "#0b0f14",
        surface: "#0f141b",
        muted:   "#131a23",
        elev:    "#18212c",
        border:  "#1f2a37",
        line:    "#243244",
        text:    "#e5e7eb",
        subtle:  "#94a3b8",
        dim:     "#64748b",
        // Brand / accent
        accent: {
          DEFAULT: "#22d3ee", // cyan-400
          600: "#0891b2",
        },
        // Severity palette (intentionally distinct hues)
        sev: {
          info:     "#60a5fa", // blue-400
          low:      "#34d399", // emerald-400
          medium:   "#fbbf24", // amber-400
          high:     "#fb923c", // orange-400
          critical: "#f43f5e", // rose-500
        },
      },
      boxShadow: {
        card: "0 1px 0 0 rgba(255,255,255,0.04), 0 1px 3px 0 rgba(0,0,0,0.35)",
        ring: "0 0 0 1px rgba(34,211,238,0.35)",
      },
      borderRadius: {
        xl: "0.9rem",
      },
      keyframes: {
        pulseDot: {
          "0%,100%": { opacity: "0.55" },
          "50%":     { opacity: "1" },
        },
      },
      animation: {
        pulseDot: "pulseDot 1.6s ease-in-out infinite",
      },
    },
  },
  plugins: [],
} satisfies Config;
