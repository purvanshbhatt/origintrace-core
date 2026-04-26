/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"Fira Code"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        background: '#040914', // Deep dark mode base
        surface: '#0f172a',    // panel backgrounds (slate-900)
        'surface-highlight': '#1e293b', // hover state (slate-800)
        border: '#334155',     // Borders (slate-700)
        neon: {
          cyan: '#00f0ff',
          green: '#39ff14',
          yellow: '#fbbf24',
          red: '#ff003c',
          purple: '#b142f5'
        },
        text: {
          primary: '#f8fafc',  // slate-50
          secondary: '#94a3b8', // slate-400
          muted: '#64748b'     // slate-500
        }
      },
      backgroundImage: {
        'cyber-grid': 'linear-gradient(to right, rgba(255,255,255,0.05) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.05) 1px, transparent 1px)',
      },
      animation: {
        'pulse-fast': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 8s linear infinite',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' }
        }
      }
    },
  },
  plugins: [],
}
