/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#0b0f19',
        card: '#151b26',
        border: '#222f44',
        text: '#f8fafc',
        primary: {
          50: '#f0f7ff',
          100: '#e0effe',
          200: '#bae0fd',
          300: '#7cc8fc',
          400: '#38acf8',
          500: '#0ea5e9', // Cyber Sky Blue
          600: '#0284c7',
          700: '#0369a1',
          800: '#07557e',
          900: '#0c4767',
        },
        security: {
          stride: '#ec4899', // Pinkish
          linddun: '#a855f7', // Purple
          entity: '#3b82f6', // Blue
          process: '#10b981', // Green
          store: '#f59e0b', // Yellow
          boundary: '#ef4444', // Red
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['Fira Code', 'JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
