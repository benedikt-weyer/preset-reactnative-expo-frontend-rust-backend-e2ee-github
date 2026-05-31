/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./App.{ts,tsx}', './index.ts', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        accent: {
          50: '#eefcf6',
          500: '#14b87a',
          600: '#0f9d68',
          700: '#0c7850',
        },
      },
      boxShadow: {
        card: '0 18px 40px rgba(15, 23, 42, 0.08)',
      },
    },
  },
  plugins: [],
};