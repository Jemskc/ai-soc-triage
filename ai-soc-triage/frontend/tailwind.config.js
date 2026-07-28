/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        splunk: {
          dark: '#0D1316',
          panel: '#151C22',
          accent: '#E78A00',
          text: '#E8E8E8',
          danger: '#DC3528',
          success: '#00873C',
          warning: '#F89C1C'
        }
      }
    },
  },
  plugins: [],
}

