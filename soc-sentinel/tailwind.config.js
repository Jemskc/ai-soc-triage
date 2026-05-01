/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        base:    'rgb(var(--c-base)    / <alpha-value>)',
        panel:   'rgb(var(--c-panel)   / <alpha-value>)',
        card:    'rgb(var(--c-card)    / <alpha-value>)',
        hover:   'rgb(var(--c-hover)   / <alpha-value>)',
        border:  'rgb(var(--c-border)  / <alpha-value>)',
        primary: 'rgb(var(--c-primary) / <alpha-value>)',
        muted:   'rgb(var(--c-muted)   / <alpha-value>)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        pulse2:  'pulse2 2s cubic-bezier(0.4,0,0.6,1) infinite',
        fadeIn:  'fadeIn 0.2s ease-out',
      },
      keyframes: {
        pulse2: {
          '0%,100%': { opacity: '1', transform: 'scale(1)' },
          '50%':     { opacity: '0.4', transform: 'scale(0.85)' },
        },
        fadeIn: {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
};
