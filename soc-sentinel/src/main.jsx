import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import ErrorBoundary from './components/ErrorBoundary.jsx'

// Outermost boundary: without one, a throw anywhere unmounts the tree and the
// page goes blank with nothing on screen to say why.
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ErrorBoundary label="the dashboard">
      <App />
    </ErrorBoundary>
  </StrictMode>,
)
