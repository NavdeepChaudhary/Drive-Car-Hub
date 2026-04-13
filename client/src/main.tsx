import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { ClerkProvider } from '@clerk/clerk-react'
import './index.css'
import './global.css'
import App from './App.tsx'

const PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY

if (!PUBLISHABLE_KEY) {
  console.error("Clerk Publishable Key is missing. Please add VITE_CLERK_PUBLISHABLE_KEY to your .env file or environment variables.");
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {PUBLISHABLE_KEY ? (
      <ClerkProvider publishableKey={PUBLISHABLE_KEY}>
        <App />
      </ClerkProvider>
    ) : (
      <div style={{ 
        display: 'flex', 
        height: '100vh', 
        width: '100vw', 
        alignItems: 'center', 
        justifyContent: 'center', 
        background: 'linear-gradient(to bottom right, #1e293b, #0f172a)',
        color: 'white',
        fontFamily: 'sans-serif',
        textAlign: 'center',
        padding: '20px'
      }}>
        <div>
          <h1 style={{ color: '#ef4444' }}>Configuration Error</h1>
          <p>The Clerk Publishable Key is missing.</p>
          <p style={{ opacity: 0.8 }}>If you are the developer, please add <b>VITE_CLERK_PUBLISHABLE_KEY</b> to your Vercel/Environment variables.</p>
        </div>
      </div>
    )}
  </StrictMode>,
)
