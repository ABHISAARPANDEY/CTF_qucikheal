import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import './index.css';
import App from './App.jsx';
import { RealtimeProvider } from './lib/RealtimeProvider';
import { ThreatReactionOverlay } from './components/ThreatReactionOverlay';
import { wsUrl } from './lib/api';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <RealtimeProvider url={wsUrl()}>
        <App />
      {
        }
      <ThreatReactionOverlay />
    </RealtimeProvider>
    </BrowserRouter>
  </StrictMode>
);