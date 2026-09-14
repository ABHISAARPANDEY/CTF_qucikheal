import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import './index.css';
import App from './App.jsx';
import { RealtimeProvider } from './lib/RealtimeProvider';
import { wsUrl } from './lib/api';
import { initTheme } from './lib/theme';

initTheme();

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <RealtimeProvider url={wsUrl()}>
        <App />
      </RealtimeProvider>
    </BrowserRouter>
  </StrictMode>
);