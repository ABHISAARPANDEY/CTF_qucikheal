import { defineConfig, loadEnv } from 'vite';
import { cwd } from 'node:process';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';


export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, cwd(), '');
  const backendUrl =
    env.VITE_API_BASE_URL || env.VITE_BACKEND_URL || 'http://localhost:8000';

  return {
    plugins: [react(), tailwindcss()],
    server: {
      proxy: {
        '/api': { target: backendUrl, changeOrigin: true },
        // Use HTTP `target` + `ws: true` (normal Upgrade). A bare `ws://` target is
        // easy to misconfigure and can add noisy proxy resets during dev reloads.
        '/ws': { target: backendUrl, ws: true, changeOrigin: true },
        '/attack': { target: backendUrl, changeOrigin: true }
      }
    }
  };
});