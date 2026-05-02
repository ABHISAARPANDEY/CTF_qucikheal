import { defineConfig, loadEnv } from 'vite';
import { cwd } from 'node:process';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';


export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, cwd(), '');
  const backendUrl = env.VITE_BACKEND_URL || 'http://localhost:8000';
  const wsTarget = backendUrl.replace(/^http/, 'ws');

  return {
    plugins: [react(), tailwindcss()],
    server: {
      proxy: {
        '/api': { target: backendUrl, changeOrigin: true },
        '/ws': { target: wsTarget, ws: true, changeOrigin: true },
        '/attack': { target: backendUrl, changeOrigin: true }
      }
    }
  };
});