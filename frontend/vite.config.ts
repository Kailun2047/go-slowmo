import { defineConfig, loadEnv, type UserConfig } from 'vite'
import react from '@vitejs/plugin-react'
import type { TestUserConfig } from 'vitest/config';

// https://vite.dev/config/
export default defineConfig(({mode}) => {
  const env = loadEnv(mode, process.cwd(), '');
  const config: UserConfig = {
    plugins: [react()],
    define: {
      __APP_ENV__: JSON.stringify(env.APP_ENV),
    },
  }
  if (env.VITE_DEV_MODE === '1') {
    config.server = {
      allowedHosts: true
    };
  }
  if (mode === 'test') {
    (config as UserConfig & {
      test: TestUserConfig
    }).test = {
      globals: true,
      setupFiles: ['./setup-vitest.ts'],
    };
  }
  return config;
})
