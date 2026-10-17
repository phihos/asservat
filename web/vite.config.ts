import { defineConfig } from 'vitest/config';

export default defineConfig({
  build: { sourcemap: false, assetsInlineLimit: 0 },
  test: { environment: 'jsdom', include: ['src/**/*.test.ts', 'src/**/*.test.tsx'], restoreMocks: true },
});
