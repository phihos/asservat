import { defineConfig } from 'vitest/config';

export default defineConfig({
  build: { sourcemap: false, assetsInlineLimit: 0 },
  test: { environment: 'jsdom', setupFiles: ['src/test-setup.ts'], include: ['src/**/*.test.ts', 'src/**/*.test.tsx'], restoreMocks: true },
});
