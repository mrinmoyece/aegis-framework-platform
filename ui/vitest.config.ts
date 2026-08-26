import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/setup-tests.ts"],
    exclude: ["e2e/**", "node_modules/**", "dist/**"],
    coverage: {
      provider: "v8",
      include: [
        "src/App.tsx",
        "src/api/**/*.ts",
        "src/components/**/*.{ts,tsx}",
        "src/contracts/**/*.ts",
        "src/operator-context.ts",
        "src/pages.tsx",
        "src/router.tsx",
        "src/safety.ts"
      ],
      exclude: ["src/**/*.test.{ts,tsx}", "src/test-fixtures.ts"],
      thresholds: {
        lines: 75,
        functions: 70,
        statements: 75,
        branches: 80
      }
    }
  }
});
