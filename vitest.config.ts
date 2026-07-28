import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: ["**/dist/**", "**/node_modules/**"],
    globalSetup: ["./test/azurite.ts"],
    include: ["packages/**/*.test.ts"],
    testTimeout: 30_000,
  },
});
