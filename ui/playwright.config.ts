import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  retries: 0,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 8_000 },
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    ...devices["Desktop Chrome"]
  },
  webServer: [
    {
      command:
        "cd .. && PYTHONPATH=src AEGIS_MODE=demo .venv/bin/python -m uvicorn aegis_framework.api:app --host 127.0.0.1 --port 8123 --no-access-log",
      url: "http://127.0.0.1:8123/healthz",
      reuseExistingServer: false,
      timeout: 120_000
    },
    {
      command: "npm run dev",
      url: "http://127.0.0.1:4173",
      reuseExistingServer: false,
      timeout: 120_000
    }
  ]
});
