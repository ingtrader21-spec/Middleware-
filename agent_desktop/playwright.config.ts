import { defineConfig, devices } from "@playwright/test";

const port = process.env.PLAYWRIGHT_PORT ?? "4173";
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./tests/browser",
  timeout: 30_000,
  retries: 0,
  reporter: [["line"], ["json", { outputFile: "test-results/playwright-results.json" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], permissions: ["microphone"], launchOptions: { args: ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", "--autoplay-policy=no-user-gesture-required"] } } },
    { name: "firefox", use: { ...devices["Desktop Firefox"], launchOptions: { firefoxUserPrefs: { "media.navigator.streams.fake": true, "media.navigator.permission.disabled": true } } } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: {
    command: `npm run build -- --mode staging && npx vite preview --host 127.0.0.1 --port ${port}`,
    url: baseURL,
    reuseExistingServer: false,
    env: {
      VITE_APP_ENV: "staging",
      VITE_SAFE_MODE: "false",
      VITE_MOCK_MODE: "false",
      VITE_DISABLE_LIVE_INTEGRATIONS: "false",
      VITE_SIP_ENABLED: "true",
      VITE_WEBRTC_ENABLED: "true",
    },
  },
});
