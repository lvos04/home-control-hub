import { defineConfig } from '@playwright/test';

// Statuspagina-UI-tests (HC11; ONTWERPTAAL §12 en §13.2). Alleen Chromium. De pagina's komen uit de echte app
// (genereer_toestanden.py) en gaan met dezelfde headers (CSP) naar de browser.
export default defineConfig({
  testDir: '.',
  testMatch: /.*\.spec\.ts$/,
  fullyParallel: true,
  workers: 2, // geheugen is de grens op de gedeelde bouwmachine
  retries: 0,
  timeout: 240_000,
  reporter: [['list']],
  outputDir: 'test-results',
  use: { browserName: 'chromium', headless: true, locale: 'nl-NL', timezoneId: 'UTC' },
});
