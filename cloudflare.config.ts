import { defineConfig } from 'cf/config';

// Static, client-side only site. No Worker code runs: Cloudflare serves the
// Vite build as assets. All Stellar work happens in the visitor's browser.
export default defineConfig({
  worker: {
    name: 'pq-wallet-tour',
    compatibilityDate: '2026-11-01',
    // Custom domain on the stellar.buzz zone (same account). Cloudflare creates
    // the DNS record and certificate on deploy.
    domains: ['quantum.stellar.buzz'],
    // Keep the first URL working. The canonical tag points to the custom domain.
    workersDev: true,
    assets: {
      notFoundHandling: 'single-page-application',
    },
  },
});
