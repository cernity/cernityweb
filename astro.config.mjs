import { defineConfig } from 'astro/config';

// Static marketing + docs site for Cernity NDR. Output is a plain static bundle
// (S3 + CloudFront). No SSR/runtime — everything renders at build time.
export default defineConfig({
  site: 'https://cernity.io', // canonical for sitemap/OG; served on the CloudFront default domain until cutover
  output: 'static',
  build: { format: 'directory' },
});
