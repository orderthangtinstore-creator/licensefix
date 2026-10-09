// Cloudflare Worker example for a short LicenseFix PowerShell URL.
// Create a Worker and add a Custom Domain such as fix.thangtin.com.
const UPSTREAM = 'https://raw.githubusercontent.com/orderthangtinstore-creator/licensefix/main/launch.ps1';

export default {
  async fetch(request) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method not allowed', {
        status: 405, headers: { Allow: 'GET, HEAD' }
      });
    }
    const url = new URL(request.url);
    if (url.pathname !== '/' && url.pathname !== '/launch.ps1') {
      return new Response('Not found', { status: 404 });
    }
    const response = await fetch(UPSTREAM, {
      cf: { cacheEverything: false, cacheTtl: 0 }
    });
    if (!response.ok) {
      return new Response('Launcher unavailable', { status: 503 });
    }
    return new Response(request.method === 'HEAD' ? null : response.body, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
      }
    });
  }
};
