export const dynamic = 'force-dynamic';

function readRuntimeConfig() {
  return {
    backendUrl: process.env.API_BASE_URL?.trim() ?? '',
  };
}

export function GET() {
  return new Response(
    `window.__RUNTIME_CONFIG__ = Object.freeze(${JSON.stringify(readRuntimeConfig())});`,
    {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Content-Type': 'application/javascript; charset=utf-8',
      },
    },
  );
}