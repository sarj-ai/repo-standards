import metadata from '../../package.json' with { type: 'json' };

export const SITE_URL = metadata.homepage;
export const SITE_ORIGIN = new globalThis.URL(SITE_URL).origin;
export const SITE_BASE_PATH = new globalThis.URL(SITE_URL).pathname;
export const LEGACY_HOSTNAME = 'repo-standards.sarj.ai';

export function siteHref(path: string): string {
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new TypeError('Project links must start with exactly one slash');
  }
  return `${SITE_BASE_PATH.slice(0, -1)}${path}`;
}

export function siteUrl(path: string): string {
  return new globalThis.URL(siteHref(path), SITE_ORIGIN).href;
}

export function legacyRedirect(requestUrl: string): string | undefined {
  const url = new globalThis.URL(requestUrl);
  if (url.hostname !== LEGACY_HOSTNAME) return undefined;
  const destination = new globalThis.URL(SITE_URL);
  destination.pathname = url.pathname.startsWith(SITE_BASE_PATH)
    ? url.pathname : `${SITE_BASE_PATH}${url.pathname.slice(1)}`;
  if (url.pathname === SITE_BASE_PATH.slice(0, -1)) destination.pathname = SITE_BASE_PATH;
  destination.search = url.search;
  return destination.href;
}
