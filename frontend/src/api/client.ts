export class ApiError extends Error {
  status: number;
  details: unknown;

  constructor(status: number, message: string, details?: unknown) {
    super(`${status}: ${message}`);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

function errorMessage(body: unknown, fallback: string) {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === 'string') return detail;
    if (detail && typeof detail === 'object' && 'password' in detail) {
      const password = (detail as { password?: unknown }).password;
      if (Array.isArray(password)) return password.join(' ');
    }
    return JSON.stringify(detail);
  }
  return fallback;
}

export async function apiRequest<T>(
  path: string,
  init: Omit<RequestInit, 'body'> & { body?: BodyInit | object | null; csrf?: boolean } = {},
): Promise<T> {
  const { csrf = false, ...requestInit } = init;
  const headers = new Headers(init.headers);
  const method = (init.method ?? 'GET').toUpperCase();
  const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method);
  let body = init.body;

  if (body && !(body instanceof FormData) && typeof body !== 'string') {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(body);
  }
  headers.set('Accept', 'application/json');
  if ((unsafe || csrf) && csrfToken) headers.set('X-CSRF-Token', csrfToken);

  const response = await fetch(path, {
    ...requestInit,
    method,
    body: body as BodyInit | null | undefined,
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    const contentType = response.headers.get('content-type') ?? '';
    const details = contentType.includes('application/json')
      ? await response.json().catch(() => null)
      : await response.text().catch(() => null);
    if (response.status === 401 && typeof window !== 'undefined') {
      window.dispatchEvent(new Event('vulnerability-workbench:unauthorized'));
    }
    throw new ApiError(response.status, errorMessage(details, response.statusText), details);
  }

  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) return response.json() as Promise<T>;
  return (await response.text()) as T;
}

export async function downloadFromApi(path: string, filename?: string) {
  const response = await fetch(path, { credentials: 'include' });
  if (!response.ok) {
    throw new ApiError(response.status, response.statusText);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download =
    filename ??
    response.headers.get('content-disposition')?.match(/filename="?([^"]+)"?/)?.[1] ??
    'vulncat-export';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function toQueryString(values: Record<string, unknown>) {
  const query = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    if (Array.isArray(value)) {
      value.forEach((entry) => query.append(key, String(entry)));
    } else {
      query.set(key, String(value));
    }
  });
  const rendered = query.toString();
  return rendered ? `?${rendered}` : '';
}

export function normalizeCollection<T>(payload: unknown): {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
} {
  if (Array.isArray(payload)) {
    return { items: payload as T[], total: payload.length, page: 1, pageSize: payload.length || 20 };
  }
  if (!payload || typeof payload !== 'object') {
    return { items: [], total: 0, page: 1, pageSize: 20 };
  }
  const object = payload as Record<string, unknown>;
  const items =
    (object.items as T[] | undefined) ??
    (object.results as T[] | undefined) ??
    (object.data as T[] | undefined) ??
    [];
  return {
    items,
    total: Number(object.total ?? object.count ?? items.length),
    page: Number(object.page ?? 1),
    pageSize: Number(object.page_size ?? object.pageSize ?? object.limit ?? (items.length || 20)),
  };
}
