export interface ApiErrorEnvelope {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
}

const apiMeta = document.querySelector<HTMLMetaElement>('meta[name="ctfkit-api-base"]');
export const API_BASE_URL = (apiMeta?.content || 'http://127.0.0.1:8000/api/v1').replace(/\/$/, '');

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code = 'API_ERROR',
    readonly details?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    const headers = new Headers(init.headers);
    if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers,
    });
  } catch (error) {
    throw new ApiError(
      error instanceof Error ? error.message : 'Unable to reach the CTFKit backend.',
      0,
      'NETWORK_ERROR',
    );
  }

  const payload = (await response.json().catch(() => ({}))) as T & ApiErrorEnvelope;
  if (!response.ok) {
    throw new ApiError(
      payload.error?.message || `Request failed with status ${response.status}.`,
      response.status,
      payload.error?.code,
      payload.error?.details,
    );
  }
  return payload;
}
