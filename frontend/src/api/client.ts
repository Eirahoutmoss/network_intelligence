// Thin fetch wrapper. All state-changing requests carry the custom
// X-Requested-With header the backend requires (CSRF protection).

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'X-Requested-With': 'nexus' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  })
  if (res.status === 401 && !path.startsWith('/api/auth/')) {
    onUnauthorized?.()
  }
  const text = await res.text()
  let data: unknown = undefined
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }
  if (!res.ok) {
    const msg = (data && typeof data === 'object' && 'error' in data ? String((data as { error: string }).error) : '') || res.statusText
    throw new ApiError(res.status, msg)
  }
  return data as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  del: <T>(path: string) => request<T>('DELETE', path),
}

// download fetches a file (with the CSRF header and session cookie) and saves it.
export async function download(method: 'GET' | 'POST', path: string, fallbackName: string, body?: unknown): Promise<void> {
  const headers: Record<string, string> = { 'X-Requested-With': 'nexus' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin' })
  if (!res.ok) {
    let msg = res.statusText
    try {
      msg = (await res.json()).error || msg
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, msg)
  }
  const cd = res.headers.get('Content-Disposition') || ''
  const name = /filename="([^"]+)"/.exec(cd)?.[1] || fallbackName
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '' && v !== false) u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}
