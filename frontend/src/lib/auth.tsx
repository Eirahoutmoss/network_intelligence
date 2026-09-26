import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, setUnauthorizedHandler } from '@/api/client'
import type { Role, User } from '@/api/types'

interface AuthState {
  user: User | null
  loading: boolean
  info: { version: string; simulator: boolean; llm: boolean } | null
  login: (u: string, p: string) => Promise<void>
  logout: () => Promise<void>
  can: (r: Role) => boolean
}

const Ctx = createContext<AuthState | null>(null)
const rank: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 }

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [info, setInfo] = useState<AuthState['info']>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const r = await api.get<{ user: User }>('/api/auth/me')
      setUser(r.user)
      setInfo(await api.get('/api/info'))
    } catch {
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null))
    refresh()
  }, [refresh])

  const login = async (username: string, password: string) => {
    const r = await api.post<{ user: User }>('/api/auth/login', { username, password })
    setUser(r.user)
    setInfo(await api.get('/api/info'))
  }
  const logout = async () => {
    await api.post('/api/auth/logout').catch(() => undefined)
    setUser(null)
  }
  const can = (r: Role) => !!user && rank[user.role] >= rank[r]
  return <Ctx.Provider value={{ user, loading, info, login, logout, can }}>{children}</Ctx.Provider>
}

export function useAuth() {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth outside provider')
  return c
}
