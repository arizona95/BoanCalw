import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

export type Role = "owner" | "user";

export interface AuthUser {
  enabled: boolean;
  authenticated: boolean;
  email?: string;
  name?: string;
  role: Role;
  role_label: string;
  can_edit: boolean;
  org_id?: string;
}

const ROLE_LABEL: Record<Role, string> = {
  owner: "소유자",
  user: "사용자",
};

interface AuthCtx {
  user: AuthUser | null;
  loading: boolean;
  logout: () => Promise<void>;
  login: (email: string, password: string, orgId?: string) => Promise<void>;
}

const Ctx = createContext<AuthCtx>({
  user: null,
  loading: true,
  logout: async () => {},
  login: async () => {},
} as AuthCtx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchMe = async () => {
    try {
      const res = await fetch("/api/auth/me", { credentials: "include" });
      const data = await res.json();
      if (data.authenticated) {
        setUser({
          ...data,
          role_label: ROLE_LABEL[data.role as Role] ?? data.role_label,
        });
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchMe(); }, []);

  const logout = async () => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
    setUser(null);
  };

  const login = async (email: string, code: string, orgId?: string) => {
    const res = await fetch("/api/auth/verify-otp", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code, org_id: orgId ?? "" }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error((data as Record<string, string>).error ?? "로그인 실패");
    }
    await fetchMe();
  };

  return <Ctx.Provider value={{ user, loading, logout, login }}>{children}</Ctx.Provider>;
}

export function useAuth() {
  return useContext(Ctx);
}
