export type AuthUser = {
  id: number;
  full_name: string;
  email: string;
  is_active: boolean;
  created_at: string;
};

export type AuthResponse = {
  access_token: string;
  token_type: string;
  user: AuthUser;
};

const TOKEN_KEY = "singularity_access_token";
const USER_KEY = "singularity_user";

export function getToken(): string | null {
  return (
    window.localStorage.getItem(TOKEN_KEY) ??
    window.sessionStorage.getItem(TOKEN_KEY)
  );
}

export function getStoredUser(): AuthUser | null {
  const raw =
    window.localStorage.getItem(USER_KEY) ??
    window.sessionStorage.getItem(USER_KEY);

  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}

export function saveSession(
  response: AuthResponse,
  remember: boolean,
): void {
  const storage = remember
    ? window.localStorage
    : window.sessionStorage;

  storage.setItem(
    TOKEN_KEY,
    response.access_token,
  );

  storage.setItem(
    USER_KEY,
    JSON.stringify(response.user),
  );

  const otherStorage = remember
    ? window.sessionStorage
    : window.localStorage;

  otherStorage.removeItem(TOKEN_KEY);
  otherStorage.removeItem(USER_KEY);
}

export function clearSession(): void {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);

  window.sessionStorage.removeItem(TOKEN_KEY);
  window.sessionStorage.removeItem(USER_KEY);
}

export function isAuthenticated(): boolean {
  return Boolean(getToken());
}
