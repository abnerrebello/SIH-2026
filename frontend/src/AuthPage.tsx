import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { FormEvent } from "react";
import { ArrowRight, Eye, EyeOff, LockKeyhole } from "lucide-react";
import { Link, useLocation, useNavigate } from "react-router-dom";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

type AuthUser = {
  id: number;
  full_name: string;
  email: string;
  is_active: boolean;
  created_at: string;
};

type AuthResponse = {
  access_token: string;
  token_type: string;
  user: AuthUser;
};

export default function AuthPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [mode, setMode] = useState<"login" | "register">(
    new URLSearchParams(location.search).get("mode") === "register"
      ? "register"
      : "login",
  );

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [remember, setRemember] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const requestedMode =
      new URLSearchParams(location.search).get("mode") === "register"
        ? "register"
        : "login";

    setMode(requestedMode);
  }, [location.search]);

  const switchMode = (nextMode: "login" | "register") => {
    setError("");
    setPassword("");
    setMode(nextMode);

    navigate(
      nextMode === "register" ? "/auth?mode=register" : "/auth",
      { replace: true },
    );
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const endpoint =
        mode === "register"
          ? `${API_BASE}/auth/register`
          : `${API_BASE}/auth/login`;

      const payload =
        mode === "register"
          ? {
              full_name: fullName.trim(),
              email: email.trim(),
              password,
            }
          : {
              email: email.trim(),
              password,
            };

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        const detail = Array.isArray(data?.detail)
          ? data.detail
              .map((item: { msg?: string }) => item.msg)
              .filter(Boolean)
              .join(" ")
          : data?.detail;

        throw new Error(
          detail || "Authentication failed. Please try again.",
        );
      }

      const auth = data as AuthResponse;
      queryClient.clear();

      const storage = remember
        ? window.localStorage
        : window.sessionStorage;

      storage.setItem("singularity_access_token", auth.access_token);
      storage.setItem(
        "singularity_user",
        JSON.stringify(auth.user),
      );

      if (remember) {
        window.sessionStorage.removeItem("singularity_access_token");
        window.sessionStorage.removeItem("singularity_user");
      } else {
        window.localStorage.removeItem("singularity_access_token");
        window.localStorage.removeItem("singularity_user");
      }

      navigate("/CommandCenter", { replace: true });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to reach the authentication service.",
      );
    } finally {
      setLoading(false);
    }
  };

  const isLogin = mode === "login";

  return (
    <div className="auth-page auth-page-v3">
      <div className="auth-v3-atmosphere" aria-hidden="true">
        <div className="auth-v3-grid" />
        <div className="auth-v3-orb auth-v3-orb-a" />
        <div className="auth-v3-orb auth-v3-orb-b" />
        <div className="auth-v3-orb auth-v3-orb-c" />

        <div className="auth-v3-network">
          <span className="auth-v3-line auth-v3-line-a" />
          <span className="auth-v3-line auth-v3-line-b" />
          <span className="auth-v3-line auth-v3-line-c" />

          <i className="auth-v3-node auth-v3-node-a" />
          <i className="auth-v3-node auth-v3-node-b" />
          <i className="auth-v3-node auth-v3-node-c" />
          <i className="auth-v3-node auth-v3-node-d" />

          <i className="auth-v3-packet auth-v3-packet-a" />
          <i className="auth-v3-packet auth-v3-packet-b" />
        </div>

        <div className="auth-v3-scan" />
      </div>

      <header className="auth-v3-nav">
        <Link to="/" className="auth-v3-brand" aria-label="Singularity home">
          <span className="auth-v3-brand-mark" aria-hidden="true">
            <span>S</span>
            <i />
          </span>

          <span className="auth-v3-brand-copy">
            <strong>Singularity</strong>
            <small>Cyber Risk Intelligence</small>
          </span>
        </Link>

        <Link to="/" className="auth-v3-back">
          Back to platform
          <ArrowRight size={15} />
        </Link>
      </header>

      <main className="auth-v3-main">
        <section className="auth-v3-story">
          <span className="auth-v3-overline">Cyber Risk Intelligence</span>

          <h1>
            Security decisions
            <br />
            <span>with context.</span>
          </h1>

          <p>
            Bring your environment, vulnerabilities, attack paths and
            business impact into one clear security view.
          </p>

          <div className="auth-v3-rule" />

          <div className="auth-v3-points">
            <div>
              <span>01</span>
              <strong>Understand exposure</strong>
            </div>
            <div>
              <span>02</span>
              <strong>Trace attack paths</strong>
            </div>
            <div>
              <span>03</span>
              <strong>Prioritize what matters</strong>
            </div>
          </div>
        </section>

        <section className="auth-v3-panel">
          <div className="auth-v3-panel-inner">
            <div className="auth-v3-panel-heading">
              <div className="auth-v3-lock">
                <LockKeyhole size={17} />
              </div>

              <div>
                <span>{isLogin ? "SIGN IN" : "CREATE ACCOUNT"}</span>
                <h2>
                  {isLogin ? "Welcome back." : "Create your workspace."}
                </h2>
              </div>
            </div>

            <div className="auth-v3-tabs">
              <button
                type="button"
                className={isLogin ? "active" : ""}
                onClick={() => switchMode("login")}
              >
                Sign in
              </button>

              <button
                type="button"
                className={!isLogin ? "active" : ""}
                onClick={() => switchMode("register")}
              >
                Create account
              </button>
            </div>

            <form onSubmit={submit} className="auth-v3-form">
              {!isLogin && (
                <label>
                  <span>Full name</span>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(event) => setFullName(event.target.value)}
                    placeholder="Your name"
                    autoComplete="name"
                    required
                    minLength={2}
                  />
                </label>
              )}

              <label>
                <span>Email address</span>
                <input
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@company.com"
                  autoComplete="email"
                  required
                />
              </label>

              <label>
                <span>Password</span>

                <div className="auth-v3-password">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder={
                      isLogin ? "Enter your password" : "Minimum 8 characters"
                    }
                    autoComplete={
                      isLogin ? "current-password" : "new-password"
                    }
                    required
                    minLength={isLogin ? undefined : 8}
                  />

                  <button
                    type="button"
                    onClick={() => setShowPassword((value) => !value)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                  </button>
                </div>
              </label>

              <div className="auth-v3-options">
                <label className="auth-v3-remember">
                  <input
                    type="checkbox"
                    checked={remember}
                    onChange={(event) => setRemember(event.target.checked)}
                  />
                  <span />
                  Keep me signed in
                </label>

                {isLogin && (
                  <button
                    type="button"
                    className="auth-v3-forgot"
                    onClick={() =>
                      setError("Password recovery is not available yet.")
                    }
                  >
                    Forgot password?
                  </button>
                )}
              </div>

              {error && (
                <div className="auth-v3-error">
                  <strong>Authentication failed</strong>
                  <span>{error}</span>
                </div>
              )}

              <button
                type="submit"
                className="auth-v3-submit"
                disabled={loading}
              >
                <span>
                  {loading
                    ? isLogin
                      ? "Authenticating..."
                      : "Creating account..."
                    : isLogin
                      ? "Enter Singularity"
                      : "Create secure account"}
                </span>

                {!loading && <ArrowRight size={18} />}
                {loading && <span className="auth-v3-spinner" />}
              </button>
            </form>

            <p className="auth-v3-footnote">
              Your credentials are processed securely through the Singularity API.
            </p>
          </div>
        </section>
      </main>

      <footer className="auth-v3-footer">
        <span>Singularity</span>
        <span>Cyber Risk Intelligence Platform</span>
      </footer>
    </div>
  );
}