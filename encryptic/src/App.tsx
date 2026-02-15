import React, { useCallback, useEffect, useRef, useState } from "react";
import "./App.css";

type Mode = "encrypt" | "decrypt";

const API_BASE = "/api";
const MAGIC = "ENCRYPTIC";

const TURNSTILE_SITE_KEY = (import.meta.env.VITE_TURNSTILE_SITE_KEY ?? "").trim();
const CAPTCHA_REQUIRED = TURNSTILE_SITE_KEY.length > 0;

const STRIPE_DONATION_URL = (import.meta.env.VITE_STRIPE_DONATION_URL ?? "").trim();
const BRAND_LOGO_URL = (import.meta.env.VITE_LOGO_URL ?? "").trim();
const SOURCE_CODE_URL = (import.meta.env.VITE_SOURCE_CODE_URL ?? "").trim();

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let index = 0;

  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }

  const decimals = index === 0 ? 0 : index === 1 ? 1 : 2;
  return `${size.toFixed(decimals)} ${units[index]}`;
}

async function isEncrypticFile(file: File): Promise<boolean> {
  const fileHead = new Uint8Array(await file.slice(0, MAGIC.length).arrayBuffer());
  if (fileHead.length < MAGIC.length) return false;

  const magicBytes = new TextEncoder().encode(MAGIC);
  for (let i = 0; i < magicBytes.length; i++) {
    if (fileHead[i] !== magicBytes[i]) return false;
  }

  return true;
}

function getEndpoint(mode: Mode): string {
  return mode === "encrypt" ? `${API_BASE}/encrypt` : `${API_BASE}/decrypt`;
}

function getDownloadName(mode: Mode, originalName: string): string {
  if (mode === "encrypt") return `${originalName}.enc`;
  return originalName.replace(/\.enc$/i, "") || "decrypted";
}

type DropzoneProps = {
  file: File | null;
  isDragActive: boolean;
  inputRef: React.RefObject<HTMLInputElement>;
  onPick: () => void;
  onFileSelected: (file: File) => void;
  onDragActiveChange: (isActive: boolean) => void;
};

function Dropzone({ file, isDragActive, inputRef, onPick, onFileSelected, onDragActiveChange }: DropzoneProps) {
  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      onDragActiveChange(false);
      const droppedFile = event.dataTransfer.files?.[0];
      if (droppedFile) onFileSelected(droppedFile);
    },
    [onDragActiveChange, onFileSelected]
  );

  return (
    <div
      className={`dropzone ${isDragActive ? "is-active" : ""}`}
      role="button"
      tabIndex={0}
      aria-label="File upload dropzone"
      onClick={onPick}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") onPick();
      }}
      onDragEnter={(event) => {
        event.preventDefault();
        onDragActiveChange(true);
      }}
      onDragOver={(event) => {
        event.preventDefault();
        onDragActiveChange(true);
      }}
      onDragLeave={(event) => {
        event.preventDefault();
        onDragActiveChange(false);
      }}
      onDrop={onDrop}
    >
      <div className="dropzone__inner">
        <div className="dropzone__title">
          {file ? (
            <>
              <span className="mono">{file.name}</span>
              <span className="muted"> | {formatBytes(file.size)}</span>
            </>
          ) : (
            "Drop your file here"
          )}
        </div>
        <div className="dropzone__subtitle">Input any file, or click to browse</div>

        <input
          ref={inputRef}
          type="file"
          className="sr-only"
          onChange={(event) => {
            const selectedFile = event.target.files?.[0];
            if (selectedFile) onFileSelected(selectedFile);
          }}
        />
      </div>
    </div>
  );
}

export default function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [mode, setMode] = useState<Mode>("encrypt");
  const [passkey, setPasskey] = useState("");
  const [showPasskey, setShowPasskey] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [captchaToken, setCaptchaToken] = useState("");

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const turnstileMountRef = useRef<HTMLDivElement | null>(null);
  const turnstileWidgetIdRef = useRef<string | null>(null);

  const pickFile = useCallback(() => fileInputRef.current?.click(), []);

  const resetCaptcha = useCallback(() => {
    setCaptchaToken("");
    if (window.turnstile && turnstileWidgetIdRef.current) {
      window.turnstile.reset(turnstileWidgetIdRef.current);
    }
  }, []);

  const clearForm = useCallback(() => {
    setSelectedFile(null);
    setPasskey("");
    setDragActive(false);
    setMode("encrypt");
    resetCaptcha();
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, [resetCaptcha]);

  const handleFileSelection = useCallback(async (file: File) => {
    setSelectedFile(file);
    const encrypted = await isEncrypticFile(file);
    setMode(encrypted ? "decrypt" : "encrypt");
  }, []);

  useEffect(() => {
    if (!CAPTCHA_REQUIRED) return;

    const renderTurnstile = () => {
      if (!window.turnstile || !turnstileMountRef.current || turnstileWidgetIdRef.current) return;

      turnstileWidgetIdRef.current = window.turnstile.render(turnstileMountRef.current, {
        sitekey: TURNSTILE_SITE_KEY,
        callback: (token: string) => setCaptchaToken(token),
        "expired-callback": () => setCaptchaToken(""),
        "error-callback": () => setCaptchaToken(""),
      });
    };

    if (window.turnstile) {
      renderTurnstile();
      return;
    }

    const scriptId = "cf-turnstile-script";
    const existingScript = document.getElementById(scriptId) as HTMLScriptElement | null;

    if (existingScript) {
      existingScript.addEventListener("load", renderTurnstile);
      return () => {
        existingScript.removeEventListener("load", renderTurnstile);
      };
    }

    const script = document.createElement("script");
    script.id = scriptId;
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.addEventListener("load", renderTurnstile);
    document.head.appendChild(script);

    return () => {
      script.removeEventListener("load", renderTurnstile);
    };
  }, []);

  const canSubmit = Boolean(selectedFile) && passkey.trim().length > 0 && (!CAPTCHA_REQUIRED || captchaToken.length > 0) && !busy;

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selectedFile || !passkey.trim()) return;
    if (CAPTCHA_REQUIRED && !captchaToken) return;

    try {
      setBusy(true);

      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("passkey", passkey.trim());
      if (CAPTCHA_REQUIRED) formData.append("captcha_token", captchaToken);

      const endpoint = getEndpoint(mode);
      const response = await fetch(endpoint, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const message = await response.text();
        alert(`${mode} failed: ${message}`);
        resetCaptcha();
        return;
      }

      const responseBlob = await response.blob();
      const downloadUrl = URL.createObjectURL(responseBlob);
      const downloadName = getDownloadName(mode, selectedFile.name);

      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = downloadName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(downloadUrl);

      setSelectedFile(null);
      setDragActive(false);
      resetCaptcha();
      if (fileInputRef.current) fileInputRef.current.value = "";
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <main className="shell">
        <header className="header">
          <div className="brand">
            <div className="brand__mark" aria-hidden="true">
              {BRAND_LOGO_URL ? <img className="brand__logo" src={BRAND_LOGO_URL} alt="" /> : "E"}
            </div>
            <div>
              <h1 className="brand__name">Encryptic</h1>
              <p className="brand__tagline">Secure file encryption and decryption for any file type.</p>
              <p className="brand__mission">
                Our mission is to protect today&apos;s records so archives remain accessible, trustworthy, and useful for future
                generations.
              </p>
            </div>
          </div>
        </header>

        <form className="card" onSubmit={onSubmit}>
          <Dropzone
            file={selectedFile}
            isDragActive={dragActive}
            inputRef={fileInputRef}
            onPick={pickFile}
            onFileSelected={handleFileSelection}
            onDragActiveChange={setDragActive}
          />

          <div className="field">
            <div className="rowHeader">
              <label className="label" htmlFor="passkey">
                Passkey
              </label>
            </div>

            <div className="inputRow">
              <input
                id="passkey"
                className="input"
                value={passkey}
                placeholder="Enter your passkey"
                type={showPasskey ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setPasskey(event.target.value)}
              />
              <button
                type="button"
                className="ghost"
                aria-label={showPasskey ? "Hide passkey" : "Show passkey"}
                onClick={() => setShowPasskey((value) => !value)}
              >
                {showPasskey ? "Hide" : "Show"}
              </button>
            </div>
            <div className="hint">
              Protect your passkey. Use a long, unique passkey you do not reuse, and keep it safe since you need it to decrypt later.
            </div>
          </div>

          <div className={`captchaBlock ${CAPTCHA_REQUIRED ? "has-widget" : "no-widget"} ${captchaToken ? "is-verified" : ""}`}>
            {CAPTCHA_REQUIRED ? (
              <div
                ref={turnstileMountRef}
                className={`captchaMount ${captchaToken ? "is-verified" : ""}`}
                aria-label="Captcha verification"
              />
            ) : (
              <div className="hint">Set `VITE_TURNSTILE_SITE_KEY` to enable Cloudflare Turnstile.</div>
            )}
          </div>

          <div className="actions">
            <button type="button" className="secondary" onClick={clearForm} disabled={busy && !selectedFile}>
              Clear
            </button>

            <button type="submit" className="primary" disabled={!canSubmit}>
              {busy ? (mode === "encrypt" ? "Encrypting..." : "Decrypting...") : mode === "encrypt" ? "Encrypt" : "Decrypt"}
            </button>
          </div>
        </form>

        <section className="opensourceCard" aria-label="Open source">
          <div className="opensourceCard__copy">
            <p className="opensourceCard__title">Open-source transparency</p>
            <p className="hint">Running with React + TypeScript frontend and FastAPI + AES-GCM encryption backend.</p>
          </div>
          {SOURCE_CODE_URL ? (
            <a className="secondary opensourceCard__button" href={SOURCE_CODE_URL} target="_blank" rel="noreferrer">
              View Code
            </a>
          ) : (
            <button type="button" className="secondary opensourceCard__button" disabled aria-disabled="true">
              View Code
            </button>
          )}
        </section>

        <section className="donationCard" aria-label="Donations">
          <div className="donationCard__copy">
            <p className="donationCard__title">Support Encryptic</p>
            <p className="hint">If Encryptic helps you, a small donation supports ongoing upkeep.</p>
          </div>
          {STRIPE_DONATION_URL ? (
            <a className="secondary donationCard__button" href={STRIPE_DONATION_URL} target="_blank" rel="noreferrer">
              Donate
            </a>
          ) : (
            <button type="button" className="secondary donationCard__button" disabled aria-disabled="true">
              Donate
            </button>
          )}
        </section>

        <footer className="footer">
          <span className="muted">
            {mode === "encrypt"
              ? "Input any file to encrypt. Encryptic does not record your input or output data in any form."
              : "Upload an Encryptic `.enc` file to decrypt. Encryptic does not record your input or output data in any form."}
          </span>
        </footer>
      </main>
    </div>
  );
}
