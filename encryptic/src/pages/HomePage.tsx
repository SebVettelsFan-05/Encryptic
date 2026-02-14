import React, { useRef, useState } from "react";

export default function HomePage() {
  const [file, setFile] = useState<File | null>(null);
  const [key, setKey] = useState("");
  const [drag, setDrag] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const pick = () => inputRef.current?.click();

  return (
    <div
      style={{
        minHeight: "calc(100vh - 64px)",
        display: "grid",
        placeItems: "center",
        padding: 16,
      }}
    >
      <div style={{ width: "min(720px, 100%)", display: "grid", gap: 16 }}>
        <h1 style={{ margin: 0 }}>Encryptic</h1>

        <div
          onClick={pick}
          onDragEnter={(e) => {
            e.preventDefault();
            setDrag(true);
          }}
          onDragOver={(e) => {
            e.preventDefault();
            setDrag(true);
          }}
          onDragLeave={(e) => {
            e.preventDefault();
            setDrag(false);
          }}
          onDrop={(e) => {
            e.preventDefault();
            setDrag(false);
            const f = e.dataTransfer.files?.[0];
            if (f) setFile(f);
          }}
          style={{
            border: "2px dashed",
            borderColor: drag ? "#555" : "#ccc",
            borderRadius: 16,
            padding: 40,
            textAlign: "center",
            cursor: "pointer",
          }}
        >
          <div style={{ fontSize: 16 }}>
            {file ? `Selected: ${file.name}` : "Drop a file here (or click to choose)"}
          </div>

          <input
            ref={inputRef}
            type="file"
            style={{ display: "none" }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) setFile(f);
            }}
          />
        </div>

        <div style={{ display: "grid", gap: 8 }}>
          <label style={{ fontSize: 12, opacity: 0.8 }}>Encryption key</label>
          <input
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="Enter key..."
            style={{
              padding: "12px 14px",
              borderRadius: 12,
              border: "1px solid #ccc",
              fontSize: 14,
            }}
          />
        </div>

        <button
          disabled={!file || !key}
          onClick={() => alert("Hook to backend later")}
          style={{
            padding: "12px 14px",
            borderRadius: 12,
            border: "1px solid #ccc",
            opacity: !file || !key ? 0.5 : 1,
            cursor: !file || !key ? "not-allowed" : "pointer",
          }}
        >
          Encrypt
        </button>
      </div>
    </div>
  );
}
