import { useMemo, useState } from "react";

function randomKeyHex(bytes: number) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export default function KeygenPage() {
  const [bytes, setBytes] = useState(32); // 32 bytes = 256-bit
  const [key, setKey] = useState(() => randomKeyHex(32));
  const bitLabel = useMemo(() => `${bytes * 8}-bit`, [bytes]);

  return (
    <div style={{ padding: 16, display: "grid", placeItems: "center" }}>
      <div style={{ width: "min(720px, 100%)", display: "grid", gap: 12 }}>
        <h2 style={{ margin: 0 }}>Generate a random key</h2>

        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <label style={{ fontSize: 12, opacity: 0.8 }}>Strength</label>
          <select
            value={bytes}
            onChange={(e) => setBytes(Number(e.target.value))}
            style={{ padding: "8px 10px", borderRadius: 10, border: "1px solid #ccc" }}
          >
            <option value={16}>128-bit</option>
            <option value={32}>256-bit</option>
            <option value={64}>512-bit</option>
          </select>

          <button
            onClick={() => setKey(randomKeyHex(bytes))}
            style={{ padding: "8px 12px", borderRadius: 10, border: "1px solid #ccc" }}
          >
            Generate ({bitLabel})
          </button>

          <button
            onClick={async () => {
              await navigator.clipboard.writeText(key);
              alert("Copied");
            }}
            style={{ padding: "8px 12px", borderRadius: 10, border: "1px solid #ccc" }}
          >
            Copy
          </button>
        </div>

        <textarea
          value={key}
          readOnly
          style={{
            width: "100%",
            minHeight: 120,
            padding: 12,
            borderRadius: 12,
            border: "1px solid #ccc",
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
            fontSize: 13,
          }}
        />
      </div>
    </div>
  );
}
