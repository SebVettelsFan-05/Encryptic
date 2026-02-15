from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
import io
import json
import os
import sys
from pathlib import Path
from typing import Optional
from urllib import parse, request as urlrequest

app = FastAPI()

# basic local CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
UART_PORT = os.getenv("CRYPTO_UART_PORT", "COM7").strip()
UART_BAUD = os.getenv("CRYPTO_UART_BAUD", "115200").strip()

if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from Testing import testing1

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_ENABLED = os.getenv("TURNSTILE_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "").strip()


def make_enc_name(filename: str) -> str:
    return (filename or "file") + ".enc"


def strip_enc_ext(filename: str) -> str:
    if filename.lower().endswith(".enc"):
        return filename[:-4]
    return filename or "decrypted"


def run_uart_crypto(command: str, passkey: str, file_bytes: bytes, filename: str) -> tuple[bytes, str]:
    if command not in {"encrypt", "decrypt"}:
        raise ValueError("invalid command")

    try:
        passkey.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("passkey must be ASCII for FPGA UART flow") from exc

    out_name = make_enc_name(filename) if command == "encrypt" else strip_enc_ext(filename)
    try:
        baud = int(UART_BAUD)
    except ValueError as exc:
        raise ValueError("CRYPTO_UART_BAUD must be an integer") from exc

    output_bytes = testing1.run_crypto_bytes(
        command=command,
        port=UART_PORT,
        baud=baud,
        passphrase=passkey,
        input_bytes=file_bytes,
    )
    return output_bytes, out_name


def verify_turnstile(token: Optional[str], remote_ip: Optional[str]) -> tuple[bool, int, str]:
    if not TURNSTILE_ENABLED:
        return True, 200, "captcha disabled"

    if not TURNSTILE_SECRET_KEY:
        # keep local/dev usable if backend secret is not set
        return True, 200, "captcha skipped (secret not configured)"

    cleaned_token = (token or "").strip()
    if not cleaned_token:
        return False, 400, "captcha required"

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": cleaned_token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    data = parse.urlencode(payload).encode("utf-8")

    try:
        req = urlrequest.Request(TURNSTILE_VERIFY_URL, data=data, method="POST")
        with urlrequest.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return False, 503, "captcha verification unavailable"

    if not body.get("success", False):
        return False, 400, "captcha verification failed"

    return True, 200, "ok"


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/encrypt")
async def encrypt(
    request: Request,
    file: UploadFile = File(...),
    passkey: str = Form(...),
    captcha_token: Optional[str] = Form(None),
):
    ok, status, message = verify_turnstile(
        captcha_token,
        request.client.host if request.client else None,
    )
    if not ok:
        return JSONResponse({"error": message}, status_code=status)

    clean_passkey = passkey.strip()
    if not clean_passkey:
        return JSONResponse({"error": "passkey required"}, status_code=400)

    data = await file.read()
    if not data:
        return JSONResponse({"error": "empty file"}, status_code=400)

    try:
        output_bytes, out_name = run_uart_crypto(
            "encrypt",
            clean_passkey,
            data,
            file.filename or "file",
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)

    out = io.BytesIO(output_bytes)
    out.seek(0)
    return StreamingResponse(
        out,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{out_name}"'},
    )


@app.post("/decrypt")
async def decrypt(
    request: Request,
    file: UploadFile = File(...),
    passkey: str = Form(...),
    captcha_token: Optional[str] = Form(None),
):
    ok, status, message = verify_turnstile(
        captcha_token,
        request.client.host if request.client else None,
    )
    if not ok:
        return JSONResponse({"error": message}, status_code=status)
    clean_passkey = passkey.strip()
    if not clean_passkey:
        return JSONResponse({"error": "passkey required"}, status_code=400)

    data = await file.read()
    if not file.filename or not file.filename.lower().endswith(".enc"):
        return JSONResponse({"error": "expected a .enc file for decryption"}, status_code=400)

    try:
        output_bytes, out_name = run_uart_crypto(
            "decrypt",
            clean_passkey,
            data,
            file.filename or "file.enc",
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)

    out = io.BytesIO(output_bytes)
    out.seek(0)
    return StreamingResponse(
        out,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{out_name}"'},
    )
