from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import io
import json
import os
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

MAGIC = b"ENCRYPTIC"   # 8 bytes
SALT_LEN = 16
NONCE_LEN = 12
KDF_ITERS = 200_000
HEADER_LEN = len(MAGIC) + SALT_LEN + NONCE_LEN  # 36

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_ENABLED = os.getenv("TURNSTILE_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "").strip()


def derive_key(passkey: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(passkey.encode("utf-8"))


def make_enc_name(filename: str) -> str:
    return (filename or "file") + ".enc"


def strip_enc_ext(filename: str) -> str:
    if filename.lower().endswith(".enc"):
        return filename[:-4]
    return filename or "decrypted"


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

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(clean_passkey, salt)
    aes = AESGCM(key)

    ct = aes.encrypt(nonce, data, None)
    payload = MAGIC + salt + nonce + ct

    out = io.BytesIO(payload)
    out.seek(0)

    out_name = make_enc_name(file.filename or "file")
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
    if not data or len(data) < HEADER_LEN + 1:
        return JSONResponse({"error": "file too small / invalid"}, status_code=400)

    if not data.startswith(MAGIC):
        return JSONResponse({"error": "not an Encryptic file"}, status_code=400)

    salt_off = len(MAGIC)
    nonce_off = salt_off + SALT_LEN
    ct_off = nonce_off + NONCE_LEN

    salt = data[salt_off:nonce_off]
    nonce = data[nonce_off:ct_off]
    ct = data[ct_off:]

    key = derive_key(clean_passkey, salt)
    aes = AESGCM(key)

    try:
        pt = aes.decrypt(nonce, ct, None)
    except Exception:
        return JSONResponse({"error": "bad passkey or corrupted file"}, status_code=400)

    out = io.BytesIO(pt)
    out.seek(0)

    out_name = strip_enc_ext(file.filename or "file")
    return StreamingResponse(
        out,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{out_name}"'},
    )
