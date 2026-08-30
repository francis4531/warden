"""
Encrypts secrets (connection tokens) at rest so they never sit in the database as
plaintext. The key comes from WARDEN_SECRET_KEY if set (kept out of the data dir, the
stronger option); otherwise a key is generated once and stored on the persistent disk
next to the data, so encryption works with zero configuration. Any string works as
WARDEN_SECRET_KEY, it is hashed into a valid key.
"""
import os
import base64
import hashlib

try:
    from cryptography.fernet import Fernet
    _OK = True
except Exception:
    _OK = False

import paths
DATA_ROOT = paths.DATA_ROOT
KEY_FILE = os.path.join(DATA_ROOT, ".warden_key")

def _key():
    env = os.environ.get("WARDEN_SECRET_KEY")
    if env:
        return base64.urlsafe_b64encode(hashlib.sha256(env.encode()).digest())
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read().strip()
    k = Fernet.generate_key()
    os.makedirs(DATA_ROOT, exist_ok=True)
    open(KEY_FILE, "wb").write(k)
    try:
        os.chmod(KEY_FILE, 0o600)
    except Exception:
        pass
    return k

_F = None
def _fernet():
    global _F
    if _F is None:
        _F = Fernet(_key())
    return _F

def encrypt(s):
    """Return an 'enc:'-prefixed ciphertext, or the original if encryption is unavailable."""
    if not s or not _OK:
        return s
    try:
        return "enc:" + _fernet().encrypt(s.encode()).decode()
    except Exception:
        return s

def decrypt(s):
    """Reverse encrypt(); passes through anything not marked 'enc:' (e.g. legacy plaintext)."""
    if not s or not _OK or not isinstance(s, str) or not s.startswith("enc:"):
        return s
    try:
        return _fernet().decrypt(s[4:].encode()).decode()
    except Exception:
        return s
