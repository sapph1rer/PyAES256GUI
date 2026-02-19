import argparse
import base64
import contextlib
import getpass
import io
import os
import shlex
import struct
import sys
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC_V1 = b"AES256CLI1"
MAGIC_V2 = b"AESRSA4096V2"
MAGIC_V3 = b"AES256SC3"
MAGIC_V4 = b"AESRSAPEM4"

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 32 bytes = AES-256

PBKDF2_ITERATIONS_V1 = 390_000
PBKDF2_ITERATIONS_V2 = 600_000
RSA4096_ENCRYPTED_KEY_SIZE = 512

SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1


BANNER = r"""
                                        _    _____ ____ ____  ____   __   
                                       / \  | ____/ ___|___ \| ___| / /_  
                                      / _ \ |  _| \___ \ __) |___ \| '_ \ 
                                     / ___ \| |___ ___) / __/ ___) | (_) |
                                    /_/   \_\_____|____/_____|____/ \___/ 
                                       
"""


EXAMPLE_TEXT = r"""Examples:
  help
  example

  # Settings
  settings show
  settings load
  settings key_timestamp true
  settings key_timestamp false

  # Password text mode
  encrypt-text -t "hello world" -p "your-strong-password"
  encrypt-text -t "hello world" -p password.txt
  decrypt-text -t "<TOKEN>" -p "your-strong-password"
  decrypt-text -t "<TOKEN>" -p password.txt

  # Password file mode
  encrypt-file -i notes.txt -p password.txt
  decrypt-file -i notes.aes -o notes.dec.txt -p password.txt
  encrypt-file -i notes.txt -p password.txt --raw -o notes.aesbin
  decrypt-file -i notes.aesbin --raw -p password.txt -o notes.dec.txt

  # RSA keypair + text/file mode
  generate-keypair --private-out private_key.pem --public-out public_key.pem --encrypt-private
  encrypt-text-pem -t "hello world" --public-key public_key.pem
  decrypt-text-pem -t "<TOKEN>" --private-key private_key.pem --private-pass password.txt
  encrypt-file-pem -i notes.txt --public-key public_key.pem
  decrypt-file-pem -i notes_pem.aes --private-key private_key.pem -o notes.dec.txt
  encrypt-file-pem -i notes.txt --public-key public_key.pem --raw -o notes_pem.aesbin
  decrypt-file-pem -i notes_pem.aesbin --private-key private_key.pem --raw -o notes.dec.txt

  # Ed25519 signing mode
  generate-signing-keypair --private-out sign_private.pem --public-out sign_public.pem --encrypt-private
  sign-token -t "<TOKEN>" --signing-private sign_private.pem --signing-pass password.txt
  verify-token -t "<SIGNED_TOKEN>" --signer-public sign_public.pem --print-payload
  sign-file -i notes_pem.aes --signing-private sign_private.pem --signing-pass password.txt -o notes_pem.aes.sig
  verify-file -i notes_pem.aes.sig --signer-public sign_public.pem -o extracted_payload.token
  sign-file -i notes_pem.aesbin --raw-input --signing-private sign_private.pem --signing-pass password.txt --raw -o notes_pem.aesbin.sigbin
  verify-file -i notes_pem.aesbin.sigbin --raw-input --signer-public sign_public.pem -o extracted_payload.bin --payload-raw
"""

# ----------------------------
# Settings (JSON)
# ----------------------------
# Settings are stored at: ~/.aes256-cli/settings.json
# You can view/update them via:
#   settings show
#   settings load
#   settings key_timestamp true|false
#
# key_timestamp:
#   - true  (default): append _DDMMYYYY_HHMMSS to generated key filenames
#   - false: do not append timestamps (use the provided paths as-is)

DEFAULT_SETTINGS = {
    "key_timestamp": True,
}

def _settings_dir() -> Path:
    return (Path.home() / ".aes256-cli").resolve()

def _settings_path() -> Path:
    return _settings_dir() / "settings.json"

def load_settings() -> dict:
    path = _settings_path()
    try:
        if path.exists():
            import json
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                # merge defaults
                merged = DEFAULT_SETTINGS.copy()
                merged.update({k: data.get(k, merged.get(k)) for k in merged.keys()})
                return merged
    except Exception:
        # If settings are corrupted, fall back to defaults.
        pass
    return DEFAULT_SETTINGS.copy()

def save_settings(settings: dict) -> None:
    import json
    d = _settings_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = _settings_path()
    path.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")

def get_setting_bool(key: str, default: bool = False) -> bool:
    val = SETTINGS.get(key, default)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("1", "true", "yes", "y", "on")
    if isinstance(val, (int, float)):
        return bool(val)
    return default

# Loaded on import
SETTINGS = load_settings()

def parse_bool(value: str) -> bool:
    v = value.strip().lower()
    if v in ("true", "1", "yes", "y", "on"):
        return True
    if v in ("false", "0", "no", "n", "off"):
        return False
    raise ValueError("Value must be true/false.")

def settings_flow(args):
    global SETTINGS
    key = args.key
    value = args.value

    if key is None or key.lower() in ("show", "list"):
        # show all
        import json
        print(json.dumps(SETTINGS, ensure_ascii=False, indent=2))
        return

    if key is not None and key.strip().lower() in ("load", "reload"):
        # reload settings from disk (useful in interactive mode)
        SETTINGS = load_settings()
        save_settings(SETTINGS)
        print("[OK] Settings reloaded.")
        return

    key = key.strip()
    if key not in DEFAULT_SETTINGS:
        raise ValueError(f"Unknown setting: {key}. Supported: {', '.join(DEFAULT_SETTINGS.keys())}")

    if value is None:
        print(f"{key} = {SETTINGS.get(key)}")
        return

    # set
    if isinstance(DEFAULT_SETTINGS[key], bool):
        SETTINGS[key] = parse_bool(value)
    else:
        SETTINGS[key] = value

    save_settings(SETTINGS)
    print(f"[OK] Updated setting: {key} = {SETTINGS[key]}")



def print_banner():
    print(BANNER)


def help_flow(args):
    args.parser.print_help()
    print("\nRun 'example' to see full command examples.")


def example_flow(args):
    print(EXAMPLE_TEXT)


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_dashboard(last_result: str):
    print(BANNER)
    print(r"""
Commands:
| help              | example                   | settings
| generate-keypair  | generate-signing-keypair  | encrypt-text-pem
| encrypt-text      | decrypt-text              | decrypt-text-pem
| encrypt-file      | decrypt-file              | encrypt-file-pem   | decrypt-file-pem
| sign-token        | verify-token              | sign-file          | verify-file
          """)
    if last_result:
        print(last_result.strip())


def derive_key_pbkdf2(password: str, salt: bytes, algorithm: hashes.HashAlgorithm, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=algorithm,
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_key_v1(password: str, salt: bytes) -> bytes:
    return derive_key_pbkdf2(password, salt, hashes.SHA256(), PBKDF2_ITERATIONS_V1)


def derive_key_v2(password: str, salt: bytes) -> bytes:
    return derive_key_pbkdf2(password, salt, hashes.SHA512(), PBKDF2_ITERATIONS_V2)


def derive_key_v3(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def pack_payload_v1(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return MAGIC_V1 + salt + nonce + ciphertext


def unpack_payload_v1(payload: bytes):
    if len(payload) < len(MAGIC_V1) + SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Encrypted payload is too short or malformed.")
    if not payload.startswith(MAGIC_V1):
        raise ValueError("Invalid payload header. Not generated by this CLI.")

    offset = len(MAGIC_V1)
    salt = payload[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = payload[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = payload[offset:]
    return salt, nonce, ciphertext


def unpack_payload_v2(payload: bytes):
    header_size = len(MAGIC_V2) + SALT_SIZE + NONCE_SIZE + NONCE_SIZE + 4 + 2
    if len(payload) < header_size + 16:
        raise ValueError("Encrypted payload is too short or malformed.")
    if not payload.startswith(MAGIC_V2):
        raise ValueError("Invalid payload header. Not generated by this CLI.")

    offset = len(MAGIC_V2)
    salt = payload[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    key_nonce = payload[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    data_nonce = payload[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    encrypted_private_key_len = struct.unpack(">I", payload[offset : offset + 4])[0]
    offset += 4
    encrypted_session_key_len = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2

    if encrypted_private_key_len <= 16:
        raise ValueError("Malformed payload: invalid private key section length.")
    if encrypted_session_key_len != RSA4096_ENCRYPTED_KEY_SIZE:
        raise ValueError("Malformed payload: invalid RSA section length.")
    if len(payload) < offset + encrypted_private_key_len + encrypted_session_key_len + 16:
        raise ValueError("Malformed payload: payload sections do not match declared lengths.")

    encrypted_private_key = payload[offset : offset + encrypted_private_key_len]
    offset += encrypted_private_key_len
    encrypted_session_key = payload[offset : offset + encrypted_session_key_len]
    offset += encrypted_session_key_len
    ciphertext = payload[offset:]

    if len(ciphertext) < 16:
        raise ValueError("Malformed payload: missing ciphertext/tag.")

    return salt, key_nonce, data_nonce, encrypted_private_key, encrypted_session_key, ciphertext


def pack_payload_v3(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return MAGIC_V3 + salt + nonce + ciphertext


def unpack_payload_v3(payload: bytes):
    if len(payload) < len(MAGIC_V3) + SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Encrypted payload is too short or malformed.")
    if not payload.startswith(MAGIC_V3):
        raise ValueError("Invalid payload header. Not generated by this CLI.")

    offset = len(MAGIC_V3)
    salt = payload[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = payload[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = payload[offset:]
    return salt, nonce, ciphertext


def pack_payload_v4(nonce: bytes, encrypted_session_key: bytes, ciphertext: bytes) -> bytes:
    return MAGIC_V4 + nonce + struct.pack(">H", len(encrypted_session_key)) + encrypted_session_key + ciphertext


def unpack_payload_v4(payload: bytes):
    header_size = len(MAGIC_V4) + NONCE_SIZE + 2
    if len(payload) < header_size + 16:
        raise ValueError("Encrypted payload is too short or malformed.")
    if not payload.startswith(MAGIC_V4):
        raise ValueError("Invalid payload header. Not generated by this CLI.")

    offset = len(MAGIC_V4)
    nonce = payload[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    encrypted_session_key_len = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2
    if encrypted_session_key_len <= 0:
        raise ValueError("Malformed payload: invalid RSA section length.")
    if len(payload) < offset + encrypted_session_key_len + 16:
        raise ValueError("Malformed payload: payload sections do not match declared lengths.")

    encrypted_session_key = payload[offset : offset + encrypted_session_key_len]
    offset += encrypted_session_key_len
    ciphertext = payload[offset:]
    return nonce, encrypted_session_key, ciphertext


def encode_payload(payload: bytes) -> str:
    # Output stays ASCII (URL-safe Base64 without padding)
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_payload(token: str) -> bytes:
    token = token.strip()
    if not token:
        raise ValueError("Empty encrypted token.")

    missing_padding = len(token) % 4
    if missing_padding:
        token += "=" * (4 - missing_padding)

    try:
        return base64.urlsafe_b64decode(token.encode("ascii"))
    except Exception as exc:
        raise ValueError("Invalid base64 token.") from exc


def encrypt_bytes_v1(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key_v1(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC_V1)
    return pack_payload_v1(salt, nonce, ciphertext)


def decrypt_bytes_v1(payload: bytes, password: str) -> bytes:
    salt, nonce, ciphertext = unpack_payload_v1(payload)
    key = derive_key_v1(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, MAGIC_V1)
    except InvalidTag as exc:
        raise ValueError("Decryption failed: wrong password or corrupted data.") from exc


def decrypt_bytes_v2(payload: bytes, password: str) -> bytes:
    salt, key_nonce, data_nonce, encrypted_private_key, encrypted_session_key, ciphertext = unpack_payload_v2(payload)
    password_key = derive_key_v2(password, salt)

    try:
        private_key_pem = AESGCM(password_key).decrypt(key_nonce, encrypted_private_key, None)
    except InvalidTag as exc:
        raise ValueError("Decryption failed: wrong password or corrupted data.") from exc

    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
        )
        return AESGCM(session_key).decrypt(data_nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("Decryption failed: wrong password or corrupted data.") from exc


def encrypt_bytes_v3(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key_v3(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC_V3)
    return pack_payload_v3(salt, nonce, ciphertext)


def decrypt_bytes_v3(payload: bytes, password: str) -> bytes:
    salt, nonce, ciphertext = unpack_payload_v3(payload)
    key = derive_key_v3(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, MAGIC_V3)
    except InvalidTag as exc:
        raise ValueError("Decryption failed: wrong password or corrupted data.") from exc


def encrypt_bytes_v4(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    session_key = os.urandom(KEY_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(session_key).encrypt(nonce, data, MAGIC_V4)
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return pack_payload_v4(nonce, encrypted_session_key, ciphertext)


def decrypt_bytes_v4(payload: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    nonce, encrypted_session_key, ciphertext = unpack_payload_v4(payload)
    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return AESGCM(session_key).decrypt(nonce, ciphertext, MAGIC_V4)
    except Exception as exc:
        raise ValueError("Decryption failed: wrong private key or corrupted data.") from exc


def encrypt_bytes(data: bytes, password: str) -> bytes:
    return encrypt_bytes_v3(data, password)


def decrypt_bytes(payload: bytes, password: str) -> bytes:
    if payload.startswith(MAGIC_V3):
        return decrypt_bytes_v3(payload, password)
    if payload.startswith(MAGIC_V2):
        return decrypt_bytes_v2(payload, password)
    if payload.startswith(MAGIC_V1):
        return decrypt_bytes_v1(payload, password)
    raise ValueError("Invalid payload header. Not generated by this CLI.")


def read_password_from_file(password_path: Path) -> str:
    if not password_path.exists():
        raise FileNotFoundError(f"Password file not found: {password_path}")
    if not password_path.is_file():
        raise ValueError(f"Password path is not a file: {password_path}")

    content = password_path.read_text(encoding="utf-8")
    if "\x00" in content:
        raise ValueError(f"Password file contains invalid NULL byte: {password_path}")

    password = content.rstrip("\r\n")
    if "\n" in password or "\r" in password:
        raise ValueError(f"Password file must contain a single-line password: {password_path}")
    if not password:
        raise ValueError(f"Password file is empty: {password_path}")
    return password


def resolve_password_arg(password_arg: str) -> str:
    password_path = Path(password_arg).expanduser()
    if password_path.suffix.lower() == ".txt":
        return read_password_from_file(password_path.resolve())
    return password_arg


def resolve_key_path(path_arg: str) -> Path:
    return Path(path_arg).expanduser().resolve()


def write_file(path: Path | str, data: bytes, force: bool = False) -> None:
    target = Path(path).expanduser()
    if target.exists() and target.is_dir():
        raise ValueError(f"Output path is a directory: {target}")
    if target.exists() and not force:
        raise FileExistsError(f"Output file already exists: {target}. Use --force to overwrite.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def force_suffix(path: Path, suffix: str) -> Path:
    if path.suffix.lower() == suffix.lower():
        return path
    return path.with_suffix(suffix) if path.suffix else Path(str(path) + suffix)


def append_suffix_if_missing(path: Path, suffix: str) -> Path:
    return path if path.suffix else Path(str(path) + suffix)


def make_key_path(path_arg: str | None, default_prefix: str, timestamp: str, use_timestamp: bool) -> Path:
    """
    Build a key output path.
    - If use_timestamp=True: append _DDMMYYYY_HHMMSS before suffix.
    - If use_timestamp=False: use the provided path as-is (or default <prefix>.pem).
    """
    if path_arg:
        raw_path = Path(path_arg).expanduser()
        parent = raw_path.parent
        stem = raw_path.stem if raw_path.suffix else raw_path.name
        suffix = ".pem"
    else:
        parent = Path(".")
        stem = default_prefix
        suffix = ".pem"

    if use_timestamp:
        filename = f"{stem}_{timestamp}{suffix}"
    else:
        filename = f"{stem}{suffix}"

    return (parent / filename).resolve()


# Backwards-compat helper (kept for older code paths)
def make_forced_timestamped_key_path(path_arg: str | None, default_prefix: str, timestamp: str) -> Path:
    return make_key_path(path_arg, default_prefix, timestamp, use_timestamp=True)


def parse_private_pass_arg(private_pass_arg: str | None) -> bytes | None:
    if private_pass_arg is None:
        return None

    password = resolve_password_arg(private_pass_arg)
    if not password:
        raise ValueError("Private key password cannot be empty.")
    return password.encode("utf-8")


def load_public_key_pem(path_arg: str) -> rsa.RSAPublicKey:
    path = resolve_key_path(path_arg)
    if not path.exists():
        raise FileNotFoundError(f"Public key file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Public key path is not a file: {path}")

    key_data = path.read_bytes()
    try:
        public_key = serialization.load_pem_public_key(key_data)
    except Exception as exc:
        raise ValueError(f"Failed to load PEM public key: {path}") from exc

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Public key must be an RSA PEM key.")
    return public_key


def load_private_key_pem(
    path_arg: str,
    private_pass_arg: str | None,
    prompt_if_needed: bool = True,
) -> rsa.RSAPrivateKey:
    path = resolve_key_path(path_arg)
    if not path.exists():
        raise FileNotFoundError(f"Private key file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Private key path is not a file: {path}")

    key_data = path.read_bytes()
    password_bytes = parse_private_pass_arg(private_pass_arg)

    try:
        private_key = serialization.load_pem_private_key(key_data, password=password_bytes)
    except Exception as exc:
        if prompt_if_needed and password_bytes is None and b"ENCRYPTED" in key_data:
            password = getpass.getpass("Private key password: ")
            if not password:
                raise ValueError("Private key password cannot be empty.")
            try:
                private_key = serialization.load_pem_private_key(key_data, password=password.encode("utf-8"))
            except Exception as inner_exc:
                raise ValueError("Failed to load private key: wrong password or malformed PEM.") from inner_exc
        else:
            raise ValueError("Failed to load private key: wrong password or malformed PEM.") from exc

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Private key must be an RSA PEM key.")
    return private_key


def build_private_encryption(private_pass_arg: str | None, encrypt_private: bool):
    if private_pass_arg:
        private_password = resolve_password_arg(private_pass_arg)
    elif encrypt_private:
        private_password = get_password(None, confirm=True)
    else:
        private_password = None

    if private_password:
        return serialization.BestAvailableEncryption(private_password.encode("utf-8"))
    return serialization.NoEncryption()


def get_password(password_arg: str | None, confirm: bool = False, prompt: str = "Password: ") -> str:
    if password_arg:
        password = resolve_password_arg(password_arg)
        if not password:
            raise ValueError("Password cannot be empty.")
        return password

    password = getpass.getpass(prompt)
    if not password:
        raise ValueError("Password cannot be empty.")

    if confirm:
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            raise ValueError("Passwords do not match.")
    return password


def generate_keypair_flow(args):
    use_ts = get_setting_bool("key_timestamp", True)
    timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
    private_path = make_key_path(args.private_out, "private_key", timestamp, use_ts)
    public_path = make_key_path(args.public_out, "public_key", timestamp, use_ts)
    if private_path == public_path:
        raise ValueError("Private and public key output paths must be different.")

    if private_path.exists() and not args.force:
        raise FileExistsError(f"Private key output already exists: {private_path}. Use --force to overwrite.")
    if public_path.exists() and not args.force:
        raise FileExistsError(f"Public key output already exists: {public_path}. Use --force to overwrite.")
    if private_path.exists() and private_path.is_dir():
        raise ValueError(f"Private key output path is a directory: {private_path}")
    if public_path.exists() and public_path.is_dir():
        raise ValueError(f"Public key output path is a directory: {public_path}")

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=args.bits)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=build_private_encryption(args.private_pass, args.encrypt_private),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    print(f"\n[OK] Private key saved: {private_path}")
    print(f"[OK] Public key saved:  {public_path}")


def encrypt_text_flow(args):
    text = args.text
    if text is None:
        text = input("Text to encrypt: ")
    if not text:
        raise ValueError("Text cannot be empty.")

    password = get_password(args.password, confirm=True)
    encrypted = encrypt_bytes(text.encode("utf-8"), password)
    token = encode_payload(encrypted)

    print("\n[OK] Encrypted token:")
    print(token)


def decrypt_text_flow(args):
    token = args.token
    if token is None:
        token = input("Token to decrypt: ")

    password = get_password(args.password, confirm=False)
    payload = decode_payload(token)
    plaintext = decrypt_bytes(payload, password)

    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted bytes are not valid UTF-8 text.") from exc

    print("\n[OK] Decrypted text:")
    print(text)


def encrypt_text_pem_flow(args):
    text = args.text
    if text is None:
        text = input("Text to encrypt: ")
    if not text:
        raise ValueError("Text cannot be empty.")

    public_key = load_public_key_pem(args.public_key)
    encrypted = encrypt_bytes_v4(text.encode("utf-8"), public_key)
    token = encode_payload(encrypted)

    print("\n[OK] Encrypted token:")
    print(token)


def decrypt_text_pem_flow(args):
    token = args.token
    if token is None:
        token = input("Token to decrypt: ")

    private_key = load_private_key_pem(args.private_key, args.private_pass)
    payload = decode_payload(token)
    plaintext = decrypt_bytes_v4(payload, private_key)

    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted bytes are not valid UTF-8 text.") from exc

    print("\n[OK] Decrypted text:")
    print(text)


def encrypt_file_flow(args):
    input_path = Path(args.input).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if input_path.suffix.lower() != ".txt":
        raise ValueError("Only .txt files are allowed for file encryption.")

    # default outputs:
    # - token mode: <stem>.aes (text file storing base64 token)
    # - raw mode:   <stem>.aesbin (binary payload)
    if args.output:
        output_path = force_suffix(Path(args.output).resolve(), ".aesbin" if args.raw else ".aes")
    else:
        output_path = input_path.with_name(f"{input_path.stem}.aesbin" if args.raw else f"{input_path.stem}.aes")

    password = get_password(args.password, confirm=True)

    content = input_path.read_bytes()
    encrypted = encrypt_bytes(content, password)

    if args.raw:
        output_path.write_bytes(encrypted)
    else:
        output_path.write_text(encode_payload(encrypted), encoding="utf-8")

    print(f"\n[OK] Encrypted file saved: {output_path}")


def decrypt_file_flow(args):
    input_path = Path(args.input).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Force output to be a .txt file (because encrypt-file only allows .txt inputs).
    if args.output:
        output_path = Path(args.output).resolve()
        if output_path.suffix.lower() != ".txt":
            output_path = output_path.with_suffix(".txt") if output_path.suffix else Path(str(output_path) + ".txt")
    else:
        output_path = Path(str(input_path) + ".decrypted.txt")

    password = get_password(args.password, confirm=False)

    # Raw input is supported via --raw or by using the .aesbin extension.
    raw_in = bool(getattr(args, "raw", False)) or input_path.suffix.lower() == ".aesbin"
    if raw_in:
        payload = input_path.read_bytes()
    else:
        token = input_path.read_text(encoding="utf-8").strip()
        payload = decode_payload(token)

    plaintext = decrypt_bytes(payload, password)

    try:
        text_out = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted content is not valid UTF-8 text.") from exc

    output_path.write_text(text_out, encoding="utf-8")

    print(f"\n[OK] Decrypted file saved: {output_path}")


def encrypt_file_pem_flow(args):
    input_path = Path(args.input).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not input_path.is_file():
        raise ValueError(f"Input path is not a file: {input_path}")

    public_key = load_public_key_pem(args.public_key)

    # Output rules:
    # - default: *_pem.aes (token/base64 text)
    # - with --raw: *_pem.aesbin (raw binary payload)
    if args.raw:
        default_out = input_path.with_name(f"{input_path.stem}_pem.aesbin")
        output_path = force_suffix(Path(args.output).resolve(), ".aesbin") if args.output else default_out
    else:
        default_out = input_path.with_name(f"{input_path.stem}_pem.aes")
        output_path = force_suffix(Path(args.output).resolve(), ".aes") if args.output else default_out

    content = input_path.read_bytes()
    encrypted = encrypt_bytes_v4(content, public_key)

    if args.raw:
        output_path.write_bytes(encrypted)
    else:
        output_path.write_text(encode_payload(encrypted), encoding="utf-8")

    print(f"[OK] Encrypted file saved: {output_path}")


def decrypt_file_pem_flow(args):
    input_path = Path(args.input).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not input_path.is_file():
        raise ValueError(f"Input path is not a file: {input_path}")

    output_path = append_suffix_if_missing(Path(args.output).resolve(), ".decrypted") if args.output else Path(str(input_path) + ".decrypted")
    private_key = load_private_key_pem(args.private_key, args.private_pass)

    is_raw = bool(args.raw) or input_path.suffix.lower() == ".aesbin"

    if is_raw:
        payload = input_path.read_bytes()
    else:
        token = input_path.read_text(encoding="utf-8").strip()
        payload = decode_payload(token)

    plaintext = decrypt_bytes_v4(payload, private_key)
    output_path.write_bytes(plaintext)

    print(f"[OK] Decrypted file saved: {output_path}")

# ----------------------------
# Signing (Ed25519) helpers
# ----------------------------

MAGIC_SIG_V1 = b"SIG1"  # 4 bytes
SIG_PUB_LEN = 32
SIG_LEN = 64


def load_ed25519_private_key(path: str, password: bytes | None, prompt_if_needed: bool = True):
    key_path = resolve_key_path(path)
    if not key_path.exists():
        raise FileNotFoundError(f"Signing private key file not found: {key_path}")
    if not key_path.is_file():
        raise ValueError(f"Signing private key path is not a file: {key_path}")

    key_bytes = key_path.read_bytes()
    try:
        private_key = serialization.load_pem_private_key(key_bytes, password=password)
    except Exception as exc:
        if prompt_if_needed and password is None and b"ENCRYPTED" in key_bytes:
            prompted = getpass.getpass("Signing private key password: ")
            if not prompted:
                raise ValueError("Signing private key password cannot be empty.")
            try:
                private_key = serialization.load_pem_private_key(key_bytes, password=prompted.encode("utf-8"))
            except Exception as inner_exc:
                raise ValueError("Failed to load signing private key: wrong password or malformed PEM.") from inner_exc
        else:
            raise ValueError("Failed to load signing private key: wrong password or malformed PEM.") from exc

    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Signing private key must be an Ed25519 PEM key.")
    return private_key


def load_ed25519_public_key(path: str):
    key_path = resolve_key_path(path)
    if not key_path.exists():
        raise FileNotFoundError(f"Signer public key file not found: {key_path}")
    if not key_path.is_file():
        raise ValueError(f"Signer public key path is not a file: {key_path}")

    key_bytes = key_path.read_bytes()
    try:
        public_key = serialization.load_pem_public_key(key_bytes)
    except Exception as exc:
        raise ValueError(f"Failed to load signer public key PEM: {key_path}") from exc

    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("Signer public key must be an Ed25519 PEM key.")
    return public_key


def generate_signing_keypair_flow(args):
    use_ts = get_setting_bool("key_timestamp", True)
    ts = datetime.now().strftime("%d%m%Y_%H%M%S")
    priv_path = make_key_path(args.private_out, "sign_private", ts, use_ts)
    pub_path = make_key_path(args.public_out, "sign_public", ts, use_ts)
    if priv_path == pub_path:
        raise ValueError("Private and public key output paths must be different.")

    password_bytes = None
    if args.private_pass:
        password_text = resolve_password_arg(args.private_pass)
        if not password_text:
            raise ValueError("Private key password cannot be empty.")
        password_bytes = password_text.encode("utf-8")
    elif args.encrypt_private:
        pw = get_password(None, confirm=True, prompt="Enter passphrase for signing private key: ")
        password_bytes = pw.encode("utf-8")

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    enc_algo = serialization.NoEncryption()
    if password_bytes is not None:
        enc_algo = serialization.BestAvailableEncryption(password_bytes)

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo,
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    write_file(priv_path, priv_pem, force=args.force)
    write_file(pub_path, pub_pem, force=args.force)

    print(f"[OK] Signing private key: {priv_path}")
    print(f"[OK] Signing public key : {pub_path}")


def pack_signed_payload(payload: bytes, signer_public_key_bytes: bytes, signature: bytes) -> bytes:
    if len(signer_public_key_bytes) != SIG_PUB_LEN:
        raise ValueError("Bad signer public key length for Ed25519 (expected 32 bytes)")
    if len(signature) != SIG_LEN:
        raise ValueError("Bad signature length for Ed25519 (expected 64 bytes)")
    return MAGIC_SIG_V1 + signer_public_key_bytes + signature + struct.pack(">I", len(payload)) + payload


def unpack_signed_payload(blob: bytes):
    if not blob.startswith(MAGIC_SIG_V1):
        raise ValueError("Not a signed payload (bad header)")
    if len(blob) < 4 + SIG_PUB_LEN + SIG_LEN + 4:
        raise ValueError("Signed payload is too short")

    off = 4
    pub_b = blob[off:off + SIG_PUB_LEN]
    off += SIG_PUB_LEN
    sig_b = blob[off:off + SIG_LEN]
    off += SIG_LEN
    (plen,) = struct.unpack(">I", blob[off:off + 4])
    off += 4

    if plen < 0 or off + plen > len(blob):
        raise ValueError("Signed payload length is invalid")
    payload = blob[off:off + plen]
    return pub_b, sig_b, payload


def sign_token_flow(args):
    token = args.token
    if not token:
        raise ValueError("Missing --token")

    payload = decode_payload(token)
    pw = None
    if args.signing_pass:
        pw = get_password(args.signing_pass, prompt="Enter passphrase for signing private key: ").encode("utf-8")

    priv = load_ed25519_private_key(args.signing_private, pw)
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    signature = priv.sign(payload)
    signed_blob = pack_signed_payload(payload, pub_raw, signature)
    print(encode_payload(signed_blob))


def verify_token_flow(args):
    token = args.token
    if not token:
        raise ValueError("Missing --token")

    signed_blob = decode_payload(token)
    embedded_pub_raw, sig_b, payload = unpack_signed_payload(signed_blob)

    # If signer public key is provided, verify against it (recommended).
    if args.signer_public:
        pub = load_ed25519_public_key(args.signer_public)
        pub_raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if pub_raw != embedded_pub_raw:
            raise ValueError("Signer public key mismatch (token embedded key differs from provided key)")
        pub.verify(sig_b, payload)
    else:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(embedded_pub_raw)
        pub.verify(sig_b, payload)

    if args.print_payload:
        # output original payload as a token (base64) for easy reuse
        print(encode_payload(payload))
    else:
        print("[OK] Signature verified")


def sign_file_flow(args):
    in_path = Path(args.input).resolve()
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")
    data = in_path.read_bytes()

    # Determine whether input is token text or raw bytes
    is_raw_in = args.raw_input or in_path.suffix.lower() in (".aesbin", ".sigbin", ".bin")
    if not is_raw_in:
        try:
            token = data.decode("utf-8").strip()
            payload = decode_payload(token)
        except Exception:
            raise ValueError("Input file does not look like a valid token. Use --raw-input for binary input.")
    else:
        payload = data

    pw = None
    if args.signing_pass:
        pw = get_password(args.signing_pass, prompt="Enter passphrase for signing private key: ").encode("utf-8")

    priv = load_ed25519_private_key(args.signing_private, pw)
    pub = priv.public_key()
    pub_raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    sig_b = priv.sign(payload)
    signed_blob = pack_signed_payload(payload, pub_raw, sig_b)

    out_path = Path(args.output).resolve() if args.output else None
    if args.raw:
        if out_path is None:
            out_path = in_path.with_suffix(in_path.suffix + ".sigbin")
        out_path = force_suffix(out_path, ".sigbin")
        write_file(out_path, signed_blob, force=args.force)
    else:
        if out_path is None:
            out_path = in_path.with_suffix(in_path.suffix + ".sig")
        out_path = force_suffix(out_path, ".sig")
        write_file(out_path, encode_payload(signed_blob).encode("utf-8"), force=args.force)

    print(f"[OK] Signed output: {out_path}")


def verify_file_flow(args):
    in_path = Path(args.input).resolve()
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")
    data = in_path.read_bytes()

    is_raw_in = args.raw_input or in_path.suffix.lower() in (".sigbin", ".bin")
    if not is_raw_in:
        token = data.decode("utf-8").strip()
        signed_blob = decode_payload(token)
    else:
        signed_blob = data

    embedded_pub_raw, sig_b, payload = unpack_signed_payload(signed_blob)

    if args.signer_public:
        pub = load_ed25519_public_key(args.signer_public)
        pub_raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        if pub_raw != embedded_pub_raw:
            raise ValueError("Signer public key mismatch (embedded key differs from provided key)")
        pub.verify(sig_b, payload)
    else:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(embedded_pub_raw)
        pub.verify(sig_b, payload)

    # Write extracted payload if requested
    if args.output:
        out_path = Path(args.output).resolve()
        if args.payload_raw:
            out_path = append_suffix_if_missing(out_path, ".bin")
            write_file(out_path, payload, force=args.force)
        else:
            out_path = force_suffix(out_path, ".token")
            write_file(out_path, encode_payload(payload).encode("utf-8"), force=args.force)
        print(f"[OK] Signature verified. Payload written: {out_path}")
    else:
        print("[OK] Signature verified")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="aes256-cli",
        description="Secure AES-256 CLI encryption/decryption for text and .txt files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command")

    p_help = subparsers.add_parser("help", help="Show command help")
    p_help.set_defaults(func=help_flow, parser=parser)

    p_example = subparsers.add_parser("example", help="Show command examples")
    p_example.set_defaults(func=example_flow)

    p_settings = subparsers.add_parser("settings", help="View/update settings (stored in ~/.aes256-cli/settings.json). Use: settings show | settings load | settings <key> <value>")
    p_settings.add_argument("key", nargs="?", help="Setting key (e.g., key_timestamp) or 'show'")
    p_settings.add_argument("value", nargs="?", help="New value (e.g., true/false)")
    p_settings.set_defaults(func=settings_flow)

    password_help = "Password text or .txt password file (if omitted, prompt securely)"

    p_enc_text = subparsers.add_parser("encrypt-text", help="Encrypt a text string")
    p_enc_text.add_argument("-t", "--text", help="Text to encrypt")
    p_enc_text.add_argument("-p", "--password", help=password_help)
    p_enc_text.set_defaults(func=encrypt_text_flow)

    p_dec_text = subparsers.add_parser("decrypt-text", help="Decrypt a text token")
    p_dec_text.add_argument("-t", "--token", help="Encrypted token")
    p_dec_text.add_argument("-p", "--password", help=password_help)
    p_dec_text.set_defaults(func=decrypt_text_flow)

    p_enc_file = subparsers.add_parser("encrypt-file", help="Encrypt a .txt file")
    p_enc_file.add_argument("-i", "--input", required=True, help="Input .txt file path")
    p_enc_file.add_argument("-o", "--output", help="Output encrypted file path (auto-forced to .aes or .aesbin when --raw)")
    p_enc_file.add_argument("--raw", action="store_true", help="Write raw binary payload instead of a base64 token file")
    p_enc_file.add_argument("-p", "--password", help=password_help)
    p_enc_file.set_defaults(func=encrypt_file_flow)

    p_dec_file = subparsers.add_parser("decrypt-file", help="Decrypt an encrypted file")
    p_dec_file.add_argument("-i", "--input", required=True, help="Input encrypted file path")
    p_dec_file.add_argument("-o", "--output", help="Output decrypted .txt file path (forced to .txt; default: input.decrypted.txt)")
    p_dec_file.add_argument("--raw", action="store_true", help="Read raw binary payload (or use .aesbin extension)")
    p_dec_file.add_argument("-p", "--password", help=password_help)
    p_dec_file.set_defaults(func=decrypt_file_flow)

    p_gen_keys = subparsers.add_parser("generate-keypair", help="Generate RSA private/public .pem files")
    p_gen_keys.add_argument(
        "--private-out",
        help="Private key output base path (auto-forced to .pem; timestamp is appended if settings.key_timestamp=true)",
    )
    p_gen_keys.add_argument(
        "--public-out",
        help="Public key output base path (auto-forced to .pem; timestamp is appended if settings.key_timestamp=true)",
    )
    p_gen_keys.add_argument("--bits", type=int, choices=[2048, 3072, 4096], default=4096, help="RSA key size")
    p_gen_keys.add_argument(
        "--private-pass",
        help="Password text or .txt file to encrypt private key PEM (optional)",
    )
    p_gen_keys.add_argument(
        "--encrypt-private",
        action="store_true",
        help="Prompt for private key password and encrypt private key PEM",
    )
    p_gen_keys.add_argument("--force", action="store_true", help="Overwrite key files if they already exist")
    p_gen_keys.set_defaults(func=generate_keypair_flow)

    private_key_pass_help = "Private key password text or .txt file (if key is encrypted)"

    p_enc_text_pem = subparsers.add_parser("encrypt-text-pem", help="Encrypt text with RSA public key (.pem)")
    p_enc_text_pem.add_argument("-t", "--text", help="Text to encrypt")
    p_enc_text_pem.add_argument("--public-key", required=True, help="Public key PEM path")
    p_enc_text_pem.set_defaults(func=encrypt_text_pem_flow)

    p_dec_text_pem = subparsers.add_parser("decrypt-text-pem", help="Decrypt text token with RSA private key (.pem)")
    p_dec_text_pem.add_argument("-t", "--token", help="Encrypted token")
    p_dec_text_pem.add_argument("--private-key", required=True, help="Private key PEM path")
    p_dec_text_pem.add_argument("--private-pass", help=private_key_pass_help)
    p_dec_text_pem.set_defaults(func=decrypt_text_pem_flow)

    p_enc_file_pem = subparsers.add_parser("encrypt-file-pem", help="Encrypt a file with RSA public key (.pem)")
    p_enc_file_pem.add_argument("-i", "--input", required=True, help="Input file path")
    p_enc_file_pem.add_argument("-o", "--output", help="Output encrypted file path (auto-forced to .aes or .aesbin with --raw)")
    p_enc_file_pem.add_argument("--public-key", required=True, help="Public key PEM path")
    p_enc_file_pem.add_argument("--raw", action="store_true", help="Write raw binary payload to .aesbin (recommended for files)")
    p_enc_file_pem.set_defaults(func=encrypt_file_pem_flow)

    p_dec_file_pem = subparsers.add_parser("decrypt-file-pem", help="Decrypt a file with RSA private key (.pem)")
    p_dec_file_pem.add_argument("-i", "--input", required=True, help="Input encrypted file path")
    p_dec_file_pem.add_argument("-o", "--output", help="Output decrypted file path (auto-appends .decrypted if no extension)")
    p_dec_file_pem.add_argument("--private-key", required=True, help="Private key PEM path")
    p_dec_file_pem.add_argument("--private-pass", help=private_key_pass_help)
    p_dec_file_pem.add_argument("--raw", action="store_true", help="Read raw binary payload (.aesbin). Auto-detected by .aesbin extension.")
    p_dec_file_pem.set_defaults(func=decrypt_file_pem_flow)

    # Signing (Ed25519) mode
    p_gen_sign = subparsers.add_parser("generate-signing-keypair", help="Generate Ed25519 signing private/public .pem files")
    p_gen_sign.add_argument("--private-out", help="Signing private key output base path (auto-forced to .pem; timestamp is appended if settings.key_timestamp=true)")
    p_gen_sign.add_argument("--public-out", help="Signing public key output base path (auto-forced to .pem; timestamp is appended if settings.key_timestamp=true)")
    p_gen_sign.add_argument("--encrypt-private", action="store_true", help="Encrypt signing private key with a passphrase")
    p_gen_sign.add_argument("--private-pass", help="Passphrase for signing private key (text or .txt file). If omitted, prompt when needed.")
    p_gen_sign.add_argument("--force", action="store_true", help="Overwrite output files if they exist")
    p_gen_sign.set_defaults(func=generate_signing_keypair_flow)

    p_sign_token = subparsers.add_parser("sign-token", help="Sign an encrypted token (Ed25519)")
    p_sign_token.add_argument("-t", "--token", required=True, help="Token to sign (base64 payload token)")
    p_sign_token.add_argument("--signing-private", required=True, help="Ed25519 signing private key (.pem)")
    p_sign_token.add_argument("--signing-pass", help="Passphrase for signing private key (text or .txt file). If omitted, prompt when needed.")
    p_sign_token.set_defaults(func=sign_token_flow)

    p_verify_token = subparsers.add_parser("verify-token", help="Verify a signed token (Ed25519)")
    p_verify_token.add_argument("-t", "--token", required=True, help="Signed token to verify")
    p_verify_token.add_argument("--signer-public", help="Expected signer public key (.pem). Recommended for trust.")
    p_verify_token.add_argument("--print-payload", action="store_true", help="Print the original (unsigned) payload token after verification")
    p_verify_token.set_defaults(func=verify_token_flow)

    p_sign_file = subparsers.add_parser("sign-file", help="Sign a token file or raw binary file (Ed25519)")
    p_sign_file.add_argument("-i", "--input", required=True, help="Input file to sign (token text file or raw binary)")
    p_sign_file.add_argument("-o", "--output", help="Output signed file path (auto-forced to .sig or .sigbin when --raw)")
    p_sign_file.add_argument("--raw", action="store_true", help="Write signed wrapper as raw binary (.sigbin required when -o is used)")
    p_sign_file.add_argument("--raw-input", action="store_true", help="Treat input file as raw binary payload (not a token text file)")
    p_sign_file.add_argument("--signing-private", required=True, help="Ed25519 signing private key (.pem)")
    p_sign_file.add_argument("--signing-pass", help="Passphrase for signing private key (text or .txt file). If omitted, prompt when needed.")
    p_sign_file.add_argument("--force", action="store_true", help="Overwrite output file if it exists")
    p_sign_file.set_defaults(func=sign_file_flow)

    p_verify_file = subparsers.add_parser("verify-file", help="Verify a signed file (.sig/.sigbin) and optionally extract payload")
    p_verify_file.add_argument("-i", "--input", required=True, help="Signed input file (.sig token text or .sigbin raw)")
    p_verify_file.add_argument("-o", "--output", help="Where to write extracted payload (optional; .token unless --payload-raw, then auto-appends .bin if no extension)")
    p_verify_file.add_argument("--payload-raw", action="store_true", help="When extracting, write raw bytes instead of a token text file")
    p_verify_file.add_argument("--raw-input", action="store_true", help="Treat input file as raw (.sigbin) even if extension differs")
    p_verify_file.add_argument("--signer-public", help="Expected signer public key (.pem). Recommended for trust.")
    p_verify_file.add_argument("--force", action="store_true", help="Overwrite output file if it exists")
    p_verify_file.set_defaults(func=verify_file_flow)

    return parser


def run_command(parser: argparse.ArgumentParser, argv: list[str], interactive: bool) -> bool:
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return False

    if not hasattr(args, "func"):
        parser.print_help()
        return False

    args.func(args)
    return True


def interactive_shell(parser: argparse.ArgumentParser) -> None:
    last_result = ""

    while True:
        try:
            clear_screen()
            print_dashboard(last_result)
            line = input("Enter command > ").strip()
            if not line:
                continue

            argv = shlex.split(line)
            executed = run_command(parser, argv, interactive=True)
            if executed:
                last_result = "[OK] Command completed."
            else:
                last_result = "[INFO] See command help above."
            input("\nPress Enter to continue...")
        except KeyboardInterrupt:
            clear_screen()
            print("[EXIT] Stopped by user (Ctrl + C).")
            break
        except EOFError:
            clear_screen()
            print("[EXIT] End of input.")
            break
        except ValueError as exc:
            last_result = f"[ERROR] {format_error(exc)}"
        except Exception as exc:
            last_result = f"[ERROR] {format_error(exc)}"



def format_error(exc: Exception) -> str:
    # Provide user-friendly, non-leaky messages for common failures.
    if isinstance(exc, InvalidTag):
        return "Authentication failed: wrong password/key or the data is corrupted."
    if isinstance(exc, FileNotFoundError):
        return str(exc)
    if isinstance(exc, PermissionError):
        return f"Permission denied: {exc}"
    if isinstance(exc, ValueError):
        return str(exc)
    return str(exc)


def launch_gui() -> int:
    try:
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QFileDialog,
            QFormLayout,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPlainTextEdit,
            QPushButton,
            QScrollArea,
            QStackedWidget,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        print("[ERROR] PyQt6 is not installed. Install it with: pip install PyQt6", file=sys.stderr)
        return 2

    class AesGui(QMainWindow):
        def __init__(self):
            super().__init__()
            self.parser = build_parser()
            self.subparsers_action = self._get_subparsers_action()
            self.command_fields: dict[str, list[dict]] = {}
            self.setWindowTitle("AES256 GUI (PyQt6)")
            self.resize(960, 640)
            self.setMinimumSize(820, 560)
            self._build_ui()

        def _get_subparsers_action(self):
            for action in self.parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    return action
            raise RuntimeError("CLI parser has no subcommands.")

        def _build_ui(self) -> None:
            root = QWidget()
            root_layout = QVBoxLayout(root)
            root_layout.setContentsMargins(10, 10, 10, 10)
            root_layout.setSpacing(8)

            command_row = QWidget()
            command_layout = QHBoxLayout(command_row)
            command_layout.setContentsMargins(0, 0, 0, 0)
            command_layout.setSpacing(8)
            self.command_combo = QComboBox()
            for command_name in self.subparsers_action.choices.keys():
                self.command_combo.addItem(command_name)
            self.command_combo.currentTextChanged.connect(self._on_command_changed)
            self.run_button = QPushButton("Run Command")
            self.run_button.clicked.connect(lambda _checked=False: self._run_action(self._run_selected_command))
            self.clear_button = QPushButton("Clear Fields")
            self.clear_button.clicked.connect(lambda _checked=False: self._clear_current_command_fields())
            command_layout.addWidget(QLabel("Command"))
            command_layout.addWidget(self.command_combo, 1)
            command_layout.addWidget(self.run_button)
            command_layout.addWidget(self.clear_button)
            root_layout.addWidget(command_row)

            self.command_help_label = QLabel()
            self.command_help_label.setWordWrap(True)
            self.command_help_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            root_layout.addWidget(self.command_help_label)

            self.form_stack = QStackedWidget()
            for command_name, subparser in self.subparsers_action.choices.items():
                self.form_stack.addWidget(self._build_command_page(command_name, subparser))
            root_layout.addWidget(self.form_stack, 3)

            preview_row = QWidget()
            preview_layout = QHBoxLayout(preview_row)
            preview_layout.setContentsMargins(0, 0, 0, 0)
            preview_layout.setSpacing(8)
            self.preview_line = QLineEdit()
            self.preview_line.setReadOnly(True)
            copy_btn = QPushButton("Copy CLI")
            copy_btn.clicked.connect(self._copy_preview_to_clipboard)
            preview_layout.addWidget(QLabel("CLI Preview"))
            preview_layout.addWidget(self.preview_line, 1)
            preview_layout.addWidget(copy_btn)
            root_layout.addWidget(preview_row)

            log_row = QWidget()
            log_layout = QHBoxLayout(log_row)
            log_layout.setContentsMargins(0, 0, 0, 0)
            log_layout.setSpacing(8)
            log_layout.addWidget(QLabel("Log"))
            self.clear_log_button = QPushButton("Clear Log")
            self.clear_log_button.clicked.connect(self._clear_log)
            log_layout.addStretch(1)
            log_layout.addWidget(self.clear_log_button)
            root_layout.addWidget(log_row)

            self.log_box = QPlainTextEdit()
            self.log_box.setReadOnly(True)
            self.log_box.setMinimumHeight(180)
            root_layout.addWidget(self.log_box, 2)

            self.setCentralWidget(root)
            self.statusBar().showMessage("Ready")
            self._on_command_changed(self.command_combo.currentText())

        def _build_command_page(self, command_name: str, subparser) -> QWidget:
            page = QWidget()
            page_layout = QVBoxLayout(page)
            page_layout.setContentsMargins(0, 0, 0, 0)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            page_layout.addWidget(scroll)

            content = QWidget()
            form = QFormLayout(content)
            form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
            form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
            form.setContentsMargins(6, 6, 6, 6)
            form.setSpacing(10)
            scroll.setWidget(content)

            fields = []
            for action in subparser._actions:
                if isinstance(action, argparse._HelpAction):
                    continue
                field_meta = self._create_input_for_action(action)
                fields.append(field_meta)
                form.addRow(self._action_label(action), field_meta["container"])
            self.command_fields[command_name] = fields

            if not fields:
                note = QLabel("This command has no options.")
                note.setWordWrap(True)
                form.addRow("", note)
            return page

        def _create_input_for_action(self, action) -> dict:
            if isinstance(action, argparse._StoreTrueAction):
                checkbox = QCheckBox(action.help or "")
                checkbox.setChecked(bool(action.default))
                checkbox.toggled.connect(lambda _checked=False: self._refresh_preview())
                return {
                    "action": action,
                    "kind": "flag",
                    "widget": checkbox,
                    "container": checkbox,
                    "default": bool(action.default),
                }

            if action.choices:
                combo = QComboBox()
                is_required = self._is_required_action(action)
                if not is_required:
                    combo.addItem("")
                for choice in action.choices:
                    combo.addItem(str(choice))
                default_text = ""
                if action.default is not None and action.default is not argparse.SUPPRESS:
                    default_text = str(action.default)
                    idx = combo.findText(default_text)
                    if idx >= 0:
                        combo.setCurrentIndex(idx)
                combo.setToolTip(action.help or "")
                combo.currentTextChanged.connect(lambda _text="": self._refresh_preview())
                return {
                    "action": action,
                    "kind": "choice",
                    "widget": combo,
                    "container": combo,
                    "default": default_text,
                }

            if action.dest in {"text", "token"}:
                edit = QPlainTextEdit()
                edit.setPlaceholderText(action.help or "")
                edit.setMinimumHeight(100)
                edit.textChanged.connect(self._refresh_preview)
                return {
                    "action": action,
                    "kind": "plain",
                    "widget": edit,
                    "container": edit,
                    "default": "",
                }

            line = QLineEdit()
            if action.help:
                line.setPlaceholderText(action.help)
                line.setToolTip(action.help)
            line.textChanged.connect(lambda _text="": self._refresh_preview())

            default_text = ""
            if action.default not in (None, argparse.SUPPRESS, False):
                default_text = str(action.default)
                line.setText(default_text)

            container: QWidget = line
            if action.dest in {"input", "output", "private_out", "public_out", "public_key", "private_key", "signing_private", "signer_public"}:
                holder = QWidget()
                row = QHBoxLayout(holder)
                row.setContentsMargins(0, 0, 0, 0)
                row.setSpacing(6)
                browse_btn = QPushButton("Browse")
                browse_btn.clicked.connect(
                    lambda _checked=False, d=action.dest, e=line: self._browse_for_dest(d, e)
                )
                row.addWidget(line, 1)
                row.addWidget(browse_btn)
                container = holder
            elif action.dest in {"password", "private_pass", "signing_pass"}:
                holder = QWidget()
                row = QHBoxLayout(holder)
                row.setContentsMargins(0, 0, 0, 0)
                row.setSpacing(6)
                load_btn = QPushButton("Load .txt")
                load_btn.clicked.connect(lambda _checked=False, e=line: self._load_password_file(e))
                row.addWidget(line, 1)
                row.addWidget(load_btn)
                container = holder

            return {
                "action": action,
                "kind": "line",
                "widget": line,
                "container": container,
                "default": default_text,
            }

        def _action_label(self, action) -> str:
            if action.option_strings:
                long_opts = [opt for opt in action.option_strings if opt.startswith("--")]
                base = long_opts[0] if long_opts else action.option_strings[0]
            else:
                base = action.dest
            if self._is_required_action(action):
                return f"{base} *"
            return base

        def _is_required_action(self, action) -> bool:
            if action.option_strings:
                return bool(getattr(action, "required", False))
            return action.nargs not in ("?", "*")

        def _preferred_option(self, action) -> str:
            long_opts = [opt for opt in action.option_strings if opt.startswith("--")]
            return long_opts[0] if long_opts else action.option_strings[0]

        def _browse_for_dest(self, dest: str, line_edit: QLineEdit) -> None:
            current_text = line_edit.text().strip()
            if current_text:
                current_path = Path(current_text).expanduser()
                start_dir = str(current_path.parent if current_path.suffix else current_path)
            else:
                start_dir = str(Path.cwd())

            pem_filter = "PEM Files (*.pem);;All Files (*)"
            all_filter = "All Files (*)"
            use_save = dest in {"output", "private_out", "public_out"}
            pem_dests = {"private_out", "public_out", "public_key", "private_key", "signing_private", "signer_public"}
            use_filter = pem_filter if dest in pem_dests else all_filter

            if use_save:
                selected, _ = QFileDialog.getSaveFileName(self, "Select output path", start_dir, use_filter)
            else:
                selected, _ = QFileDialog.getOpenFileName(self, "Select file", start_dir, use_filter)
            if selected:
                line_edit.setText(selected)

        def _load_password_file(self, line_edit: QLineEdit) -> None:
            start_dir = str(Path.cwd())
            selected, _ = QFileDialog.getOpenFileName(self, "Select password file", start_dir, "Text Files (*.txt);;All Files (*)")
            if selected:
                line_edit.setText(selected)

        def _on_command_changed(self, command_name: str) -> None:
            if command_name not in self.command_fields:
                return
            command_index = self.command_combo.findText(command_name)
            if command_index >= 0:
                self.form_stack.setCurrentIndex(command_index)
            subparser = self.subparsers_action.choices.get(command_name)
            help_text = ""
            if subparser is not None:
                help_text = getattr(subparser, "description", None) or getattr(subparser, "help", None) or ""
            if not help_text:
                for choice_action in self.subparsers_action._choices_actions:
                    if choice_action.dest == command_name:
                        help_text = choice_action.help or ""
                        break
            self.command_help_label.setText(help_text or "No description.")
            self._refresh_preview()

        def _clear_current_command_fields(self) -> None:
            command = self.command_combo.currentText()
            for meta in self.command_fields.get(command, []):
                kind = meta["kind"]
                widget = meta["widget"]
                default_value = meta["default"]
                if kind == "flag":
                    widget.setChecked(bool(default_value))
                elif kind == "choice":
                    idx = widget.findText(default_value)
                    if idx >= 0:
                        widget.setCurrentIndex(idx)
                    else:
                        widget.setCurrentIndex(0)
                elif kind == "plain":
                    widget.setPlainText(default_value)
                else:
                    widget.setText(default_value)
            self._refresh_preview()

        def _collect_argv(self, command_name: str) -> list[str]:
            argv: list[str] = [command_name]
            for meta in self.command_fields.get(command_name, []):
                action = meta["action"]
                kind = meta["kind"]
                widget = meta["widget"]

                if kind == "flag":
                    if widget.isChecked():
                        argv.append(self._preferred_option(action))
                    continue

                if kind == "choice":
                    value = widget.currentText()
                elif kind == "plain":
                    value = widget.toPlainText()
                else:
                    value = widget.text()

                value_is_empty = value.strip() == ""
                if value_is_empty:
                    if self._is_required_action(action):
                        raise ValueError(f"Missing required argument: {self._action_label(action)}")
                    continue

                if action.option_strings:
                    argv.append(self._preferred_option(action))
                    argv.append(value)
                else:
                    argv.append(value)
            return argv

        def _collect_values_by_dest(self, command_name: str) -> dict[str, object]:
            values: dict[str, object] = {}
            for meta in self.command_fields.get(command_name, []):
                action = meta["action"]
                kind = meta["kind"]
                widget = meta["widget"]
                if kind == "flag":
                    values[action.dest] = bool(widget.isChecked())
                elif kind == "choice":
                    values[action.dest] = widget.currentText().strip()
                elif kind == "plain":
                    values[action.dest] = widget.toPlainText()
                else:
                    values[action.dest] = widget.text().strip()
            return values

        def _validate_non_interactive_requirements(self, command_name: str) -> None:
            values = self._collect_values_by_dest(command_name)

            if command_name in {"encrypt-text", "decrypt-text", "encrypt-file", "decrypt-file"}:
                if not str(values.get("password", "")).strip():
                    raise ValueError("`--password` is required in GUI mode for this command.")

            if command_name == "generate-keypair":
                if bool(values.get("encrypt_private")) and not str(values.get("private_pass", "")).strip():
                    raise ValueError("`--private-pass` is required when `--encrypt-private` is enabled in GUI mode.")

            if command_name == "generate-signing-keypair":
                if bool(values.get("encrypt_private")) and not str(values.get("private_pass", "")).strip():
                    raise ValueError("`--private-pass` is required when `--encrypt-private` is enabled in GUI mode.")

            if command_name in {"decrypt-text-pem", "decrypt-file-pem"}:
                private_key_path = str(values.get("private_key", "")).strip()
                private_pass = str(values.get("private_pass", "")).strip()
                if private_key_path and not private_pass:
                    key_data = resolve_key_path(private_key_path).read_bytes()
                    if b"ENCRYPTED" in key_data:
                        raise ValueError("Private key is encrypted. Please fill `--private-pass`.")

            if command_name in {"sign-token", "sign-file"}:
                signing_private_path = str(values.get("signing_private", "")).strip()
                signing_pass = str(values.get("signing_pass", "")).strip()
                if signing_private_path and not signing_pass:
                    key_data = resolve_key_path(signing_private_path).read_bytes()
                    if b"ENCRYPTED" in key_data:
                        raise ValueError("Signing private key is encrypted. Please fill `--signing-pass`.")

        def _refresh_preview(self) -> None:
            command = self.command_combo.currentText()
            try:
                argv = self._collect_argv(command)
                self.preview_line.setText(" ".join(shlex.quote(part) for part in argv))
            except Exception:
                self.preview_line.clear()

        def _run_action(self, action) -> None:
            try:
                action()
            except Exception as exc:
                message = format_error(exc)
                self._log(message, is_error=True)
                self.statusBar().showMessage(f"Error: {message}", 6000)
                QMessageBox.critical(self, "Error", message)

        def _run_selected_command(self) -> None:
            self._clear_log()
            command = self.command_combo.currentText()
            self._validate_non_interactive_requirements(command)
            argv = self._collect_argv(command)
            self.preview_line.setText(" ".join(shlex.quote(part) for part in argv))

            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                try:
                    executed = run_command(self.parser, argv, interactive=False)
                    if not executed:
                        print("[INFO] Command did not execute. Check arguments or command syntax.")
                except Exception as exc:
                    print(f"[ERROR] {format_error(exc)}", file=sys.stderr)

            stdout_text = stdout_buf.getvalue().strip()
            stderr_text = stderr_buf.getvalue().strip()
            if stdout_text:
                self._log(stdout_text)
            if stderr_text:
                self._log(stderr_text, is_error=True)
            if not stdout_text and not stderr_text:
                self._log("[OK] Command completed.")

            self.statusBar().showMessage("Command completed.", 4000)

        def _clear_log(self) -> None:
            self.log_box.clear()

        def _copy_preview_to_clipboard(self) -> None:
            preview = self.preview_line.text().strip()
            if not preview:
                raise ValueError("Nothing to copy. Fill required fields first.")
            QApplication.clipboard().setText(preview)
            self.statusBar().showMessage("CLI preview copied.", 2500)
            self._log("[OK] Copied CLI preview.")

        def _log(self, message: str, is_error: bool = False) -> None:
            level = "ERROR" if is_error else "INFO"
            ts = datetime.now().strftime("%H:%M:%S")
            for line in str(message).splitlines():
                line = line.strip()
                if line:
                    self.log_box.appendPlainText(f"[{ts}] [{level}] {line}")

    app = QApplication(sys.argv)
    window = AesGui()
    window.show()
    return app.exec()


def main():
    parser = build_parser()
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        code = launch_gui()
        if code:
            sys.exit(code)
        return

    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        cli_args = sys.argv[2:]
        try:
            if cli_args:
                run_command(parser, cli_args, interactive=False)
            else:
                interactive_shell(parser)
        except Exception as exc:
            print(f"\n[ERROR] {format_error(exc)}", file=sys.stderr)
            sys.exit(1)
        return

    if len(sys.argv) > 1:
        try:
            run_command(parser, sys.argv[1:], interactive=False)
        except Exception as exc:
            print(f"\n[ERROR] {format_error(exc)}", file=sys.stderr)
            sys.exit(1)
    else:
        code = launch_gui()
        if code:
            sys.exit(code)


if __name__ == "__main__":
    main()
