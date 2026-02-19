# PyEncGUI / AES256 CLI + GUI

เครื่องมือเข้ารหัสไฟล์และข้อความด้วย Python ที่รองรับทั้ง **GUI (PyQt6)** และ **CLI** ในไฟล์เดียว (`cli.py`)

Python encryption toolkit for text/files with both **GUI (PyQt6)** and **CLI** in one file (`cli.py`).

---

## ภาษาไทย

### คุณสมบัติหลัก
- เข้ารหัส/ถอดรหัสข้อความด้วยรหัสผ่าน (AES-256)
- เข้ารหัส/ถอดรหัสด้วยกุญแจ RSA (`.pem`)
- สร้าง RSA keypair และ Ed25519 signing keypair
- เซ็น/ตรวจสอบลายเซ็น token และไฟล์ (`sign/verify`)
- GUI แบบฟอร์มครบทุกคำสั่งจาก CLI
- CLI ยังใช้งานได้เหมือนเดิม

### ความต้องการระบบ
- Python 3.10+
- แพ็กเกจ:
  - `cryptography`
  - `PyQt6`

### ติดตั้ง
```bash
pip install cryptography PyQt6
```

### เริ่มใช้งาน
- เปิด GUI (ค่าเริ่มต้น):
```bash
python cli.py
```

- เปิด GUI แบบระบุชัดเจน:
```bash
python cli.py --gui
```

- ใช้งาน CLI:
```bash
python cli.py --cli help
```

### คำสั่งที่รองรับ
- `help`
- `example`
- `settings`
- `encrypt-text`
- `decrypt-text`
- `encrypt-file`
- `decrypt-file`
- `generate-keypair`
- `encrypt-text-pem`
- `decrypt-text-pem`
- `encrypt-file-pem`
- `decrypt-file-pem`
- `generate-signing-keypair`
- `sign-token`
- `verify-token`
- `sign-file`
- `verify-file`

### การใช้งาน GUI แบบเร็ว
1. เลือกคำสั่งจากช่อง `Command`
2. กรอกค่าที่ต้องใช้ (`*` = จำเป็น)
3. กด `Run Command`
4. ดูผลลัพธ์ใน `Log`

### พฤติกรรมนามสกุลไฟล์ (Auto Extension)
ระบบจะช่วยล็อค/เติมนามสกุลให้อัตโนมัติเพื่อลดความผิดพลาด:

- `generate-keypair` / `generate-signing-keypair`:
  - `--private-out`, `--public-out` จะถูกบังคับเป็น `.pem`
- `encrypt-file`:
  - ปกติบังคับ `.aes`
  - ถ้า `--raw` บังคับ `.aesbin`
- `encrypt-file-pem`:
  - ปกติบังคับ `.aes`
  - ถ้า `--raw` บังคับ `.aesbin`
- `decrypt-file`:
  - output จะถูกบังคับเป็น `.txt`
- `decrypt-file-pem`:
  - ถ้าไม่ใส่นามสกุล output จะเติม `.decrypted`
- `sign-file`:
  - ปกติบังคับ `.sig`
  - ถ้า `--raw` บังคับ `.sigbin`
- `verify-file`:
  - ถ้าไม่ใช้ `--payload-raw` output จะบังคับเป็น `.token`
  - ถ้าใช้ `--payload-raw` และไม่ใส่นามสกุล จะเติม `.bin`

### ตัวอย่าง workflow ไฟล์ที่ถูก sign ไว้ (`.sig`)
ถ้าคุณมี `notes_encrypted.sig`:

1. Verify และดึง payload ออกก่อน
```bash
python cli.py --cli verify-file -i notes_encrypted.sig --signer-public sign_public.pem -o notes_payload
```

2. ถอดรหัส payload ที่ได้
- ถ้าเข้ารหัสด้วย password:
```bash
python cli.py --cli decrypt-file -i notes_payload.token -p password.txt -o notes_dec
```
- ถ้าเข้ารหัสด้วย PEM:
```bash
python cli.py --cli decrypt-file-pem -i notes_payload.token --private-key private_key.pem --private-pass password.txt -o notes_dec
```

### Settings
- ไฟล์ settings: `~/.aes256-cli/settings.json`
- ค่าที่ใช้: `key_timestamp` (true/false)
  - คุมการต่อ timestamp ตอนสร้าง key files

---

## English

### Key Features
- Password-based text/file encryption and decryption (AES-256)
- RSA PEM-based encryption and decryption
- RSA keypair and Ed25519 signing keypair generation
- Token/file signing and verification
- Full GUI form coverage for all CLI commands
- Backward-compatible CLI usage

### Requirements
- Python 3.10+
- Packages:
  - `cryptography`
  - `PyQt6`

### Installation
```bash
pip install cryptography PyQt6
```

### Run
- Start GUI (default):
```bash
python cli.py
```

- Start GUI explicitly:
```bash
python cli.py --gui
```

- Run CLI:
```bash
python cli.py --cli help
```

### Supported Commands
- `help`
- `example`
- `settings`
- `encrypt-text`
- `decrypt-text`
- `encrypt-file`
- `decrypt-file`
- `generate-keypair`
- `encrypt-text-pem`
- `decrypt-text-pem`
- `encrypt-file-pem`
- `decrypt-file-pem`
- `generate-signing-keypair`
- `sign-token`
- `verify-token`
- `sign-file`
- `verify-file`

### Quick GUI Usage
1. Select a command in `Command`
2. Fill required fields (`*`)
3. Click `Run Command`
4. Check output in `Log`

### Auto File Extension Behavior
To make usage easier, outputs are auto-normalized:

- `generate-keypair` / `generate-signing-keypair`:
  - `--private-out`, `--public-out` are forced to `.pem`
- `encrypt-file`:
  - default forced to `.aes`
  - with `--raw`, forced to `.aesbin`
- `encrypt-file-pem`:
  - default forced to `.aes`
  - with `--raw`, forced to `.aesbin`
- `decrypt-file`:
  - output is forced to `.txt`
- `decrypt-file-pem`:
  - if output has no extension, `.decrypted` is appended
- `sign-file`:
  - default forced to `.sig`
  - with `--raw`, forced to `.sigbin`
- `verify-file`:
  - without `--payload-raw`, output is forced to `.token`
  - with `--payload-raw`, `.bin` is appended when no extension is provided

### Example: Decrypt a Signed Encrypted File (`.sig`)
If you have `notes_encrypted.sig`:

1. Verify signature and extract payload
```bash
python cli.py --cli verify-file -i notes_encrypted.sig --signer-public sign_public.pem -o notes_payload
```

2. Decrypt extracted payload
- Password mode:
```bash
python cli.py --cli decrypt-file -i notes_payload.token -p password.txt -o notes_dec
```
- PEM mode:
```bash
python cli.py --cli decrypt-file-pem -i notes_payload.token --private-key private_key.pem --private-pass password.txt -o notes_dec
```

### Settings
- Settings file: `~/.aes256-cli/settings.json`
- Current setting: `key_timestamp` (true/false)
  - Controls timestamp suffix on generated key files

