# MIFARE Classic RFID Reader/Writer

Web-based MIFARE Classic card reader/writer using the [Web Serial API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Serial_API) and a PN532 module over USB serial (HSU mode).

## Features

- **Read & write** MIFARE Classic 1K, 4K, and Mini cards
- **Sector dump** — read all blocks from all sectors
- **Block editor** — hex editor with ASCII preview
- **Key finder** — tries ~90 known factory and backdoor keys
- **Value block operations** — increment, decrement, restore
- **Clone** — read a card to buffer, write to another card
- **Card detection** — SAK/ATQA-based type identification
- **Dark theme** — styled after [jpdias.me](https://jpdias.me)

## Compatible Devices

Any PN532 module that exposes a USB serial (CDC/ACM) port in HSU mode.

| Device                          | Interface         | Chip              | Notes                                           |
| ------------------------------- | ----------------- | ----------------- | ----------------------------------------------- |
| **ELECHOUSE PN532 USB**         | USB-C             | CH340             | Plug-and-play, recommended                      |
| **MTools Tec All-In-One PN532** | Micro-USB / USB-C | CH340E            | With battery/SPP/BLE expansion                  |
| **MTools Tec PN532 Module**     | USB via adapter   | CH340             | Standard breakout board                         |
| **Generic PN532 breakout**      | USB-TTL adapter   | CH340/CP2102/FTDI | Any HSU-capable USB-serial adapter works        |
| **Elechouse PN532 V3/V4**       | SPI/I2C/HSU       | —                 | Set DIP switches to HSU, connect via USB-serial |
| **Adafruit PN532 Shield**       | SPI/HSU           | —                 | Use HSU mode with external USB-serial adapter   |
| **CYTRON PN532 Kit**            | USB               | CH340             | Arduino-compatible                              |

### What does NOT work

- **MFRC522** — different chip, different protocol (not PN532)
- **ACR122U** — uses a different command set (not raw PN532 frames)
- **Phone NFC** — Web Serial requires a desktop browser
- **PN5180/PN532 clones with proprietary firmware** — must speak standard PN532 HSU frames

## Requirements

- **Chrome/Edge 89+** on Windows, macOS, or Linux
- HTTPS or localhost (required for Web Serial API)
- PN532 module connected via USB

## Usage

1. Connect your PN532 module via USB
2. Open the page (or run locally — see below)
3. Click **Connect** and select the serial port
4. Click **Scan Card** to detect a MIFARE Classic card
5. Use **Find Keys** to discover keys, then **Dump All** to read the card

### Run Locally

```bash
# Serve over HTTPS (required for Web Serial)
python3 -m http.server 9090
# Then open http://localhost:9090
```

### Deploy to GitHub Pages

Push to `main` — the GitHub Actions workflow deploys automatically.

## Project Structure

```
.github/workflows/deploy.yml  — GitHub Pages CI/CD
.nojekyll                      — skip Jekyll processing
.prettierrc                    — code formatting config
index.html                     — UI (3-column layout)
style.css                      — dark theme (jpdias.me style)
app.js                         — PN532 protocol + MIFARE logic + UI
```

## PN532 Protocol Reference

Frame format (HSU):

```
[PREAMBLE 00] [START 00 FF] [LEN] [LCS] [TFI] [DATA...] [DCS] [POSTAMBLE 00]
```

- `TFI = D4` for host→PN532, `D5` for PN532→host
- `LCS = 0x100 - LEN` (length checksum)
- `DCS = 0x100 - (TFI + SUM(DATA))` (data checksum)

## MIFARE Classic Commands

| Code | Command    | Description                   |
| ---- | ---------- | ----------------------------- |
| `60` | Auth Key A | Authenticate with Key A       |
| `61` | Auth Key B | Authenticate with Key B       |
| `30` | Read       | Read 16 bytes from block      |
| `A0` | Write      | Write 16 bytes to block       |
| `C0` | Decrement  | Subtract value from block     |
| `C1` | Increment  | Add value to block            |
| `C2` | Restore    | Copy value to internal buffer |
| `B0` | Transfer   | Write buffer to block         |
| `50` | Halt       | Put card in HALT state        |

## License

MIT
