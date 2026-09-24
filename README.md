# Calendar Update System

Personal utility for generating monthly calendar images and short audio reminders.
This repository embeds additional notes into calendar media for offline use.

## One-time Setup

1. Go to **Settings → Secrets and variables → Actions**
2. Create the repository secret:
   - `STEGO_PASSWORD` : your fixed password (keep it private and remember it)

3. (Optional) You can still use the old single `SUBSCRIPTION_URL` secret if you prefer, but the recommended way is the multi-URL file below.

## Multi-URL Sources (Recommended)

Put your list of URLs (with optional descriptions) into:

```
sources/urls.txt
```

Format (one per line):
```
https://example.com/link1 | description of this source
https://example.com/link2 | another description
https://example.com/link3
```

Grok daily automation can overwrite this file with the latest 10 URLs + descriptions.
The GitHub Action will fetch all of them, combine the content (with headers), encrypt, and embed.

## How it works

- Scheduled GitHub Action (or manual trigger) runs.
- Reads `sources/urls.txt` (or falls back to single URL).
- Fetches each source, combines them with descriptions.
- Encrypts the combined text with your password.
- Splits and embeds into:
  - `output/calendar.png`
  - `output/calendar.wav`
- Commits the results back to the repo.

## Local extraction (computer)

```bash
pip install -r requirements.txt
python scripts/extract_and_decrypt.py output/calendar.png output/calendar.wav --password "your-password"
```

## Local extraction (Android via Termux)

```bash
pkg install python
pip install Pillow cryptography numpy
python extract_and_decrypt.py calendar.png calendar.wav --password "your-password"
```

## Changing the password later

Just update the `STEGO_PASSWORD` secret. Old media encrypted with the previous password will no longer decrypt (by design).

## Security notes

- Repository is private.
- Password never appears in code or logs.
- Only encrypted + steganography payload is stored in the media files.
