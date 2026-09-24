# Calendar Update System

Personal utility for generating monthly calendar images and short audio reminders.

This repository contains scripts that can embed additional notes into calendar media for offline use.

## Setup (one-time)

1. Go to **Settings → Secrets and variables → Actions**
2. Create two repository secrets:
   - `STEGO_PASSWORD` : your fixed password (keep it private)
   - `SUBSCRIPTION_URL` : the source URL that returns the content to be processed (plain text / yaml link)

3. (Optional) Enable Actions if not already enabled.

## How it works

- A scheduled GitHub Action runs periodically.
- It fetches content from `SUBSCRIPTION_URL`.
- Encrypts the content with your password.
- Splits and embeds the ciphertext into:
  - A generated monthly calendar image (PNG)
  - A short calendar-style audio (WAV)
- Commits the resulting files into the `output/` folder.

You only need to download the latest files from `output/` and run the local extractor with the same password.

## Local extraction

```bash
pip install -r requirements.txt
python scripts/extract_and_decrypt.py output/calendar.png output/calendar.wav --password "your-password"
```

The recovered content will be printed / saved.

## Changing the password later

Just update the `STEGO_PASSWORD` secret in GitHub. Old files encrypted with the previous password will no longer be recoverable (by design).

## Security notes

- Repository is private.
- Password never appears in code or logs.
- Only the encrypted + steganography payload is stored in the media files.
