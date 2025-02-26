# Snakey Keylogger - Release Notes (26/02/2025)

## Key Features:
- **Keylogger**: Captures keyboard inputs and stores them in a log file.
- **Clipboard Monitoring**: Periodically checks and logs clipboard data.
- **Audio Recording**: Records 10-second audio clips every time it runs.
- **Screenshots**: Takes screenshots at regular intervals (every 30 seconds).
- **System Information**: Logs system details such as IP addresses, hostname, machine type, and more.

## Security:
- All collected logs are **encrypted** using the `cryptography.fernet` module to ensure data privacy.
- Encrypted files are sent via email securely using **Gmail's SMTP server** with **SSL encryption**.

## Improvement:
- The `computer_information()` function now logs the start and end times for data collection, including the total duration for better tracking.
- **Email functionality** has been refined to handle errors more gracefully (e.g., when an attachment can't be added).

## Known Issues:
- If the system doesn’t have a working internet connection, the script will fail to fetch the public IP address via the `requests` module.
- If the clipboard cannot be accessed, it will log an error message.

## Performance:
- The script is designed to be **lightweight** and operates without heavy resource consumption.
- The **keylogger** runs for 60 seconds by default, which can be adjusted if needed.

## Dependencies:
- `pynput`: For keylogging.
- `win32clipboard`: For clipboard access.
- `sounddevice` & `scipy`: For audio recording.
- `Pillow`: For screenshots.
- `cryptography`: For data encryption.
- `requests`: To get public IP.
- `smtplib`: For sending emails.


