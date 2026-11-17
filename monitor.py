import os
import smtplib
from email.message import EmailMessage

print("Global Network Monitor starting...")

SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_PORT = int(os.environ["SMTP_PORT"])
SMTP_USERNAME = os.environ["SMTP_USERNAME"]
SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]
ALERT_FROM = os.environ["ALERT_FROM"]
ALERT_TO = os.environ["ALERT_TO"]

message = EmailMessage()

message["Subject"] = "[TEST] Global Network Monitor"
message["From"] = ALERT_FROM
message["To"] = ALERT_TO

message.set_content(
    """
Global Network Monitor Test

Congratulations!

Your GitHub Actions workflow successfully sent this email.

This confirms:

- GitHub Actions is working
- Python is working
- Your GitHub secrets are working
- SMTP authentication is working
- Email delivery is working

No actual network outage occurred.

Next step: Connect the monitor to Cloudflare Radar.
"""
)

print("Connecting to email server...")

with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()

    print("Authenticating...")

    smtp.login(
        SMTP_USERNAME,
        SMTP_PASSWORD
    )

    print("Sending test email...")

    smtp.send_message(message)

print("Email sent successfully!")
print("Global Network Monitor finished.")
