"""Sending email.

Render's free plan blocks outgoing SMTP ports (25/465/587), so on Render use an HTTP email API:
  BREVO_API_KEY   (free 300 emails/day; verify one sender address, no domain needed)   <- recommended
  RESEND_API_KEY  (needs a verified domain to email other people)
  SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASSWORD  (works on your laptop or paid hosts, e.g. Gmail app password)
Sender: MAIL_FROM (e.g. yourname@gmail.com, must be verified with the provider) and MAIL_FROM_NAME.
With none configured, emails are written to the server log and kept in OUTBOX (used by the tests), so sign-up and
sign-in still work.

Sending happens in a background thread: a slow email provider never delays a sign-in.
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import threading
from collections import deque
from email.message import EmailMessage

log = logging.getLogger("payguard.mail")
OUTBOX: deque = deque(maxlen=50)          # last messages (console mode and tests)
STATUS: deque = deque(maxlen=20)          # (provider, to-domain, ok/error) for /api/health


def provider() -> str:
    if os.environ.get("BREVO_API_KEY"):
        return "brevo"
    if os.environ.get("RESEND_API_KEY"):
        return "resend"
    if os.environ.get("SMTP_HOST"):
        return "smtp"
    return "console"


def _sender() -> tuple[str, str]:
    return os.environ.get("MAIL_FROM_NAME", "PayGuard"), os.environ.get("MAIL_FROM", "no-reply@payguard.local")


def _send_now(to: str, subject: str, html: str, text: str) -> None:
    import httpx
    p = provider()
    name, addr = _sender()
    try:
        if p == "brevo":
            r = httpx.post("https://api.brevo.com/v3/smtp/email", timeout=15,
                           headers={"api-key": os.environ["BREVO_API_KEY"], "accept": "application/json",
                                    "content-type": "application/json"},
                           content=json.dumps({"sender": {"name": name, "email": addr}, "to": [{"email": to}],
                                               "subject": subject, "htmlContent": html, "textContent": text}))
            r.raise_for_status()
        elif p == "resend":
            r = httpx.post("https://api.resend.com/emails", timeout=15,
                           headers={"Authorization": f"Bearer {os.environ['RESEND_API_KEY']}"},
                           json={"from": f"{name} <{addr}>", "to": [to], "subject": subject, "html": html, "text": text})
            r.raise_for_status()
        elif p == "smtp":
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = f"{name} <{addr}>", to, subject
            msg.set_content(text)
            msg.add_alternative(html, subtype="html")
            port = int(os.environ.get("SMTP_PORT", "587"))
            if port == 465:
                s = smtplib.SMTP_SSL(os.environ["SMTP_HOST"], port, timeout=15)
            else:
                s = smtplib.SMTP(os.environ["SMTP_HOST"], port, timeout=15)
                s.starttls()
            with s:
                if os.environ.get("SMTP_USER"):
                    s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
                s.send_message(msg)
        else:
            OUTBOX.append({"to": to, "subject": subject, "text": text, "html": html})
            log.warning("EMAIL (no provider configured) to=%s subject=%s\n%s", to, subject, text)
        STATUS.append((p, to.split("@")[-1], "ok"))
    except Exception as e:  # never break the request that triggered the email
        STATUS.append((p, to.split("@")[-1], f"error: {type(e).__name__}"))
        log.error("email to %s failed via %s: %s", to.split("@")[-1], p, e)


def send(to: str, subject: str, html: str, text: str, wait: bool = False) -> None:
    if wait or os.environ.get("PAYGUARD_MAIL_SYNC") == "1":
        _send_now(to, subject, html, text)
    else:
        threading.Thread(target=_send_now, args=(to, subject, html, text), daemon=True).start()
