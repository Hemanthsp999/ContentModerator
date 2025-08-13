import os
import requests
from dotenv import load_dotenv

load_dotenv()
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")


def send_slack_alert(user_email, category, confidence, reason):
    """Send an alert to Slack when inappropriate content is detected."""
    if not SLACK_WEBHOOK_URL:
        print("Slack Webhook URL not configured")
        return False

    message = {
        "text": f":rotating_light: *Content Alert!* :rotating_light:\n"
                f"*User:* {user_email}\n"
                f"*Category:* {category}\n"
                f"*Confidence:* {confidence:.2f}\n"
                f"*Reason:* {reason}"
    }

    print(message)

    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=message)
        return resp.status_code == 200
    except Exception as e:
        print(f"Error sending Slack alert: {e}")
        return False

