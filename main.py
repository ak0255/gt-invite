from flask import Flask, render_template, request, jsonify
import requests
import os
from dotenv import load_dotenv
import logging
import time
from datetime import datetime, timedelta, timezone

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")

logging.getLogger("werkzeug").setLevel(logging.ERROR)
app.logger.setLevel(logging.INFO)


class No404Filter(logging.Filter):
    def filter(self, record):
        return not (getattr(record, "status_code", None) == 404)


logging.getLogger("werkzeug").addFilter(No404Filter())

AUTHORIZATION_TOKEN = os.getenv("AUTHORIZATION_TOKEN")
ACCOUNT_ID = os.getenv("ACCOUNT_ID")
CF_TURNSTILE_SECRET_KEY = os.getenv("CF_TURNSTILE_SECRET_KEY")
CF_TURNSTILE_SITE_KEY = os.getenv("CF_TURNSTILE_SITE_KEY")

STATS_CACHE_TTL = 60
stats_cache = {"timestamp": 0, "data": None}


def get_client_ip_address():
    if "CF-Connecting-IP" in request.headers:
        return request.headers["CF-Connecting-IP"]
    if "X-Forwarded-For" in request.headers:
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "unknown"


def build_base_headers():
    return {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9",
        "authorization": AUTHORIZATION_TOKEN,
        "chatgpt-account-id": ACCOUNT_ID,
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    }


def build_invite_headers():
    headers = build_base_headers()
    headers.update(
        {
            "content-type": "application/json",
            "origin": "https://chatgpt.com",
            "referer": "https://chatgpt.com/",
            'sec-ch-ua': '"Chromium";v="135", "Not)A;Brand";v="99", "Google Chrome";v="135"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
    )
    return headers


def parse_emails(raw_emails):
    if not raw_emails:
        return [], []
    parts = raw_emails.replace("\n", ",").split(",")
    emails = [p.strip() for p in parts if p.strip()]
    valid = [e for e in emails if e.count("@") == 1]
    return emails, valid


def validate_turnstile(turnstile_response):
    if not turnstile_response:
        return False
    data = {
        "secret": CF_TURNSTILE_SECRET_KEY,
        "response": turnstile_response,
        "remoteip": get_client_ip_address(),
    }
    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            timeout=10,
        )
        result = response.json()
        return result.get("success", False)
    except Exception:
        return False


def stats_expired():
    if stats_cache["data"] is None:
        return True
    return time.time() - stats_cache["timestamp"] >= STATS_CACHE_TTL


def refresh_stats():
    base_headers = build_base_headers()
    subs_url = f"https://chatgpt.com/backend-api/subscriptions?account_id={ACCOUNT_ID}"
    invites_url = f"https://chatgpt.com/backend-api/accounts/{ACCOUNT_ID}/invites?offset=0&limit=1&query="

    subs_resp = requests.get(subs_url, headers=base_headers, timeout=10)
    subs_resp.raise_for_status()
    subs_data = subs_resp.json()

    invites_resp = requests.get(invites_url, headers=base_headers, timeout=10)
    invites_resp.raise_for_status()
    invites_data = invites_resp.json()

    stats = {
        "seats_in_use": subs_data.get("seats_in_use"),
        "seats_entitled": subs_data.get("seats_entitled"),
        "pending_invites": invites_data.get("total"),
        "plan_type": subs_data.get("plan_type"),
        "active_start": subs_data.get("active_start"),
        "active_until": subs_data.get("active_until"),
        "billing_period": subs_data.get("billing_period"),
        "billing_currency": subs_data.get("billing_currency"),
        "will_renew": subs_data.get("will_renew"),
        "is_delinquent": subs_data.get("is_delinquent"),
    }

    stats_cache["data"] = stats
    stats_cache["timestamp"] = time.time()
    return stats


@app.route("/")
def index():
    client_ip = get_client_ip_address()
    app.logger.info(f"Index page accessed by IP: {client_ip}")
    return render_template("index.html", site_key=CF_TURNSTILE_SITE_KEY)


@app.route("/send-invites", methods=["POST"])
def send_invites():
    client_ip = get_client_ip_address()
    app.logger.info(f"Invitation request received from IP: {client_ip}")

    raw_emails = request.form.get("emails", "").strip()
    email_list, valid_emails = parse_emails(raw_emails)

    cf_turnstile_response = request.form.get("cf-turnstile-response")
    turnstile_valid = validate_turnstile(cf_turnstile_response)

    if not turnstile_valid:
        app.logger.warning(f"CAPTCHA verification failed for IP: {client_ip}")
        return jsonify({"success": False, "message": "CAPTCHA verification failed. Please try again."})

    if not email_list:
        return jsonify({"success": False, "message": "Please enter at least one email address."})

    if not valid_emails:
        return jsonify({"success": False, "message": "Email addresses are not valid. Please check and try again."})

    headers = build_invite_headers()
    payload = {"email_addresses": valid_emails, "role": "standard-user", "resend_emails": True}
    invite_url = f"https://chatgpt.com/backend-api/accounts/{ACCOUNT_ID}/invites"

    try:
        resp = requests.post(invite_url, headers=headers, json=payload, timeout=10)
        if resp.status_code == 200:
            app.logger.info(f"Successfully sent invitations to {len(valid_emails)} emails from IP: {client_ip}")
            return jsonify(
                {
                    "success": True,
                    "message": f"Successfully sent invitations for: {', '.join(valid_emails)}",
                }
            )
        else:
            app.logger.error(f"Failed to send invitations from IP: {client_ip}. Status code: {resp.status_code}")
            return jsonify(
                {
                    "success": False,
                    "message": "Failed to send invitations.",
                    "details": {"status_code": resp.status_code, "body": resp.text},
                }
            )
    except Exception as e:
        app.logger.error(f"Error sending invitations from IP: {client_ip}. Error: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route("/stats")
def stats():
    client_ip = get_client_ip_address()
    app.logger.info(f"Stats requested from IP: {client_ip}")

    refresh = request.args.get("refresh") == "1"

    try:
        if refresh:
            data = refresh_stats()
            expired = False
        else:
            expired = stats_expired()
            if stats_cache["data"] is None:
                data = refresh_stats()
                expired = False
            else:
                data = stats_cache["data"]

        updated_at = None
        if stats_cache["timestamp"]:
            ts = stats_cache["timestamp"]
            dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
            cst_tz = timezone(timedelta(hours=8))
            dt_cst = dt_utc.astimezone(cst_tz)
            updated_at = dt_cst.strftime("%Y-%m-%d %H:%M:%S")

        return jsonify(
            {
                "success": True,
                "data": data,
                "expired": expired,
                "updated_at": updated_at,
            }
        )
    except Exception as e:
        app.logger.error(f"Error fetching stats from IP: {client_ip}. Error: {str(e)}")
        return jsonify({"success": False, "message": f"Error fetching stats: {str(e)}"}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 39001))
    app.run(debug=False, host="0.0.0.0", port=port)

