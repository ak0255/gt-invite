from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests
import os
from dotenv import load_dotenv
import logging
import time
import json
import uuid
from datetime import datetime, timedelta, timezone
from jinja2 import ChoiceLoader, FileSystemLoader

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 兼容：模板既可以放在 templates/ 目录，也可以直接放在项目根目录
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(os.path.join(BASE_DIR, "templates")),
    FileSystemLoader(BASE_DIR),
])
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")

ACCESS_PASSWORD = os.getenv("ACCESS_PASSWORD", "")
UPSTASH_REDIS_REST_URL = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")
WORKSPACES_KEY = os.getenv("WORKSPACES_KEY", "workspaces")

logging.getLogger("werkzeug").setLevel(logging.ERROR)
app.logger.setLevel(logging.INFO)


class No404Filter(logging.Filter):
    def filter(self, record):
        return not (getattr(record, "status_code", None) == 404)


logging.getLogger("werkzeug").addFilter(No404Filter())

CF_TURNSTILE_SECRET_KEY = os.getenv("CF_TURNSTILE_SECRET_KEY")
CF_TURNSTILE_SITE_KEY = os.getenv("CF_TURNSTILE_SITE_KEY")

STATS_CACHE_TTL = 60
stats_cache = {}  # {workspace_id: {"timestamp": 0, "data": None}}

def load_workspaces_from_upstash():
    """从 Upstash Redis 读取工作空间配置列表"""
    if not UPSTASH_REDIS_REST_URL or not UPSTASH_REDIS_REST_TOKEN:
        return []

    try:
        resp = requests.get(
            f"{UPSTASH_REDIS_REST_URL}/get/{WORKSPACES_KEY}",
            headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
            timeout=5,
        )
        if resp.status_code != 200:
            app.logger.error(
                f"Upstash GET failed: {resp.status_code} {resp.text}"
            )
            return []

        data = resp.json()
        # Upstash REST API 的返回格式一般是 {"result": "xxx"} 
        value = data.get("result")
        if not value:
            return []

        workspaces = json.loads(value)
        if isinstance(workspaces, list):
            return workspaces
        else:
            app.logger.error("Upstash workspaces value is not a list")
            return []
    except Exception as e:
        app.logger.error(f"Failed to load workspaces from Upstash: {e}")
        return []


def save_workspaces_to_upstash(workspaces):
    """把工作空间列表写入 Upstash Redis"""
    if not UPSTASH_REDIS_REST_URL or not UPSTASH_REDIS_REST_TOKEN:
        app.logger.warning("Upstash is not configured, skip saving workspaces")
        return

    try:
        payload = json.dumps(workspaces, ensure_ascii=False)
        resp = requests.post(
            f"{UPSTASH_REDIS_REST_URL}/set/{WORKSPACES_KEY}",
            headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
            data=payload.encode("utf-8"),
            timeout=5,
        )
        if resp.status_code != 200:
            app.logger.error(
                f"Upstash SET failed: {resp.status_code} {resp.text}"
            )
    except Exception as e:
        app.logger.error(f"Failed to save workspaces to Upstash: {e}")

def load_workspaces_from_env():
    """加载工作空间配置，支持多种格式"""
    workspaces = []
    
    # 方式1: 尝试从 WORKSPACES JSON 环境变量加载
    workspaces_json = os.getenv("WORKSPACES")
    if workspaces_json:
        try:
            workspaces = json.loads(workspaces_json)
            return workspaces
        except json.JSONDecodeError:
            app.logger.error("Failed to parse WORKSPACES JSON")
    
    # 方式2: 尝试从 WORKSPACE_X_* 环境变量加载
    i = 1
    while True:
        name = os.getenv(f"WORKSPACE_{i}_NAME")
        if not name:
            break
        
        workspace = {
            "id": f"workspace{i}",
            "name": name,
            "authorization_token": os.getenv(f"WORKSPACE_{i}_AUTHORIZATION_TOKEN"),
            "account_id": os.getenv(f"WORKSPACE_{i}_ACCOUNT_ID")
        }
        workspaces.append(workspace)
        i += 1
    
    if workspaces:
        return workspaces
    
    # 方式3: 向后兼容，使用原有的单一配置
    authorization_token = os.getenv("AUTHORIZATION_TOKEN")
    account_id = os.getenv("ACCOUNT_ID")
    
    if authorization_token and account_id:
        workspaces = [{
            "id": "default",
            "name": "默认工作空间",
            "authorization_token": authorization_token,
            "account_id": account_id
        }]
    
    return workspaces

def load_workspaces():
    """总入口：优先从 Upstash 读，没有再用环境变量"""
    # 1. 先试试 Upstash
    from_upstash = load_workspaces_from_upstash()
    if from_upstash:
        app.logger.info(f"Loaded {len(from_upstash)} workspaces from Upstash")
        return from_upstash

    # 2. 如果 Upstash 里还没配置，就走老的环境变量逻辑
    from_env = load_workspaces_from_env()
    if from_env:
        app.logger.info(f"Loaded {len(from_env)} workspaces from env")
        # 顺便写回 Upstash，后面就都从 Upstash 管理
        save_workspaces_to_upstash(from_env)
        return from_env

    app.logger.warning("No workspaces configured")
    return []


def _migrate_workspaces_to_uuid(workspaces):
    """将旧的 workspaceN / default 等形式迁移为 UUID 主键，并确保唯一性。

    迁移策略：
    - 如果缺少 id，或 id 重复，则生成新的 UUID。
    - 如果 id 不是 UUID 格式（例如 workspace1/default），也会迁移为 UUID。
    - 保留 name / authorization_token / account_id 字段。
    """
    if not isinstance(workspaces, list):
        return workspaces, False

    changed = False
    seen_ids = set()
    migrated = []

    def _is_uuid_like(s: str) -> bool:
        try:
            uuid.UUID(str(s))
            return True
        except Exception:
            return False

    for ws in workspaces:
        if not isinstance(ws, dict):
            changed = True
            continue

        ws = dict(ws)
        old_id = ws.get("id")

        need_new_id = False
        if not old_id:
            need_new_id = True
        elif old_id in seen_ids:
            need_new_id = True
        elif not _is_uuid_like(old_id):
            # 旧格式一律迁移
            need_new_id = True

        if need_new_id:
            ws["id"] = uuid.uuid4().hex
            changed = True

        # 极低概率碰撞，但还是保险一下
        while ws["id"] in seen_ids:
            ws["id"] = uuid.uuid4().hex
            changed = True

        seen_ids.add(ws["id"])
        migrated.append(ws)

    return migrated, changed


# 全局加载工作空间配置
WORKSPACES = load_workspaces()

# 启动时：自动迁移旧 ID 并回写，防止出现“workspace4 重复 / 删除连坐”
WORKSPACES, _migrated = _migrate_workspaces_to_uuid(WORKSPACES)
if _migrated:
    save_workspaces_to_upstash(WORKSPACES)

def save_workspaces(workspaces):
    """更新内存中的 WORKSPACES 并同步到 Upstash"""
    global WORKSPACES
    WORKSPACES = workspaces
    save_workspaces_to_upstash(workspaces)

# 登录功能
def is_authenticated():
    return session.get("authenticated", False)

@app.route("/login", methods=["GET", "POST"])
def login():
    # 如果已经登录过，就直接去首页
    if is_authenticated():
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":
        password = request.form.get("password", "")
        # 用环境变量里的密码校验
        if ACCESS_PASSWORD and password == ACCESS_PASSWORD:
            session["authenticated"] = True
            # 登录成功后跳回首页
            return redirect(url_for("index"))
        else:
            error = "密钥错误，请重试。"

    # 这里渲染一个简单的登录页面
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin/workspaces", methods=["GET", "POST"])
def manage_workspaces():
    if not is_authenticated():
        return redirect(url_for("login"))

    error = None
    message = None
    global WORKSPACES

    if request.method == "POST":
        action = request.form.get("action", "add")

        # ========== 删除 ==========
        if action == "delete":
            workspace_id = request.form.get("workspace_id", "").strip()
            if not workspace_id:
                error = "缺少 workspace_id，删除失败。"
            else:
                old_len = len(WORKSPACES)
                WORKSPACES = [
                    ws for ws in WORKSPACES
                    if ws.get("id") != workspace_id
                ]
                if len(WORKSPACES) == old_len:
                    error = "未找到对应的工作空间，删除失败。"
                else:
                    save_workspaces(WORKSPACES)  # 这里会写回 Upstash
                    message = f"已删除工作空间：{workspace_id}"

        # ========== 新增 ==========
        else:
            name = request.form.get("name", "").strip()
            authorization_token = request.form.get("authorization_token", "").strip()
            account_id = request.form.get("account_id", "").strip()

            if not name or not authorization_token or not account_id:
                error = "名称、AUTH_TOKEN、ACCOUNT_ID 都不能为空。"
            else:
                for ws in WORKSPACES:
                    if ws.get("account_id") == account_id:
                        error = "该 ACCOUNT_ID 已存在。"
                        break

            if not error:
                # 使用更稳定的 UUID 主键，避免并发/删除导致的 ID 重复
                new_id = uuid.uuid4().hex
                existing_ids = {ws.get("id") for ws in WORKSPACES if isinstance(ws, dict)}
                while new_id in existing_ids:
                    new_id = uuid.uuid4().hex
                new_ws = {
                    "id": new_id,
                    "name": name,
                    "authorization_token": authorization_token,
                    "account_id": account_id,
                }
                WORKSPACES.append(new_ws)
                save_workspaces(WORKSPACES)
                message = f"已成功添加工作空间：{name}"

    return render_template(
        "manage_workspaces.html",
        workspaces=WORKSPACES,
        error=error,
        message=message,
    )




def get_workspace_by_id(workspace_id):
    """根据ID获取工作空间"""
    for ws in WORKSPACES:
        if ws["id"] == workspace_id:
            return ws
    return None


def get_client_ip_address():
    if "CF-Connecting-IP" in request.headers:
        return request.headers["CF-Connecting-IP"]
    if "X-Forwarded-For" in request.headers:
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "unknown"


def build_base_headers(workspace):
    return {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9",
        "authorization": workspace["authorization_token"],
        "chatgpt-account-id": workspace["account_id"],
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    }


def build_invite_headers(workspace):
    headers = build_base_headers(workspace)
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


def stats_expired(workspace_id):
    if workspace_id not in stats_cache:
        return True
    if stats_cache[workspace_id]["data"] is None:
        return True
    return time.time() - stats_cache[workspace_id]["timestamp"] >= STATS_CACHE_TTL


def refresh_stats(workspace_id):
    workspace = get_workspace_by_id(workspace_id)
    if not workspace:
        raise ValueError(f"Workspace {workspace_id} not found")
    
    base_headers = build_base_headers(workspace)
    account_id = workspace["account_id"]
    
    subs_url = f"https://chatgpt.com/backend-api/subscriptions?account_id={account_id}"
    invites_url = f"https://chatgpt.com/backend-api/accounts/{account_id}/invites?offset=0&limit=1&query="

    subs_resp = requests.get(subs_url, headers=base_headers, timeout=10)
    subs_resp.raise_for_status()
    subs_data = subs_resp.json()

    invites_resp = requests.get(invites_url, headers=base_headers, timeout=10)
    invites_resp.raise_for_status()
    invites_data = invites_resp.json()

    stats = {
        "workspace_id": workspace_id,
        "workspace_name": workspace["name"],
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

    stats_cache[workspace_id] = {
        "data": stats,
        "timestamp": time.time()
    }
    return stats


@app.route("/")
def index():
    if not is_authenticated():
        return redirect(url_for("login"))

    client_ip = get_client_ip_address()
    app.logger.info(f"Index page accessed by IP: {client_ip}")
    return render_template("index.html", site_key=CF_TURNSTILE_SITE_KEY)

@app.route("/workspaces")
def workspaces():
    if not is_authenticated():
        return redirect(url_for("login"))

    client_ip = get_client_ip_address()
    app.logger.info(f"Workspaces list requested from IP: {client_ip}")
    
    workspace_list = [{"id": ws["id"], "name": ws["name"]} for ws in WORKSPACES]
    return jsonify({"success": True, "workspaces": workspace_list})


@app.route("/send-invites", methods=["POST"])
def send_invites():
    if not is_authenticated():
        return redirect(url_for("login"))

    client_ip = get_client_ip_address()
    app.logger.info(f"Invitation request received from IP: {client_ip}")

    raw_emails = request.form.get("emails", "").strip()
    email_list, valid_emails = parse_emails(raw_emails)
    
    workspace_id = request.form.get("workspace_id", "")
    if not workspace_id and WORKSPACES:
        workspace_id = WORKSPACES[0]["id"]
    
    workspace = get_workspace_by_id(workspace_id)
    if not workspace:
        return jsonify({"success": False, "message": "Invalid workspace selected."})

    cf_turnstile_response = request.form.get("cf-turnstile-response")
    turnstile_valid = validate_turnstile(cf_turnstile_response)

    if not turnstile_valid:
        app.logger.warning(f"CAPTCHA verification failed for IP: {client_ip}")
        return jsonify({"success": False, "message": "CAPTCHA verification failed.  Please try again."})

    if not email_list:
        return jsonify({"success": False, "message": "Please enter at least one email address."})

    if not valid_emails:
        return jsonify({"success": False, "message": "Email addresses are not valid.  Please check and try again."})

    headers = build_invite_headers(workspace)
    payload = {"email_addresses": valid_emails, "role": "standard-user", "resend_emails": True}
    invite_url = f"https://chatgpt.com/backend-api/accounts/{workspace['account_id']}/invites"

    try:
        resp = requests.post(invite_url, headers=headers, json=payload, timeout=10)
        if resp.status_code == 200:
            app.logger.info(f"Successfully sent invitations to {len(valid_emails)} emails from IP: {client_ip} to workspace: {workspace['name']}")
            return jsonify(
                {
                    "success": True,
                    "message": f"成功向 {workspace['name']} 发送邀请: {', '.join(valid_emails)}",
                }
            )
        else:
            app.logger.error(f"Failed to send invitations from IP: {client_ip}.Status code: {resp.status_code}")
            return jsonify(
                {
                    "success": False,
                    "message": "Failed to send invitations.",
                    "details": {"status_code": resp.status_code, "body": resp.text},
                }
            )
    except Exception as e:
        app.logger.error(f"Error sending invitations from IP: {client_ip}.Error: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route("/stats")
def stats():
    # 先做访问密码校验（你之前已经实现的）
    if not is_authenticated():
        return redirect(url_for("login"))

    client_ip = get_client_ip_address()
    app.logger.info(f"Stats requested from IP: {client_ip}")

    refresh = request.args.get("refresh") == "1"
    get_all = request.args.get("all") == "1"
    workspace_id = request.args.get("workspace_id", "")

    # =========① all=1：返回所有工作空间统计（单个失败不拖垮整体）=========
    if get_all:
        all_stats = []

        for ws in WORKSPACES:
            ws_id = ws.get("id")
            ws_name = ws.get("name")

            try:
                # 和你原来的逻辑一样：先看缓存是否过期，决定是否 refresh
                if refresh or stats_expired(ws_id):
                    data = refresh_stats(ws_id)
                else:
                    data = stats_cache.get(ws_id, {}).get("data")
                    if not data:
                        data = refresh_stats(ws_id)

                # 避免直接修改缓存里的原始 dict，这里拷一份
                data = dict(data) if isinstance(data, dict) else {}

                # 确保 id 和 name 始终存在，方便前端使用
                data.setdefault("workspace_id", ws_id)
                data.setdefault("workspace_name", ws_name)

                # 计算更新时间字符串
                updated_at = None
                if ws_id in stats_cache and stats_cache[ws_id].get("timestamp"):
                    ts = stats_cache[ws_id]["timestamp"]
                    dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
                    cst_tz = timezone(timedelta(hours=8))
                    dt_cst = dt_utc.astimezone(cst_tz)
                    updated_at = dt_cst.strftime("%Y-%m-%d %H:%M:%S")

                data["updated_at"] = updated_at

                # 标记当前 workspace 统计是有效的
                data["is_valid"] = True
                data["error"] = None

            except Exception as e:
                # 关键：这里吞掉单个 workspace 的异常，只在该条记录上标记错误
                app.logger.error(
                    f"Failed to fetch stats for workspace {ws_id} from IP: {client_ip}. Error: {str(e)}"
                )

                data = {
                    "workspace_id": ws_id,
                    "workspace_name": ws_name,
                    "seats_in_use": 0,
                    "seats_entitled": 0,
                    "pending_invites": 0,
                    "plan_type": None,
                    "active_start": None,
                    "active_until": None,
                    "billing_period": None,
                    "billing_currency": None,
                    "will_renew": None,
                    "is_delinquent": None,
                    "updated_at": None,
                    "is_valid": False,
                    "error": str(e),
                }

            all_stats.append(data)

        # 注意：这里无论有多少个 workspace 失败，接口整体仍然 success=True
        return jsonify({"success": True, "data": all_stats})

    # =========② 单个 workspace 的统计=========
    # 如果没指定 workspace_id，就默认第一个
    if not workspace_id and WORKSPACES:
        workspace_id = WORKSPACES[0]["id"]

    if not get_workspace_by_id(workspace_id):
        return jsonify({"success": False, "message": "Invalid workspace"}), 400

    try:
        if refresh:
            data = refresh_stats(workspace_id)
            expired = False
        else:
            expired = stats_expired(workspace_id)
            if expired or workspace_id not in stats_cache:
                data = refresh_stats(workspace_id)
                expired = False
            else:
                data = stats_cache[workspace_id]["data"]

        updated_at = None
        if workspace_id in stats_cache and stats_cache[workspace_id].get("timestamp"):
            ts = stats_cache[workspace_id]["timestamp"]
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
        # 单个 workspace 视角下失败，才把 success 设为 False
        app.logger.error(
            f"Error fetching stats for workspace {workspace_id} from IP: {client_ip}. Error: {str(e)}"
        )
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Error fetching stats: {str(e)}",
                }
            ),
            500,
        )


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 39001))
    app.run(debug=False, host="0.0.0.0", port=port)



