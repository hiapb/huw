#!/usr/bin/env bash

# Huawei Cloud DNS IP guard
# Multi-account, multi-task A/AAAA health checks with DDNS source syncing.

set -uo pipefail
export LC_ALL=C

APP="huawei-dns-guard"
BASE_DIR="${HUAWEI_DNS_GUARD_BASE_DIR:-/etc/${APP}}"
CONFIG_FILE="${BASE_DIR}/config.json"
STATE_DIR="${HUAWEI_DNS_GUARD_STATE_DIR:-/var/lib/${APP}}"
LOG_FILE="${HUAWEI_DNS_GUARD_LOG_FILE:-/var/log/${APP}.log}"
BIN_PATH="${HUAWEI_DNS_GUARD_BIN_PATH:-/usr/local/sbin/${APP}}"
SERVICE_NAME="${APP}"
SERVICE_FILE="${HUAWEI_DNS_GUARD_SERVICE_FILE:-/etc/systemd/system/${SERVICE_NAME}.service}"
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SELF_PATH="$(readlink -f "$SCRIPT_PATH" 2>/dev/null || printf '%s' "$SCRIPT_PATH")"
SCRIPT_URL="${HUAWEI_DNS_GUARD_SCRIPT_URL:-https://raw.githubusercontent.com/hiapb/huw/main/install.sh}"

DEFAULT_TTL=1
DEFAULT_INTERVAL=30
DEFAULT_PING_COUNT=3
DEFAULT_PING_TIMEOUT=2
DEFAULT_CHECK_ROUNDS=3
DEFAULT_ROUND_DELAY=2
DEFAULT_MAX_PARALLEL=20
MAX_ACTIVE_IPS=50

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RESET=$'\033[0m'; BOLD=$'\033[1m'; GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'; RED=$'\033[0;31m'; CYAN=$'\033[0;36m'
else
    RESET=""; BOLD=""; GREEN=""; YELLOW=""; RED=""; CYAN=""
fi

info() { printf '%s[信息]%s %s\n' "$CYAN" "$RESET" "$*"; }
ok() { printf '%s[完成]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[注意]%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
fail() { printf '%s[错误]%s %s\n' "$RED" "$RESET" "$*" >&2; }

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        fail "请使用 root 用户运行：sudo bash huwei.sh"
        exit 1
    fi
}

require_python() {
    command -v python3 >/dev/null 2>&1 && return 0
    fail "缺少 python3。Debian/Ubuntu 请运行：apt-get install -y python3 ca-certificates"
    return 1
}

ensure_dirs() {
    install -d -m 700 "$BASE_DIR" "$STATE_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
}

pause_menu() {
    local ignored
    printf '\n按回车返回...'
    IFS= read -r ignored || true
}

menu_title() {
    printf '\n%s%s%s\n' "$BOLD" "$1" "$RESET"
    printf '%s\n' '------------------------------------------------------------'
}

menu_item() {
    printf '  %s. %s\n' "$1" "$2"
}

prompt() {
    local label="$1" default="${2:-}" value
    if [[ -n "$default" ]]; then
        printf '%s [%s]: ' "$label" "$default" >&2
    else
        printf '%s: ' "$label" >&2
    fi
    IFS= read -r value || true
    printf '%s\n' "${value:-$default}"
}

prompt_secret() {
    local label="$1" keep_old="${2:-0}" value
    if [[ "$keep_old" == "1" ]]; then
        printf '%s [回车保留原值]: ' "$label" >&2
    else
        printf '%s: ' "$label" >&2
    fi
    IFS= read -r value || true
    printf '%s\n' "$value"
}

confirm() {
    local label="$1" default="${2:-n}" answer
    if [[ "$default" == "y" ]]; then
        printf '%s [Y/n，默认是]: ' "$label" >&2
    else
        printf '%s [y/N，默认否]: ' "$label" >&2
    fi
    IFS= read -r answer || true
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy]$ ]]
}

trim() {
    local value="${1:-}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s\n' "$value"
}

is_uint() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }
in_range() {
    local value="$1" minimum="$2" maximum="$3"
    is_uint "$value" && ((10#$value >= minimum && 10#$value <= maximum))
}

valid_domain() {
    local domain="${1%.}"
    [[ ${#domain} -le 253 && "$domain" == *.* ]] || return 1
    [[ "$domain" != *..* && "$domain" != -* && "$domain" != *- ]] || return 1
    local label
    IFS=. read -r -a labels <<< "$domain"
    for label in "${labels[@]}"; do
        [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

valid_ip_for_version() {
    python3 - "$1" "$2" <<'PY' >/dev/null 2>&1
import ipaddress, sys
try:
    raise SystemExit(0 if ipaddress.ip_address(sys.argv[1]).version == int(sys.argv[2]) else 1)
except ValueError:
    raise SystemExit(1)
PY
}

new_id() {
    printf '%s-%s-%04x\n' "$1" "$(date +%s)" "$RANDOM"
}

# All configuration mutations are atomic. The migrate action upgrades the old
# one-account/one-A-record format without discarding any existing setting.
config_command() {
    local action="$1"
    shift
    python3 - "$CONFIG_FILE" "$action" "$@" <<'PY'
import json
import ipaddress
import os
import re
import sys
import tempfile

path, action = sys.argv[1:3]
args = sys.argv[3:]


def concise_exception(exc_type, exc, traceback):
    if issubclass(exc_type, (RuntimeError, ValueError, KeyError, json.JSONDecodeError)):
        print(f"错误：{exc}", file=sys.stderr)
    else:
        sys.__excepthook__(exc_type, exc, traceback)


sys.excepthook = concise_exception

DEFAULTS = {
    "ttl": 1, "interval": 30, "ping_count": 3, "ping_timeout": 2,
    "check_rounds": 3, "round_delay": 2, "max_parallel": 20,
}


def read_config():
    if not os.path.exists(path):
        return {"version": 2, "accounts": [], "tasks": []}
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise RuntimeError("配置文件根节点必须是对象")
    return data


def clean_text(value):
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


def normalize_ip_values(values):
    result = []
    seen = set()
    for value in values:
        value = clean_text(value)
        if not value:
            continue
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            pass
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def normalize(data):
    migrated = False
    if not isinstance(data.get("accounts"), list):
        data["accounts"] = []
    if not isinstance(data.get("tasks"), list):
        data["tasks"] = []
    if (data.get("ak") or data.get("sk")) and not data["accounts"]:
        account_id = "account-migrated"
        data["accounts"].append({
            "id": account_id, "name": "原华为云账号",
            "ak": str(data.get("ak", "")), "sk": str(data.get("sk", "")),
        })
        domain = clean_text(data.get("domain", "")).rstrip(".").lower()
        if domain:
            task = {
                "id": "task-migrated", "name": domain, "account_id": account_id,
                "domain": domain, "ip_version": 4, "enabled": True,
                "health_enabled": True, "ddns_domains": [], "prune_stale_ddns": True,
            }
            for key, default in DEFAULTS.items():
                task[key] = int(data.get(key, default))
            data["tasks"].append(task)
        for key in ("ak", "sk", "domain", *DEFAULTS.keys()):
            data.pop(key, None)
        migrated = True
    if data.get("version") != 3:
        migrated = True
    data["version"] = 3
    for account in data["accounts"]:
        account["id"] = clean_text(account.get("id"))
        account["name"] = clean_text(account.get("name")) or account["id"]
        account["ak"] = str(account.get("ak", "")).strip()
        account["sk"] = str(account.get("sk", "")).strip()
    for task in data["tasks"]:
        task["id"] = clean_text(task.get("id"))
        task["name"] = clean_text(task.get("name")) or clean_text(task.get("domain"))
        task["account_id"] = clean_text(task.get("account_id"))
        task["domain"] = clean_text(task.get("domain")).rstrip(".").lower()
        task["ip_version"] = int(task.get("ip_version", 4))
        task["enabled"] = bool(task.get("enabled", True))
        task["health_enabled"] = bool(task.get("health_enabled", True))
        task["prune_stale_ddns"] = bool(task.get("prune_stale_ddns", True))
        ddns_items = []
        seen_domains = set()
        for index, value in enumerate(task.get("ddns_domains", []), 1):
            if isinstance(value, dict):
                ddns_id = clean_text(value.get("id")) or f"ddns-{index}"
                ddns_name = clean_text(value.get("name"))
                ddns_domain = clean_text(value.get("domain")).rstrip(".").lower()
                ddns_backup = clean_text(value.get("backup_domain") or "").rstrip(".").lower()
                if "backup_domain" not in value:
                    migrated = True
            else:
                ddns_id = f"ddns-migrated-{index}"
                ddns_domain = clean_text(value).rstrip(".").lower()
                ddns_name = ddns_domain
                ddns_backup = ""
                migrated = True
            if not ddns_domain or ddns_domain in seen_domains:
                continue
            ddns_items.append({"id": ddns_id, "name": ddns_name or ddns_domain,
                               "domain": ddns_domain, "backup_domain": ddns_backup})
            seen_domains.add(ddns_domain)
        task["ddns_domains"] = ddns_items
        backup_items = task.get("backup_ips", [])
        if not isinstance(backup_items, list):
            backup_items = []
        task["backup_ips"] = normalize_ip_values(backup_items)
        for key, default in DEFAULTS.items():
            task[key] = int(task.get(key, default))
    return data, migrated


def validate(data):
    domain_pattern = re.compile(
        r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
    )
    ranges = {
        "ttl": (1, 2147483647), "interval": (10, 86400),
        "ping_count": (1, 10), "ping_timeout": (1, 30),
        "check_rounds": (1, 10), "round_delay": (0, 60),
        "max_parallel": (1, 100),
    }
    ids = set()
    account_names = set()
    for account in data["accounts"]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", account["id"]):
            raise RuntimeError("账号 ID 无效")
        if account["id"] in ids:
            raise RuntimeError("账号 ID 重复")
        ids.add(account["id"])
        if not account["name"]:
            raise RuntimeError("账号名称不能为空")
        normalized_name = account["name"].casefold()
        if normalized_name in account_names:
            raise RuntimeError(f"账号名称重复: {account['name']}")
        account_names.add(normalized_name)
        if not account["ak"] or not account["sk"]:
            raise RuntimeError(f"账号 {account['name']} 缺少 AK/SK")
    task_ids = set()
    task_names = set()
    for task in data["tasks"]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", task["id"]):
            raise RuntimeError("任务 ID 无效")
        if task["id"] in task_ids:
            raise RuntimeError("任务 ID 重复")
        task_ids.add(task["id"])
        if task["account_id"] not in ids:
            raise RuntimeError(f"任务 {task['name']} 绑定了不存在的账号")
        if not task["name"]:
            raise RuntimeError("任务名称不能为空")
        normalized_name = task["name"].casefold()
        if normalized_name in task_names:
            raise RuntimeError(f"任务名称重复: {task['name']}")
        task_names.add(normalized_name)
        if not domain_pattern.fullmatch(task["domain"]):
            raise RuntimeError(f"任务 {task['name']} 的记录域名无效")
        if task["ip_version"] not in (4, 6):
            raise RuntimeError("任务 IP 类型必须是 4 或 6")
        ddns_ids = set()
        ddns_names = set()
        ddns_domains = set()
        for ddns in task["ddns_domains"]:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", ddns["id"]):
                raise RuntimeError("DDNS ID 无效")
            if ddns["id"] in ddns_ids:
                raise RuntimeError(f"任务 {task['name']} 的 DDNS ID 重复")
            ddns_ids.add(ddns["id"])
            if not ddns["name"]:
                raise RuntimeError("DDNS 名称不能为空")
            normalized_name = ddns["name"].casefold()
            if normalized_name in ddns_names:
                raise RuntimeError(f"任务 {task['name']} 的 DDNS 名称重复: {ddns['name']}")
            ddns_names.add(normalized_name)
            if not domain_pattern.fullmatch(ddns["domain"]):
                raise RuntimeError(f"DDNS 域名无效: {ddns['domain']}")
            if ddns["domain"] in ddns_domains:
                raise RuntimeError(f"任务 {task['name']} 的 DDNS 域名重复: {ddns['domain']}")
            ddns_domains.add(ddns["domain"])
            if ddns.get("backup_domain"):
                if not domain_pattern.fullmatch(ddns["backup_domain"]):
                    raise RuntimeError(f"备用 DDNS 域名无效: {ddns['backup_domain']}")
                if ddns["backup_domain"] == ddns["domain"]:
                    raise RuntimeError("备用 DDNS 域名不能与主 DDNS 域名相同")
                if ddns["backup_domain"] in ddns_domains:
                    raise RuntimeError(f"任务 {task['name']} 的备用 DDNS 域名与其他主域名重复")
                ddns_domains.add(ddns["backup_domain"])
        try:
            backup_ips = [str(ipaddress.ip_address(value)) for value in task["backup_ips"]]
        except ValueError as error:
            raise RuntimeError(f"任务 {task['name']} 的备用 IP 无效") from error
        if backup_ips != task["backup_ips"] or len(set(backup_ips)) != len(backup_ips):
            raise RuntimeError(f"任务 {task['name']} 的备用 IP 存在重复或格式不规范")
        if any(ipaddress.ip_address(value).version != task["ip_version"] for value in backup_ips):
            raise RuntimeError(f"任务 {task['name']} 的备用 IP 类型与 IPv{task['ip_version']} 不匹配")
        for key, (minimum, maximum) in ranges.items():
            if not minimum <= task[key] <= maximum:
                raise RuntimeError(f"任务 {task['name']} 的 {key} 超出范围")


def write_config(data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".config.", dir=os.path.dirname(path))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def find_account(data, account_id):
    for item in data["accounts"]:
        if item["id"] == account_id:
            return item
    raise RuntimeError(f"找不到账号: {account_id}")


def find_task(data, task_id):
    for item in data["tasks"]:
        if item["id"] == task_id or item["name"] == task_id:
            return item
    raise RuntimeError(f"找不到任务: {task_id}")


data, migrated = normalize(read_config())
mutated = False

if action == "migrate":
    validate(data)
    if migrated:
        write_config(data)
        print("migrated")
elif action == "ready":
    validate(data)
    raise SystemExit(0 if data["accounts"] else 1)
elif action == "account-list":
    for item in data["accounts"]:
        print(f"{item['id']}\t{item['name']}\t{item['ak'][:4]}***{item['ak'][-2:] if len(item['ak']) > 4 else ''}")
elif action == "account-show":
    item = find_account(data, args[0])
    for key in ("id", "name", "ak", "sk"):
        print(f"{key}\t{item[key]}")
elif action == "account-add":
    account_id, name, ak, sk = args
    if any(a["id"] == account_id for a in data["accounts"]):
        raise RuntimeError("账号 ID 已存在")
    data["accounts"].append({"id": account_id, "name": clean_text(name), "ak": ak.strip(), "sk": sk.strip()})
    mutated = True
elif action == "account-update":
    account_id, name, ak, sk = args
    item = find_account(data, account_id)
    item.update({"name": clean_text(name), "ak": ak.strip(), "sk": sk.strip()})
    mutated = True
elif action == "account-delete":
    account_id = args[0]
    item = find_account(data, account_id)
    used = [t["name"] for t in data["tasks"] if t["account_id"] == account_id]
    if used:
        raise RuntimeError("账号仍被任务引用: " + ", ".join(used))
    data["accounts"].remove(item)
    mutated = True
elif action == "task-list":
    accounts = {a["id"]: a["name"] for a in data["accounts"]}
    for task in data["tasks"]:
        record_type = "A" if task["ip_version"] == 4 else "AAAA"
        fields = (
            task["id"], task["name"], task["domain"],
            f"{record_type} / IPv{task['ip_version']}",
            "启用" if task["enabled"] else "停用",
            accounts.get(task["account_id"], task["account_id"]),
            str(len(task["ddns_domains"])),
            str(len(task.get("backup_ips", []))),
        )
        print("\t".join(fields))
elif action == "task-show":
    task = find_task(data, args[0])
    account = find_account(data, task["account_id"])
    values = dict(task)
    values["account_name"] = account["name"]
    values["record_type"] = "A" if task["ip_version"] == 4 else "AAAA"
    values["ddns_count"] = len(task["ddns_domains"])
    values["backup_ips"] = ", ".join(task.get("backup_ips", []))
    values["backup_count"] = len(task.get("backup_ips", []))
    for key, value in values.items():
        if isinstance(value, bool):
            value = "1" if value else "0"
        elif key == "ddns_domains":
            value = ", ".join(item["name"] for item in value)
        print(f"{key}\t{value}")
elif action == "task-add":
    (task_id, name, account_id, domain, version, ttl, interval, ping_count,
     ping_timeout, check_rounds, round_delay, max_parallel) = args
    find_account(data, account_id)
    if any(t["id"] == task_id for t in data["tasks"]):
        raise RuntimeError("任务 ID 已存在")
    task = {
        "id": task_id, "name": clean_text(name), "account_id": account_id,
        "domain": clean_text(domain).rstrip(".").lower(), "ip_version": int(version),
        "enabled": True, "health_enabled": True, "prune_stale_ddns": True,
        "ddns_domains": [], "backup_ips": [], "ttl": int(ttl), "interval": int(interval),
        "ping_count": int(ping_count), "ping_timeout": int(ping_timeout),
        "check_rounds": int(check_rounds), "round_delay": int(round_delay),
        "max_parallel": int(max_parallel),
    }
    data["tasks"].append(task)
    mutated = True
elif action == "task-set":
    task_id, field, value = args
    task = find_task(data, task_id)
    allowed = {"name", "account_id", "domain", "ip_version", "enabled", "health_enabled",
               "prune_stale_ddns", "backup_ips", *DEFAULTS.keys()}
    if field not in allowed:
        raise RuntimeError("不允许修改该字段")
    if field == "account_id":
        find_account(data, value)
    if field in ("ip_version", *DEFAULTS.keys()):
        value = int(value)
        if field == "ip_version" and value != task["ip_version"]:
            if task["ddns_domains"]:
                raise RuntimeError("请先解除该任务的全部 DDNS 绑定，再切换 IP 类型")
            if task.get("backup_ips"):
                raise RuntimeError("请先清空该任务的备用 IP，再切换 IP 类型")
    elif field in ("enabled", "health_enabled", "prune_stale_ddns"):
        value = value.lower() in ("1", "true", "yes", "y")
    elif field == "domain":
        value = clean_text(value).rstrip(".").lower()
    elif field == "backup_ips":
        value = normalize_ip_values(value.split(","))
    else:
        value = clean_text(value)
    task[field] = value
    mutated = True
elif action == "task-delete":
    task = find_task(data, args[0])
    data["tasks"].remove(task)
    mutated = True
elif action == "ddns-list":
    for item in find_task(data, args[0])["ddns_domains"]:
        print(f"{item['id']}\t{item['name']}\t{item['domain']}\t{item.get('backup_domain', '')}")
elif action == "backup-list":
    for value in find_task(data, args[0])["backup_ips"]:
        print(value)
elif action == "backup-add":
    task_id = args[0]
    task = find_task(data, task_id)
    values = normalize_ip_values(args[1:])
    task["backup_ips"] = normalize_ip_values(task["backup_ips"] + values)
    mutated = True
elif action == "backup-remove":
    task_id = args[0]
    task = find_task(data, task_id)
    removals = set(normalize_ip_values(args[1:]))
    task["backup_ips"] = [value for value in task["backup_ips"] if value not in removals]
    mutated = True
elif action == "backup-clear":
    task = find_task(data, args[0])
    task["backup_ips"] = []
    mutated = True
elif action == "ddns-add":
    task_id, ddns_id, name, domain, backup_domain = args
    task = find_task(data, task_id)
    domain = clean_text(domain).rstrip(".").lower()
    if any(item["id"] == ddns_id for item in task["ddns_domains"]):
        raise RuntimeError("DDNS ID 已存在")
    if any(item["domain"] == domain for item in task["ddns_domains"]):
        raise RuntimeError("该 DDNS 域名已经绑定到任务")
    backup_domain = clean_text(backup_domain).rstrip(".").lower()
    if backup_domain and (backup_domain == domain or any(item.get("backup_domain") == backup_domain
                                                        or item["domain"] == backup_domain
                                                        for item in task["ddns_domains"])):
        raise RuntimeError("该备用 DDNS 域名已经绑定到任务")
    task["ddns_domains"].append({"id": ddns_id, "name": clean_text(name), "domain": domain,
                                  "backup_domain": backup_domain})
    mutated = True
elif action == "ddns-remove":
    task_id, ddns_id = args
    task = find_task(data, task_id)
    item = next((item for item in task["ddns_domains"] if item["id"] == ddns_id), None)
    if not item:
        raise RuntimeError("找不到该 DDNS 来源")
    task["ddns_domains"].remove(item)
    mutated = True
elif action == "ddns-clear":
    task = find_task(data, args[0])
    task["ddns_domains"] = []
    mutated = True
elif action == "ddns-update":
    task_id, ddns_id, name, domain, backup_domain = args
    task = find_task(data, task_id)
    item = next((item for item in task["ddns_domains"] if item["id"] == ddns_id), None)
    if not item:
        raise RuntimeError("找不到该 DDNS 来源")
    domain = clean_text(domain).rstrip(".").lower()
    if any(other["domain"] == domain and other["id"] != ddns_id for other in task["ddns_domains"]):
        raise RuntimeError("该 DDNS 域名已经绑定到任务")
    backup_domain = clean_text(backup_domain).rstrip(".").lower()
    if backup_domain and (backup_domain == domain or any(
            other.get("backup_domain") == backup_domain or other["domain"] == backup_domain
            for other in task["ddns_domains"] if other["id"] != ddns_id)):
        raise RuntimeError("该备用 DDNS 域名已经绑定到任务")
    item.update({"name": clean_text(name), "domain": domain, "backup_domain": backup_domain})
    mutated = True
elif action == "enabled-runtime":
    for task in data["tasks"]:
        if task["enabled"]:
            print(f"{task['id']}\t{task['interval']}")
elif action == "task-count":
    print(len(data["tasks"]))
else:
    raise RuntimeError(f"未知配置操作: {action}")

if mutated:
    validate(data)
    write_config(data)
PY
}

config_ready() {
    [[ -f "$CONFIG_FILE" ]] || return 1
    config_command ready >/dev/null 2>&1
}

migrate_config() {
    [[ -f "$CONFIG_FILE" ]] || return 0
    local result
    result="$(config_command migrate)" || return 1
    if [[ "$result" == "migrated" ]]; then
        ok "配置已自动升级，原有账号、任务和 DDNS 数据均已保留。"
    fi
}

load_task() {
    local requested="$1" key value count=0 first_id=""
    if [[ -z "$requested" ]]; then
        while IFS=$'\t' read -r first_id _; do
            [[ -n "$first_id" ]] || continue
            ((count++))
            TASK_ID="$first_id"
        done < <(config_command task-list)
        if ((count == 0)); then
            fail "尚未创建任务。"
            return 1
        elif ((count > 1)); then
            fail "存在多个任务，请使用 --task 任务ID 指定。可用 --tasks 查看。"
            return 1
        fi
    else
        TASK_ID="$requested"
    fi

    TASK_NAME=""; ACCOUNT_ID=""; ACCOUNT_NAME=""; DOMAIN=""; IP_VERSION=""
    RECORD_TYPE=""; ENABLED=""; HEALTH_ENABLED=""; PRUNE_STALE_DDNS=""
    TTL="$DEFAULT_TTL"; INTERVAL="$DEFAULT_INTERVAL"; PING_COUNT="$DEFAULT_PING_COUNT"
    PING_TIMEOUT="$DEFAULT_PING_TIMEOUT"; CHECK_ROUNDS="$DEFAULT_CHECK_ROUNDS"
    ROUND_DELAY="$DEFAULT_ROUND_DELAY"; MAX_PARALLEL="$DEFAULT_MAX_PARALLEL"
    DDNS_DOMAINS=""; DDNS_COUNT=0; BACKUP_IPS=""; BACKUP_COUNT=0
    while IFS=$'\t' read -r key value; do
        case "$key" in
            id) TASK_ID="$value";; name) TASK_NAME="$value";; account_id) ACCOUNT_ID="$value";;
            account_name) ACCOUNT_NAME="$value";; domain) DOMAIN="$value";; ip_version) IP_VERSION="$value";;
            record_type) RECORD_TYPE="$value";; enabled) ENABLED="$value";; health_enabled) HEALTH_ENABLED="$value";;
            prune_stale_ddns) PRUNE_STALE_DDNS="$value";; ttl) TTL="$value";; interval) INTERVAL="$value";;
            ping_count) PING_COUNT="$value";; ping_timeout) PING_TIMEOUT="$value";;
            check_rounds) CHECK_ROUNDS="$value";; round_delay) ROUND_DELAY="$value";;
            max_parallel) MAX_PARALLEL="$value";; ddns_domains) DDNS_DOMAINS="$value";;
            ddns_count) DDNS_COUNT="$value";;
            backup_ips) BACKUP_IPS="$value";; backup_count) BACKUP_COUNT="$value";;
        esac
    done < <(config_command task-show "$TASK_ID") || return 1
    [[ -n "$DOMAIN" ]]
}

task_active_count() {
    local task_id="$1" records count
    if records="$(dns_command "$task_id" records 2>/dev/null)"; then
        count="$(awk 'NF { total++ } END { print total + 0 }' <<< "$records")"
        printf '%s\n' "$count"
    else
        printf '读取失败\n'
    fi
}

# Performs Huawei Cloud SDK-HMAC-SHA256 signing, A/AAAA record management,
# family-specific DDNS resolution and ownership-safe stale DDNS cleanup.
dns_command() {
    local task_id="$1" action="$2"
    shift 2
    python3 - "$CONFIG_FILE" "$STATE_DIR" "$task_id" "$action" "$@" <<'PY'
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

CONFIG_PATH, STATE_DIR, TASK_ID, ACTION = sys.argv[1:5]
ARGS = sys.argv[5:]
MAX_ACTIVE_IPS = 50


def normalize_name(value):
    return str(value).strip().rstrip(".").lower()


with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
    config = json.load(handle)
task = next((t for t in config.get("tasks", [])
             if t.get("id") == TASK_ID or t.get("name") == TASK_ID), None)
if not task:
    print(f"错误：找不到任务 {TASK_ID}", file=sys.stderr)
    raise SystemExit(1)
TASK_ID = str(task.get("id"))
account = next((a for a in config.get("accounts", []) if a.get("id") == task.get("account_id")), None)
if not account or not account.get("ak") or not account.get("sk"):
    print("错误：任务绑定的华为云账号不存在或缺少 AK/SK", file=sys.stderr)
    raise SystemExit(1)

domain = normalize_name(task["domain"])
version = int(task["ip_version"])
record_type = "A" if version == 4 else "AAAA"
address_class = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address


def canonical_query(items):
    encoded = [(urllib.parse.quote(str(k), safe="~"), urllib.parse.quote(str(v), safe="~")) for k, v in items]
    encoded.sort()
    return "&".join(f"{k}={v}" for k, v in encoded)


def api_request(method, path, query=None, body=None):
    endpoint = "https://dns.myhuaweicloud.com"
    parsed = urllib.parse.urlsplit(endpoint)
    items = []
    for key, value in (query or {}).items():
        if isinstance(value, (list, tuple)):
            items.extend((key, item) for item in value)
        elif value is not None:
            items.append((key, value))
    query_string = canonical_query(items)
    request_path = parsed.path.rstrip("/") + path
    url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, request_path, query_string, ""))
    payload = b"" if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    sdk_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    headers_to_sign = {"host": parsed.netloc, "x-sdk-date": sdk_date}
    if body is not None:
        headers_to_sign["content-type"] = "application/json; charset=utf-8"
    names = sorted(headers_to_sign)
    signed_headers = ";".join(names)
    canonical_headers = "".join(f"{n}:{' '.join(headers_to_sign[n].strip().split())}\n" for n in names)
    canonical_uri = urllib.parse.quote(urllib.parse.unquote(request_path), safe="/-_.~")
    if not canonical_uri.startswith("/"):
        canonical_uri = "/" + canonical_uri
    if not canonical_uri.endswith("/"):
        canonical_uri += "/"
    canonical_request = "\n".join((method.upper(), canonical_uri, query_string, canonical_headers,
                                    signed_headers, hashlib.sha256(payload).hexdigest()))
    algorithm = "SDK-HMAC-SHA256"
    string_to_sign = "\n".join((algorithm, sdk_date,
        hashlib.sha256(canonical_request.encode()).hexdigest()))
    signature = hmac.new(str(account["sk"]).encode(), string_to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = f"{algorithm} Access={account['ak']}, SignedHeaders={signed_headers}, Signature={signature}"
    headers = {"Host": parsed.netloc, "X-Sdk-Date": sdk_date, "Authorization": authorization,
               "Accept": "application/json", "User-Agent": "huawei-dns-guard/2.0"}
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(url, data=payload if body is not None else None,
                                     headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw.decode()) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read().decode(errors="replace")
        try:
            detail = json.loads(raw)
            message = detail.get("error_msg") or detail.get("message") or detail.get("error_code") or raw
        except json.JSONDecodeError:
            message = raw
        raise RuntimeError(f"华为云 API HTTP {error.code}: {message}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"连接华为云 DNS API 失败: {error.reason}") from error


def list_public_zones():
    result = []
    for offset in range(0, 50000, 500):
        page = api_request("GET", "/v2/zones", {"type": "public", "limit": 500, "offset": offset}).get("zones", [])
        result.extend(page)
        if len(page) < 500:
            break
    return result


def find_zone():
    matches = []
    for zone in list_public_zones():
        name = normalize_name(zone.get("name", ""))
        if domain == name or domain.endswith("." + name):
            matches.append((len(name), zone))
    if not matches:
        raise RuntimeError(f"账号中找不到 {domain} 所属的公网域名")
    return max(matches, key=lambda value: value[0])[1]


def find_recordset(zone_id):
    data = api_request("GET", f"/v2/zones/{zone_id}/recordsets",
                       {"type": record_type, "name": domain + ".", "limit": 500})
    matches = [item for item in data.get("recordsets", [])
               if normalize_name(item.get("name", "")) == domain
               and str(item.get("type", "")).upper() == record_type]
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]
    defaults = [item for item in matches if str(item.get("line", "")).lower() in ("", "default_view")]
    if len(defaults) == 1:
        return defaults[0]
    raise RuntimeError(f"发现多个同名 {record_type} 线路，无法确定管理目标")


def clean_records(values):
    result = []
    seen = set()
    for value in values:
        try:
            normalized = str(address_class(str(value).strip()))
        except ipaddress.AddressValueError as error:
            raise RuntimeError(f"无效 IPv{version} 地址: {value}") from error
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return result


def current_records(recordset):
    if not recordset:
        return []
    valid = []
    for value in recordset.get("records", []):
        try:
            valid.append(str(address_class(str(value).strip())))
        except ipaddress.AddressValueError:
            pass
    return clean_records(valid)


def record_body(records, ttl, description="", creating=False):
    body = {"ttl": int(ttl), "records": records}
    if creating:
        body.update({"name": domain + ".", "type": record_type})
    if description:
        body["description"] = description
    return body


def create_or_update(zone, recordset, records, ttl):
    description = "Managed by huawei-dns-guard"
    if recordset:
        description = str(recordset.get("description", "")) or description
        return api_request("PUT", f"/v2/zones/{zone['id']}/recordsets/{recordset['id']}",
                           body=record_body(records, ttl, description))
    return api_request("POST", f"/v2/zones/{zone['id']}/recordsets",
                       body=record_body(records, ttl, description, True))


def resolve_domain(name):
    family = socket.AF_INET if version == 4 else socket.AF_INET6
    try:
        values = [item[4][0] for item in socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)]
    except socket.gaierror as error:
        raise RuntimeError(f"{name} 无法解析 IPv{version}: {error}") from error
    return clean_records(values)


def state_path():
    return os.path.join(STATE_DIR, f"ddns-{TASK_ID}.json")


def load_ddns_state():
    try:
        with open(state_path(), "r", encoding="utf-8") as handle:
            value = json.load(handle)
        sources = {}
        for key, records in value.get("sources", {}).items():
            # v1 state stored a bare list under the domain name; retain it as
            # the primary cache so upgrades do not force an unnecessary lookup.
            if isinstance(records, dict):
                normalized = {}
                for side in ("primary", "backup"):
                    valid = []
                    for record in records.get(side, []):
                        try:
                            valid.append(str(address_class(str(record).strip())))
                        except ipaddress.AddressValueError:
                            pass
                    normalized[side] = valid
                blocked = records.get("blocked", {})
                normalized_blocked = {}
                for side in ("primary", "backup"):
                    valid = []
                    for record in blocked.get(side, []) if isinstance(blocked, dict) else []:
                        try:
                            valid.append(str(address_class(str(record).strip())))
                        except ipaddress.AddressValueError:
                            pass
                    normalized_blocked[side] = valid
                normalized["blocked"] = normalized_blocked
                domains = records.get("domains", {})
                normalized["domains"] = domains if isinstance(domains, dict) else {}
                sources[str(key)] = normalized
            else:
                valid = []
                for record in records if isinstance(records, list) else []:
                    try:
                        valid.append(str(address_class(str(record).strip())))
                    except ipaddress.AddressValueError:
                        pass
                sources[str(key)] = {"primary": valid, "backup": [],
                                     "blocked": {"primary": [], "backup": []}, "domains": {}}
        owned = []
        for record in value.get("owned", []):
            try:
                owned.append(str(address_class(str(record).strip())))
            except ipaddress.AddressValueError:
                pass
        active_sources = value.get("active_sources", {})
        if not isinstance(active_sources, dict):
            active_sources = {}
        return {"sources": sources, "active_sources": active_sources, "owned": owned}
    except (OSError, ValueError, TypeError):
        return {"sources": {}, "active_sources": {}, "owned": []}


def save_ddns_state(value):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=f".ddns-{TASK_ID}.", dir=STATE_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temp, state_path())
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def save_config(value):
    directory = os.path.dirname(CONFIG_PATH)
    fd, temp = tempfile.mkstemp(prefix=".config.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temp, CONFIG_PATH)
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def backup_records():
    values = []
    seen = set()
    for value in task.get("backup_ips", []):
        try:
            normalized = str(address_class(str(value).strip()))
        except ipaddress.AddressValueError:
            continue
        if normalized not in seen:
            values.append(normalized)
            seen.add(normalized)
    return values


def allocate_records(active, candidates):
    def ordered(values):
        result = []
        seen = set()
        for value in values:
            try:
                normalized = str(address_class(str(value).strip()))
            except ipaddress.AddressValueError:
                continue
            if normalized not in seen:
                result.append(normalized)
                seen.add(normalized)
        return result
    active = ordered(active)
    candidates = ordered(candidates)
    selected = active[:MAX_ACTIVE_IPS]
    selected_set = set(selected)
    for value in candidates:
        if len(selected) >= MAX_ACTIVE_IPS:
            break
        if value not in selected_set:
            selected.append(value)
            selected_set.add(value)
    overflow = active[MAX_ACTIVE_IPS:]
    overflow.extend(value for value in candidates if value not in selected_set and value not in overflow)
    return selected, overflow


def persist_backup(values):
    normalized_values = []
    seen = set()
    for value in values:
        try:
            normalized = str(address_class(str(value).strip()))
        except ipaddress.AddressValueError:
            continue
        if normalized not in seen:
            normalized_values.append(normalized)
            seen.add(normalized)
    values = normalized_values
    task["backup_ips"] = values
    for item in config.get("tasks", []):
        if item.get("id") == TASK_ID:
            item["backup_ips"] = values
            break
    save_config(config)


def sync_ddns(zone, recordset):
    configured = []
    for index, item in enumerate(task.get("ddns_domains", []), 1):
        if not isinstance(item, dict):
            item = {"id": f"legacy-{index}", "domain": item, "backup_domain": ""}
        primary = normalize_name(item.get("domain", ""))
        backup = normalize_name(item.get("backup_domain", ""))
        if primary:
            configured.append({"key": str(item.get("id") or primary), "primary": primary,
                               "backup": backup})
    state = load_ddns_state()
    sources = {}
    active_sources = {}
    errors = []
    existing_records = current_records(recordset)
    existing = set(existing_records)
    desired = []
    desired_set = set()
    resolved_now = 0
    for source in configured:
        key = source["key"]
        legacy_key = key not in state["sources"] and source["primary"] in state["sources"]
        cached = state["sources"].get(key) or state["sources"].get(source["primary"], {})
        if not isinstance(cached, dict):
            cached = {"primary": [], "backup": []}
        cached_domains = cached.get("domains", {})
        if not isinstance(cached_domains, dict):
            cached_domains = {}
        if legacy_key and not cached_domains:
            cached_domains = {"primary": source["primary"], "backup": ""}
        for side_name in ("primary", "backup"):
            if cached_domains.get(side_name) != source[side_name]:
                cached[side_name] = []
                if isinstance(cached.get("blocked"), dict):
                    cached["blocked"][side_name] = []
        cached["domains"] = {"primary": source["primary"], "backup": source["backup"]}
        blocked = cached.get("blocked", {})
        if not isinstance(blocked, dict):
            blocked = {}
        blocked_order = {}
        for side_name in ("primary", "backup"):
            blocked_order[side_name] = clean_records(blocked.get(side_name, [])) if blocked.get(side_name) else []
            # If an operator or another process restored an address, it is no
            # longer blocked and may be accepted again on the next lookup.
            blocked_order[side_name] = [value for value in blocked_order[side_name]
                                        if value not in existing]
            blocked[side_name] = set(blocked_order[side_name])
        cached["blocked"] = blocked
        side = state.get("active_sources", {}).get(key, "primary")
        if side not in ("primary", "backup") or (side == "backup" and not source["backup"]):
            side = "primary"
        domain_name = source[side]
        if not domain_name:
            side = "primary"
            domain_name = source["primary"]
        records = clean_records(cached.get(side, [])) if cached.get(side) else []

        # Cached DDNS answers are authoritative until health checks remove them.
        # Only then perform a new lookup, avoiding repeated DNS traffic each run.
        source_blocked = blocked["primary"] | blocked["backup"]
        stale_cached = bool((records and set(records) - existing) or
                            (not records and source_blocked))
        needs_lookup = not records or stale_cached
        if needs_lookup:
            old_record_values = records
            old_records = set(old_record_values)
            newly_blocked = [value for value in old_record_values
                             if value not in existing and value not in blocked[side]]
            blocked_order[side].extend(newly_blocked)
            blocked[side].update(newly_blocked)
            try:
                fresh = resolve_domain(domain_name)
                resolved_now += 1
                if fresh:
                    fresh_set = set(fresh)
                    other_side = "backup" if side == "primary" else "primary"
                    blocked_for_source = blocked[side] | blocked[other_side]
                    records = [value for value in fresh if value not in blocked_for_source]
                    cached[side] = records
                else:
                    records = []
            except RuntimeError as error:
                errors.append(str(error))
                # Keep healthy members of a partially removed answer set;
                # never delete unrelated live records just because DNS timed
                # out. Fully removed answers remain absent and can trigger
                # the paired fallback below.
                records = [value for value in old_record_values if value in existing]

            # A failed/stale primary immediately falls back to its paired
            # backup. The reverse happens when the backup later disappears.
            # Only switch sides when the just-refreshed answer did not
            # produce a replacement for a previously cached, removed answer.
            if stale_cached and (not records or
                                 (not (set(records) & existing) and not (set(records) - old_records))):
                other = "backup" if side == "primary" else "primary"
                other_domain = source[other]
                switched = False
                if other_domain:
                    other_records = clean_records(cached.get(other, [])) if cached.get(other) else []
                    newly_blocked = [value for value in other_records
                                     if value not in existing and value not in blocked[other]]
                    blocked_order[other].extend(newly_blocked)
                    blocked[other].update(newly_blocked)
                    try:
                        fallback = resolve_domain(other_domain)
                        resolved_now += 1
                        if fallback:
                            fallback_set = set(fallback)
                            usable = fallback_set - blocked[other] - blocked[side]
                            cached[other] = [value for value in fallback if value in usable]
                            if usable:
                                side = other
                                records = [value for value in fallback if value in usable]
                                switched = True
                    except RuntimeError as error:
                        errors.append(str(error))
                if not switched:
                    records = [value for value in old_record_values if value in existing]
        sources[key] = {"primary": clean_records(cached.get("primary", [])),
                        "backup": clean_records(cached.get("backup", [])),
                        "blocked": blocked_order,
                        "domains": cached["domains"]}
        active_sources[key] = side
        for value in records:
            if value not in desired_set:
                desired.append(value)
                desired_set.add(value)

    configured_backup = backup_records()
    old_owned_values = clean_records(state.get("owned", []))
    old_owned = set(old_owned_values)
    stale = old_owned - desired_set if task.get("prune_stale_ddns", True) else set()
    additions = [value for value in desired if value not in existing]
    candidate_active = [value for value in existing_records if value not in stale]
    candidate_active.extend(value for value in desired if value not in candidate_active)
    active, overflow = allocate_records(candidate_active, candidate_active + configured_backup)
    if active != existing_records:
        if active:
            create_or_update(zone, recordset, active, int(task.get("ttl", 300)))
        elif recordset:
            api_request("DELETE", f"/v2/zones/{zone['id']}/recordsets/{recordset['id']}")
    persist_backup(overflow)
    owned = [value for value in old_owned_values if value not in stale and value in desired_set]
    owned.extend(value for value in additions if value not in owned)
    save_ddns_state({"sources": sources, "active_sources": active_sources,
                     "owned": owned,
                     "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
    print(f"DDNS 同步：来源 {len(configured)} 个，本次解析 {resolved_now} 次，新增 {len(additions)}，清理旧地址 {len(stale)}，活动 {len(active)} 个，备用 {len(overflow)} 个。")
    for message in errors:
        print(f"注意：{message}；已保留该来源上次的地址。", file=sys.stderr)


def print_summary(zone, recordset):
    print(f"任务: {task.get('name')} ({TASK_ID})")
    print(f"账号: {account.get('name')} ({account.get('id')})")
    print(f"公网域名: {normalize_name(zone.get('name', ''))}")
    print(f"管理记录: {domain}  {record_type}")
    print(f"任务状态: {'启用' if task.get('enabled', True) else '停用'}")
    print(f"DDNS 来源: {len(task.get('ddns_domains', []))} 个")
    records = current_records(recordset)
    print(f"当前解析: {len(records)} 个（活动上限 {MAX_ACTIVE_IPS} 个）")
    print(f"备用解析: {len(task.get('backup_ips', []))} 个")
    for source in task.get("ddns_domains", []):
        if isinstance(source, dict):
            backup = source.get("backup_domain", "")
            print(f"  [{source.get('name', '')}] 主：{source.get('domain', '')}"
                  f"；备用：{backup or '无'}")
    if not recordset:
        print("记录状态: 尚未创建\nIP 数量: 0")
        return
    print(f"记录状态: {recordset.get('status', 'UNKNOWN')}")
    print(f"TTL: {recordset.get('ttl', task.get('ttl', 300))} 秒")
    print(f"活动 IP 数量: {len(records)}")
    for index, ip in enumerate(records, 1):
        print(f"  {index:>3}. {ip}")


def main():
    if ACTION == "ddns-check":
        values = resolve_domain(ARGS[0])
        print(f"解析类型匹配 IPv{version}，得到 {len(values)} 个地址：")
        for value in values:
            print(value)
        return
    zone = find_zone()
    recordset = find_recordset(zone["id"])
    if ACTION in ("summary", "test"):
        print_summary(zone, recordset)
    elif ACTION == "records":
        print("\n".join(current_records(recordset)))
    elif ACTION == "add":
        additions = clean_records(ARGS)
        existing = current_records(recordset)
        backup = backup_records()
        active, overflow = allocate_records(existing, existing + additions + backup)
        if active != existing:
            create_or_update(zone, recordset, active, int(task.get("ttl", 300)))
        persist_backup(overflow)
        print(f"已写入 {record_type} 记录：活动 {len(active)} 个，备用 {len(overflow)} 个。")
    elif ACTION == "remove":
        removals = set(clean_records(ARGS))
        existing = current_records(recordset)
        backup = backup_records()
        remaining = [ip for ip in existing if ip not in removals]
        backup_remaining = [ip for ip in backup if ip not in removals]
        active, overflow = allocate_records(remaining, backup_remaining)
        removed = len(existing) - len(active)
        if active != existing:
            if active:
                create_or_update(zone, recordset, active,
                                 int(recordset.get("ttl", task.get("ttl", 300))) if recordset
                                 else int(task.get("ttl", 300)))
            elif recordset:
                api_request("DELETE", f"/v2/zones/{zone['id']}/recordsets/{recordset['id']}")
        persist_backup(overflow)
        print(f"已处理删除：活动 {len(active)} 个，备用 {len(overflow)} 个。")
    elif ACTION == "rebalance":
        existing = current_records(recordset)
        backup = backup_records()
        active, overflow = allocate_records(existing, backup)
        if active != existing:
            if active:
                create_or_update(zone, recordset, active, int(task.get("ttl", 300)))
            elif recordset:
                api_request("DELETE", f"/v2/zones/{zone['id']}/recordsets/{recordset['id']}")
        persist_backup(overflow)
        print(f"解析池整理完成：活动 {len(active)} 个，备用 {len(overflow)} 个。")
    elif ACTION == "sync-ddns":
        sync_ddns(zone, recordset)
    else:
        raise RuntimeError(f"未知 DNS 操作: {ACTION}")


try:
    main()
except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
    print(f"错误：{error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

log_msg() {
    local level="$1"; shift
    local message="$*" line
    line="[$(date '+%F %T')] [${level}] ${message}"
    ensure_dirs
    printf '%s\n' "$line" >> "$LOG_FILE"
    case "$level" in
        完成) ok "$message";; 注意) warn "$message";; 错误) fail "$message";; *) info "$message";;
    esac
}

restart_daemon_if_running() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl restart "$SERVICE_NAME"
        ok "定时服务已重启并加载新配置。"
    fi
}

select_account() {
    local -a ids names
    local id name masked choice index=1
    ids=(); names=()
    menu_title "选择华为云账号"
    while IFS=$'\t' read -r id name masked; do
        [[ -n "$id" ]] || continue
        ids+=("$id"); names+=("$name")
        printf '  %d. %s | AK: %s\n' "$index" "$name" "$masked"
        ((index++))
    done < <(config_command account-list)
    ((${#ids[@]} > 0)) || { warn "尚未添加账号。"; return 1; }
    choice="$(prompt "请选择序号" "1")"
    in_range "$choice" 1 "${#ids[@]}" || { fail "无效序号。"; return 1; }
    SELECTED_ACCOUNT_ID="${ids[$((10#$choice - 1))]}"
    SELECTED_ACCOUNT_NAME="${names[$((10#$choice - 1))]}"
}

select_task() {
    local -a ids names
    local id name domain version enabled account ddns backup active choice index=1
    ids=(); names=()
    menu_title "选择任务"
    while IFS=$'\t' read -r id name domain version enabled account ddns backup; do
        [[ -n "$id" ]] || continue
        ids+=("$id"); names+=("$name")
        active="$(task_active_count "$id")"
        printf '\n  %d. %s\n' "$index" "$name"
        printf '     解析域名：%s\n' "$domain"
        printf '     记录类型：%s\n' "$version"
        printf '     绑定账号：%s\n' "$account"
        printf '     运行状态：%s\n' "$enabled"
        printf '     DDNS 来源：%s 个\n' "$ddns"
        printf '     当前解析：%s 个\n' "$active"
        printf '     备用解析：%s 个\n' "$backup"
        ((index++))
    done < <(config_command task-list)
    ((${#ids[@]} > 0)) || { warn "尚未创建任务。"; return 1; }
    choice="$(prompt "请选择序号" "1")"
    in_range "$choice" 1 "${#ids[@]}" || { fail "无效序号。"; return 1; }
    SELECTED_TASK_ID="${ids[$((10#$choice - 1))]}"
    SELECTED_TASK_NAME="${names[$((10#$choice - 1))]}"
}

add_account() {
    local id name ak sk
    name="$(trim "$(prompt "账号名称，例如 主账号")")"
    [[ -n "$name" ]] || { fail "账号名称不能为空。"; return 1; }
    ak="$(trim "$(prompt_secret "Access Key ID" 0)")"
    sk="$(trim "$(prompt_secret "Secret Access Key" 0)")"
    [[ -n "$ak" && -n "$sk" ]] || { fail "AK 和 SK 不能为空。"; return 1; }
    id="$(new_id account)"
    config_command account-add "$id" "$name" "$ak" "$sk" || return 1
    ok "已添加华为云账号：${name}（${id}）。"
}

edit_account() {
    local key value id name ak sk new_value
    select_account || return 1
    id="$SELECTED_ACCOUNT_ID"; name=""; ak=""; sk=""
    while IFS=$'\t' read -r key value; do
        case "$key" in name) name="$value";; ak) ak="$value";; sk) sk="$value";; esac
    done < <(config_command account-show "$id")
    new_value="$(trim "$(prompt "账号名称" "$name")")"; [[ -n "$new_value" ]] && name="$new_value"
    new_value="$(prompt_secret "Access Key ID" 1)"; [[ -n "$new_value" ]] && ak="$(trim "$new_value")"
    new_value="$(prompt_secret "Secret Access Key" 1)"; [[ -n "$new_value" ]] && sk="$(trim "$new_value")"
    config_command account-update "$id" "$name" "$ak" "$sk" || return 1
    ok "账号已更新。"
    restart_daemon_if_running
}

delete_account() {
    select_account || return 1
    confirm "确定删除账号 ${SELECTED_ACCOUNT_NAME}？绑定它的任务必须先删除或改绑" n || { info "已取消。"; return; }
    if config_command account-delete "$SELECTED_ACCOUNT_ID"; then
        ok "账号已删除（华为云上的 DNS 记录不会被删除）。"
        restart_daemon_if_running
    fi
}

list_accounts() {
    local id name masked found=0 index=1
    menu_title "华为云账号"
    while IFS=$'\t' read -r id name masked; do
        printf '  %d. %s | AK: %s\n' "$index" "$name" "$masked"
        found=1; ((index++))
    done < <(config_command account-list)
    ((found == 1)) || printf '暂无账号。\n'
}

account_menu() {
    local choice
    while true; do
        menu_title "华为云账号管理"
        menu_item 1 "查看账号"
        menu_item 2 "添加账号"
        menu_item 3 "修改账号名称 / AK / SK"
        menu_item 4 "删除账号"
        menu_item 5 "测试账号（选择绑定任务验证权限）"
        menu_item 0 "返回"
        choice="$(prompt "请选择" "0")"
        case "$choice" in
            1) list_accounts; pause_menu;; 2) add_account; pause_menu;;
            3) edit_account; pause_menu;; 4) delete_account; pause_menu;;
            5)
                if select_account && select_task && load_task "$SELECTED_TASK_ID"; then
                    if [[ "$ACCOUNT_ID" == "$SELECTED_ACCOUNT_ID" ]]; then
                        dns_command "$TASK_ID" test
                    else
                        fail "所选任务没有绑定这个账号，无法用它测试。"
                    fi
                fi
                pause_menu;;
            0) return;;
            *) warn "无效选项。";;
        esac
    done
}

prompt_number() {
    local label="$1" default="$2" minimum="$3" maximum="$4" value
    while true; do
        value="$(prompt "$label" "$default")"
        if in_range "$value" "$minimum" "$maximum"; then printf '%s\n' "$value"; return; fi
        fail "请输入 ${minimum}-${maximum}。"
    done
}

add_task() {
    local id name domain version ttl interval ping_count ping_timeout check_rounds round_delay max_parallel
    config_ready || { warn "请先添加华为云账号。"; return 1; }
    select_account || return 1
    name="$(trim "$(prompt "任务名称，例如 香港入口-v6")")"
    [[ -n "$name" ]] || { fail "任务名称不能为空。"; return 1; }
    while true; do
        domain="$(trim "$(prompt "要管理的完整解析域名，例如 vpn.example.com")")"
        domain="${domain%.}"
        valid_domain "$domain" && break
        fail "域名格式无效。"
    done
    while true; do
        printf '  1. IPv4（A 记录）\n'
        printf '  2. IPv6（AAAA 记录）\n'
        version="$(prompt "请选择 IP 类型" "1")"
        case "$version" in
            1) version=4; break;;
            2) version=6; break;;
            *) fail "请输入序号 1 或 2。";;
        esac
    done
    ttl="$(prompt_number "DNS TTL（秒）" "$DEFAULT_TTL" 1 2147483647)"
    interval="$(prompt_number "该任务检测/DDNS 同步间隔（秒）" "$DEFAULT_INTERVAL" 10 86400)"
    ping_count="$(prompt_number "每轮每个 IP ping 次数" "$DEFAULT_PING_COUNT" 1 10)"
    check_rounds="$(prompt_number "连续检测轮数" "$DEFAULT_CHECK_ROUNDS" 1 10)"
    ping_timeout="$(prompt_number "单次 ping 超时（秒）" "$DEFAULT_PING_TIMEOUT" 1 30)"
    round_delay="$(prompt_number "失败轮次等待（秒）" "$DEFAULT_ROUND_DELAY" 0 60)"
    max_parallel="$(prompt_number "最大并发检测数" "$DEFAULT_MAX_PARALLEL" 1 100)"
    id="$(new_id task)"
    config_command task-add "$id" "$name" "$SELECTED_ACCOUNT_ID" "${domain,,}" "$version" \
        "$ttl" "$interval" "$ping_count" "$ping_timeout" "$check_rounds" "$round_delay" "$max_parallel" || return 1
    ok "任务已创建：${name}（${id}，IPv${version}）。"
    info "正在验证账号权限和域名..."
    if dns_command "$id" test; then
        ok "华为云 DNS 连接正常。"
    else
        warn "任务已保存，但连接测试失败；可修改账号或任务后重试。"
    fi
    restart_daemon_if_running
}

list_tasks() {
    local id name domain version enabled account ddns backup active found=0 index=1
    menu_title "DNS 任务"
    while IFS=$'\t' read -r id name domain version enabled account ddns backup; do
        active="$(task_active_count "$id")"
        printf '\n  %d. %s\n' "$index" "$name"
        printf '     解析域名：%s\n' "$domain"
        printf '     记录类型：%s\n' "$version"
        printf '     绑定账号：%s\n' "$account"
        printf '     运行状态：%s\n' "$enabled"
        printf '     DDNS 来源：%s 个\n' "$ddns"
        printf '     当前解析：%s 个\n' "$active"
        printf '     备用解析：%s 个\n' "$backup"
        found=1; ((index++))
    done < <(config_command task-list)
    ((found == 1)) || printf '暂无任务。\n'
}

collect_ips() {
    local version="$1" line existing ip
    INPUT_IPS=()
    printf '请输入 IPv%s，一行一个；空行或单独一行 . 结束：\n' "$version"
    while IFS= read -r line; do
        line="$(trim "${line//$'\r'/}")"
        [[ -n "$line" && "$line" != "." ]] || break
        if ! valid_ip_for_version "$line" "$version"; then
            warn "已跳过无效或类型不匹配的地址：$line"; continue
        fi
        existing=0
        for ip in "${INPUT_IPS[@]}"; do [[ "$ip" == "$line" ]] && existing=1; done
        ((existing == 1)) || INPUT_IPS+=("$line")
    done
    ((${#INPUT_IPS[@]} > 0)) || { warn "没有输入有效 IP。"; return 1; }
}

task_add_ips() {
    load_task "$1" || return 1
    collect_ips "$IP_VERSION" || return 1
    info "正在向 ${DOMAIN} 的 ${RECORD_TYPE} 记录添加 ${#INPUT_IPS[@]} 个地址..."
    dns_command "$TASK_ID" add "${INPUT_IPS[@]}" && ok "IP 添加完成。"
}

list_backup_ips() {
    local task_id="$1" ip found=0 index=1
    menu_title "备用解析 IP"
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        printf '  %d. %s\n' "$index" "$ip"
        found=1; ((index++))
    done < <(config_command backup-list "$task_id")
    ((found == 1)) || printf '  暂无备用 IP。\n'
}

backup_add_ips() {
    local task_id="$1" line ip
    load_task "$task_id" || return 1
    printf '请输入备用 IPv%s，一行一个；空行或单独一行 . 结束：\n' "$IP_VERSION"
    local -a values=()
    while IFS= read -r line; do
        line="$(trim "${line//$'\r'/}")"
        [[ -n "$line" && "$line" != "." ]] || break
        if valid_ip_for_version "$line" "$IP_VERSION"; then
            values+=("$line")
        else
            warn "已跳过无效或类型不匹配的地址：$line"
        fi
    done
    ((${#values[@]} > 0)) || { warn "没有输入有效备用 IP。"; return 1; }
    config_command backup-add "$task_id" "${values[@]}" || return 1
    if dns_command "$TASK_ID" rebalance >/dev/null 2>&1; then
        ok "备用 IP 已添加，并已自动补入活动解析（上限 ${MAX_ACTIVE_IPS} 个）。"
    else
        warn "备用 IP 已添加；本次云端补位失败，将在下次任务检查时重试。"
    fi
}

backup_remove_ips() {
    local task_id="$1" line ip
    load_task "$task_id" || return 1
    printf '请输入要删除的备用 IPv%s，一行一个；空行或单独一行 . 结束：\n' "$IP_VERSION"
    local -a values=()
    while IFS= read -r line; do
        line="$(trim "${line//$'\r'/}")"
        [[ -n "$line" && "$line" != "." ]] || break
        valid_ip_for_version "$line" "$IP_VERSION" && values+=("$line") || warn "已跳过无效地址：$line"
    done
    ((${#values[@]} > 0)) || { warn "没有输入有效 IP。"; return 1; }
    config_command backup-remove "$task_id" "${values[@]}" || return 1
    ok "备用 IP 已删除。"
}

backup_remove_all_ips() {
    local task_id="$1"
    load_task "$task_id" || return 1
    [[ "$BACKUP_COUNT" =~ ^[1-9][0-9]*$ ]] || { warn "该任务没有备用 IP。"; return 0; }
    confirm "确定一键删除该任务的全部 ${BACKUP_COUNT} 个备用 IP" n || { info "已取消。"; return 0; }
    config_command backup-clear "$TASK_ID" || return 1
    ok "已删除全部备用 IP。"
}

backup_menu() {
    local task_id="$1" choice
    while true; do
        load_task "$task_id" || return 1
        menu_title "备用解析 IP"
        printf '  任务名称: %s\n' "$TASK_NAME"
        printf '  活动解析上限: %s 个\n' "$MAX_ACTIVE_IPS"
        printf '  当前备用数量: %s 个\n\n' "$BACKUP_COUNT"
        menu_item 1 "查看备用 IP"
        menu_item 2 "添加备用 IP"
        menu_item 3 "删除备用 IP"
        menu_item 4 "一键删除全部备用 IP"
        menu_item 0 "返回"
        choice="$(prompt "请选择" "0")"
        case "$choice" in
            1) list_backup_ips "$task_id"; pause_menu;;
            2) backup_add_ips "$task_id"; pause_menu;;
            3) backup_remove_ips "$task_id"; pause_menu;;
            4) backup_remove_all_ips "$task_id"; pause_menu;;
            0) return;; *) warn "无效选项。";;
        esac
    done
}

task_remove_ips() {
    load_task "$1" || return 1
    collect_ips "$IP_VERSION" || return 1
    confirm "确定从 ${DOMAIN} 的 ${RECORD_TYPE} 记录删除这些 IP" n || { info "已取消。"; return; }
    dns_command "$TASK_ID" remove "${INPUT_IPS[@]}" && ok "IP 删除完成。"
}

task_remove_all_ips() {
    local task_id="$1" ip active records_output
    local -a values=()
    load_task "$task_id" || return 1
    records_output="$(dns_command "$TASK_ID" records)" || { fail "读取活动解析 IP 失败。"; return 1; }
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && values+=("$ip")
    done <<< "$records_output"
    active="${#values[@]}"
    ((active > 0)) || { warn "该任务没有活动解析 IP。"; return 0; }
    confirm "确定一键删除 ${DOMAIN} 的全部 ${active} 个活动解析 IP？有备用 IP 时会自动补位" n || { info "已取消。"; return 0; }
    dns_command "$TASK_ID" remove "${values[@]}" && ok "已处理全部活动解析 IP；备用 IP 已按上限自动补位。"
}

task_show_records() {
    load_task "$1" || return 1
    printf '\n'
    dns_command "$TASK_ID" summary
}

ddns_add() {
    local task_id="$1" id name domain backup_domain
    load_task "$task_id" || return 1
    name="$(trim "$(prompt "DDNS 名称，例如 家里宽带")")"
    [[ -n "$name" ]] || { fail "DDNS 名称不能为空。"; return 1; }
    while true; do
        domain="$(trim "$(prompt "DDNS 完整域名")")"; domain="${domain%.}"
        valid_domain "$domain" && break
        fail "域名格式无效。"
    done
    info "正在确认 ${domain} 可解析出 IPv${IP_VERSION} 地址..."
    if ! dns_command "$TASK_ID" ddns-check "${domain,,}"; then
        fail "DDNS 域名类型与任务 IPv${IP_VERSION} 不匹配，未添加。"
        return 1
    fi
    while true; do
        backup_domain="$(trim "$(prompt "备用 DDNS 完整域名（可留空）")")"
        backup_domain="${backup_domain%.}"
        [[ -z "$backup_domain" ]] && break
        [[ "$backup_domain" != "$domain" ]] && valid_domain "$backup_domain" && break
        fail "备用域名格式无效，且不能与主域名相同。"
    done
    if [[ -n "$backup_domain" ]]; then
        info "正在确认备用 ${backup_domain} 可解析出 IPv${IP_VERSION} 地址..."
        dns_command "$TASK_ID" ddns-check "${backup_domain,,}" || {
            fail "备用 DDNS 域名类型与任务 IPv${IP_VERSION} 不匹配，未添加。"
            return 1
        }
    fi
    id="$(new_id ddns)"
    config_command ddns-add "$TASK_ID" "$id" "$name" "${domain,,}" "${backup_domain,,}" || return 1
    ok "DDNS 来源已添加：${name}（${domain,,}，备用：${backup_domain:-无}）。"
    dns_command "$TASK_ID" sync-ddns || warn "已绑定，但本次同步失败。"
}

list_ddns() {
    local task_id="$1" id name domain backup_domain found=0 index=1
    menu_title "DDNS 来源"
    while IFS=$'\t' read -r id name domain backup_domain; do
        [[ -n "$id" ]] || continue
        printf '  %d. %s | 主：%s | 备用：%s\n' "$index" "$name" "$domain" "${backup_domain:-无}"
        found=1; ((index++))
    done < <(config_command ddns-list "$task_id")
    ((found == 1)) || printf '  暂无 DDNS 来源。\n'
}

ddns_edit() {
    local task_id="$1"
    local -a ids names domains backups
    local id name domain backup_domain choice new_name new_domain new_backup index=1
    ids=(); names=(); domains=(); backups=()
    menu_title "选择要修改的 DDNS 来源"
    while IFS=$'\t' read -r id name domain backup_domain; do
        [[ -n "$id" ]] || continue
        ids+=("$id"); names+=("$name"); domains+=("$domain"); backups+=("$backup_domain")
        printf '  %d. %s | 主：%s | 备用：%s\n' "$index" "$name" "$domain" "${backup_domain:-无}"; ((index++))
    done < <(config_command ddns-list "$task_id")
    ((${#ids[@]} > 0)) || { warn "该任务没有 DDNS 来源。"; return 1; }
    choice="$(prompt "要修改的序号")"
    in_range "$choice" 1 "${#ids[@]}" || { fail "无效序号。"; return 1; }
    id="${ids[$((10#$choice - 1))]}"
    name="${names[$((10#$choice - 1))]}"
    domain="${domains[$((10#$choice - 1))]}"
    backup_domain="${backups[$((10#$choice - 1))]}"
    new_name="$(trim "$(prompt "DDNS 名称" "$name")")"
    [[ -n "$new_name" ]] || { fail "DDNS 名称不能为空。"; return 1; }
    while true; do
        new_domain="$(trim "$(prompt "DDNS 完整域名" "$domain")")"
        new_domain="${new_domain%.}"
        valid_domain "$new_domain" && break
        fail "域名格式无效。"
    done
    while true; do
        new_backup="$(trim "$(prompt "备用 DDNS 完整域名（可留空）" "$backup_domain")")"
        new_backup="${new_backup%.}"
        [[ -z "$new_backup" ]] && break
        [[ "$new_backup" != "$new_domain" ]] && valid_domain "$new_backup" && break
        fail "备用域名格式无效，且不能与主域名相同。"
    done
    info "正在确认 ${new_domain} 可解析出 IPv${IP_VERSION} 地址..."
    dns_command "$TASK_ID" ddns-check "${new_domain,,}" || {
        fail "DDNS 域名类型与任务 IPv${IP_VERSION} 不匹配，未修改。"
        return 1
    }
    if [[ -n "$new_backup" ]]; then
        info "正在确认备用 ${new_backup} 可解析出 IPv${IP_VERSION} 地址..."
        dns_command "$TASK_ID" ddns-check "${new_backup,,}" || {
            fail "备用 DDNS 域名类型与任务 IPv${IP_VERSION} 不匹配，未修改。"
            return 1
        }
    fi
    config_command ddns-update "$task_id" "$id" "$new_name" "${new_domain,,}" "${new_backup,,}" || return 1
    ok "DDNS 来源已更新。"
    dns_command "$task_id" sync-ddns || warn "配置已更新，但本次同步失败。"
}

ddns_remove() {
    local task_id="$1"
    local -a ids names domains backups
    local id name domain backup_domain choice index=1
    ids=(); names=(); domains=(); backups=()
    menu_title "选择要删除的 DDNS 来源"
    while IFS=$'\t' read -r id name domain backup_domain; do
        [[ -n "$id" ]] || continue
        ids+=("$id"); names+=("$name"); domains+=("$domain"); backups+=("$backup_domain")
        printf '  %d. %s | 主：%s | 备用：%s\n' "$index" "$name" "$domain" "${backup_domain:-无}"; ((index++))
    done < <(config_command ddns-list "$task_id")
    ((${#ids[@]} > 0)) || { warn "该任务没有 DDNS 来源。"; return 1; }
    choice="$(prompt "要删除的序号")"
    in_range "$choice" 1 "${#ids[@]}" || { fail "无效序号。"; return 1; }
    id="${ids[$((10#$choice - 1))]}"
    name="${names[$((10#$choice - 1))]}"
    domain="${domains[$((10#$choice - 1))]}"
    confirm "确定删除 DDNS 来源 ${name}（${domain}）？已同步 IP 会按所有权清理" n || return 0
    config_command ddns-remove "$task_id" "$id" || return 1
    ok "DDNS 来源已删除。"
    dns_command "$task_id" sync-ddns || warn "配置已删除，但旧地址清理失败，将在下次同步重试。"
}

ddns_remove_all() {
    local task_id="$1"
    load_task "$task_id" || return 1
    [[ "$DDNS_COUNT" =~ ^[1-9][0-9]*$ ]] || { warn "该任务没有 DDNS 来源。"; return 0; }
    confirm "确定一键删除该任务的全部 ${DDNS_COUNT} 个 DDNS 来源？已同步 IP 会按所有权清理" n || { info "已取消。"; return 0; }
    config_command ddns-clear "$TASK_ID" || return 1
    ok "已删除全部 DDNS 来源。"
    dns_command "$TASK_ID" sync-ddns || warn "配置已删除，但旧地址清理失败，将在下次同步重试。"
}

ddns_menu() {
    local task_id="$1" choice
    while true; do
        load_task "$task_id" || return 1
        menu_title "DDNS 来源管理"
        printf '  任务名称: %s\n' "$TASK_NAME"
        printf '  任务类型: IPv%s / %s\n' "$IP_VERSION" "$RECORD_TYPE"
        printf '  来源数量: %s\n\n' "$DDNS_COUNT"
        menu_item 1 "查看 DDNS 来源"
        menu_item 2 "添加 DDNS 来源"
        menu_item 3 "修改 DDNS 来源名称 / 域名"
        menu_item 4 "删除 DDNS 来源"
        menu_item 5 "立即解析并同步"
        menu_item 6 "一键删除全部 DDNS 来源"
        menu_item 0 "返回"
        choice="$(prompt "请选择" "0")"
        case "$choice" in
            1) list_ddns "$task_id"; pause_menu;; 2) ddns_add "$task_id"; pause_menu;;
            3) ddns_edit "$task_id"; pause_menu;; 4) ddns_remove "$task_id"; pause_menu;;
            5) dns_command "$task_id" sync-ddns; pause_menu;;
            6) ddns_remove_all "$task_id"; pause_menu;;
            0) return;; *) warn "无效选项。";;
        esac
    done
}

edit_task_settings() {
    local task_id="$1" choice value
    while true; do
        load_task "$task_id" || return 1
        menu_title "任务设置"
        printf '  当前任务: %s\n' "$TASK_NAME"
        printf '  当前账号: %s\n' "$ACCOUNT_NAME"
        printf '  当前记录: %s (%s / IPv%s)\n\n' "$DOMAIN" "$RECORD_TYPE" "$IP_VERSION"
        menu_item 1 "修改任务名称（当前：${TASK_NAME}）"
        menu_item 2 "修改绑定账号（当前：${ACCOUNT_NAME}）"
        menu_item 3 "修改记录域名（当前：${DOMAIN}）"
        menu_item 4 "修改 IP 类型（当前：IPv${IP_VERSION}）"
        menu_item 5 "修改 TTL（当前：${TTL} 秒）"
        menu_item 6 "修改执行间隔（当前：${INTERVAL} 秒）"
        menu_item 7 "修改每轮 ping 次数（当前：${PING_COUNT}）"
        menu_item 8 "修改检测轮数（当前：${CHECK_ROUNDS}）"
        menu_item 9 "修改 ping 超时（当前：${PING_TIMEOUT} 秒）"
        menu_item 10 "修改轮次等待（当前：${ROUND_DELAY} 秒）"
        menu_item 11 "修改最大并发（当前：${MAX_PARALLEL}）"
        menu_item 12 "切换健康删除（当前：$([[ "$HEALTH_ENABLED" == 1 ]] && printf '开启' || printf '关闭')）"
        menu_item 13 "切换旧 DDNS 地址清理（当前：$([[ "$PRUNE_STALE_DDNS" == 1 ]] && printf '开启' || printf '关闭')）"
        menu_item 0 "返回"
        choice="$(prompt "请选择设置项" "0")"
        case "$choice" in
            1) value="$(trim "$(prompt "新任务名称" "$TASK_NAME")")"; [[ -n "$value" ]] && config_command task-set "$task_id" name "$value" || fail "任务名称不能为空或保存失败。";;
            2) if select_account; then config_command task-set "$task_id" account_id "$SELECTED_ACCOUNT_ID" || fail "绑定账号保存失败。"; fi;;
            3) value="$(trim "$(prompt "新完整域名" "$DOMAIN")")"; if valid_domain "$value"; then config_command task-set "$task_id" domain "$value" || fail "域名保存失败。"; else fail "域名无效。"; fi;;
            4)
                if ((DDNS_COUNT > 0)); then
                    fail "请先在 DDNS 域名管理中解除全部绑定，再切换 IP 类型。"
                else
                    printf '  1. IPv4（A 记录）\n'
                    printf '  2. IPv6（AAAA 记录）\n'
                    value="$(prompt "请选择 IP 类型" "$([[ "$IP_VERSION" == 4 ]] && printf 1 || printf 2)")"
                    case "$value" in
                        1) config_command task-set "$task_id" ip_version 4 || fail "IPv4 类型保存失败。";;
                        2) config_command task-set "$task_id" ip_version 6 || fail "IPv6 类型保存失败。";;
                        *) fail "请输入序号 1 或 2。";;
                    esac
                fi;;
            5) value="$(prompt_number "TTL" "$TTL" 1 2147483647)"; config_command task-set "$task_id" ttl "$value" || fail "TTL 保存失败。";;
            6) value="$(prompt_number "间隔" "$INTERVAL" 10 86400)"; config_command task-set "$task_id" interval "$value" || fail "间隔保存失败。";;
            7) value="$(prompt_number "ping 次数" "$PING_COUNT" 1 10)"; config_command task-set "$task_id" ping_count "$value" || fail "ping 次数保存失败。";;
            8) value="$(prompt_number "检测轮数" "$CHECK_ROUNDS" 1 10)"; config_command task-set "$task_id" check_rounds "$value" || fail "检测轮数保存失败。";;
            9) value="$(prompt_number "ping 超时" "$PING_TIMEOUT" 1 30)"; config_command task-set "$task_id" ping_timeout "$value" || fail "ping 超时保存失败。";;
            10) value="$(prompt_number "轮次等待" "$ROUND_DELAY" 0 60)"; config_command task-set "$task_id" round_delay "$value" || fail "轮次等待保存失败。";;
            11) value="$(prompt_number "最大并发" "$MAX_PARALLEL" 1 100)"; config_command task-set "$task_id" max_parallel "$value" || fail "最大并发保存失败。";;
            12) config_command task-set "$task_id" health_enabled "$([[ "$HEALTH_ENABLED" == 1 ]] && printf 0 || printf 1)" || fail "健康删除设置保存失败。";;
            13) config_command task-set "$task_id" prune_stale_ddns "$([[ "$PRUNE_STALE_DDNS" == 1 ]] && printf 0 || printf 1)" || fail "DDNS 清理设置保存失败。";;
            0) restart_daemon_if_running; return;; *) warn "无效选项。";;
        esac
        ok "任务设置已更新。"
    done
}

check_one_ip() {
    local ip="$1" result_file="$2" version="$3" round=1 attempt
    while ((round <= CHECK_ROUNDS)); do
        attempt=1
        while ((attempt <= PING_COUNT)); do
            if ping "-${version}" -n -c 1 -W "$PING_TIMEOUT" "$ip" >/dev/null 2>&1; then
                printf 'up %s %s\n' "$round" "$attempt" > "$result_file"; return 0
            fi
            ((attempt++))
        done
        ((round < CHECK_ROUNDS && ROUND_DELAY > 0)) && sleep "$ROUND_DELAY"
        ((round++))
    done
    printf 'down\n' > "$result_file"
    return 1
}

check_task() (
    local task_id="$1" records_output ip index running pid result temp_dir
    local -a ips pids failed
    load_task "$task_id" || exit 1
    command -v ping >/dev/null 2>&1 || { fail "缺少 ping 命令。"; exit 1; }
    command -v flock >/dev/null 2>&1 || { fail "缺少 flock 命令（util-linux）。"; exit 1; }
    ensure_dirs
    exec 9>"${STATE_DIR}/check-${TASK_ID}.lock"
    if ! flock -n 9; then warn "任务 ${TASK_NAME} 已在运行，本次跳过。"; exit 0; fi

    if ((DDNS_COUNT > 0)); then
        if ! dns_command "$TASK_ID" sync-ddns; then
            log_msg "错误" "[${TASK_NAME}] DDNS 同步失败，继续检查现有记录。"
        fi
    fi
    if [[ "$HEALTH_ENABLED" != 1 ]]; then
        dns_command "$TASK_ID" rebalance || log_msg "注意" "[${TASK_NAME}] 备用解析补位失败。"
        log_msg "完成" "[${TASK_NAME}] DDNS 同步完成；健康删除已关闭。"; exit 0
    fi
    records_output="$(dns_command "$TASK_ID" records)" || { log_msg "错误" "[${TASK_NAME}] 读取 DNS 记录失败。"; exit 1; }
    ips=()
    while IFS= read -r ip; do [[ -n "$ip" ]] && ips+=("$ip"); done <<< "$records_output"
    if ((${#ips[@]} == 0)); then
        dns_command "$TASK_ID" rebalance || log_msg "注意" "[${TASK_NAME}] 空记录补位失败。"
        log_msg "注意" "[${TASK_NAME}] ${DOMAIN} 没有 ${RECORD_TYPE} 地址。"
        exit 0
    fi

    log_msg "信息" "[${TASK_NAME}] 开始检测 ${#ips[@]} 个 IPv${IP_VERSION} 地址。"
    temp_dir="$(mktemp -d "${STATE_DIR}/check-${TASK_ID}.XXXXXX")"
    pids=(); running=0; index=0
    for ip in "${ips[@]}"; do
        check_one_ip "$ip" "${temp_dir}/${index}" "$IP_VERSION" & pids+=("$!")
        ((running++)); ((index++))
        if ((running >= MAX_PARALLEL)); then
            for pid in "${pids[@]}"; do wait "$pid" || true; done
            pids=(); running=0
        fi
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done
    failed=(); index=0
    for ip in "${ips[@]}"; do
        result="$(<"${temp_dir}/${index}")"
        if [[ "$result" == up* ]]; then
            log_msg "完成" "[${TASK_NAME}] ${ip} 可达，保留。"
        else
            failed+=("$ip"); log_msg "注意" "[${TASK_NAME}] ${ip} 连续检测失败。"
        fi
        ((index++))
    done
    rm -rf -- "$temp_dir"
    ((${#failed[@]} > 0)) || {
        dns_command "$TASK_ID" rebalance || log_msg "注意" "[${TASK_NAME}] 活动解析整理失败。"
        log_msg "完成" "[${TASK_NAME}] 全部地址可达。"; exit 0
    }
    if ((${#failed[@]} == ${#ips[@]})); then
        log_msg "注意" "[${TASK_NAME}] 所有地址连续检测失败，将全部删除；下一轮将重新同步 DDNS 或补入备用 IP。"
    fi
    if dns_command "$TASK_ID" remove "${failed[@]}"; then
        log_msg "完成" "[${TASK_NAME}] 已删除 ${#failed[@]} 个失效地址。"
    else
        log_msg "错误" "[${TASK_NAME}] 更新 DNS 失败，下轮重试。"; exit 1
    fi
    dns_command "$TASK_ID" rebalance || log_msg "注意" "[${TASK_NAME}] 删除后备用解析补位失败。"
)

check_all_tasks() {
    local id _ found=0 status=0
    while IFS=$'\t' read -r id _; do
        [[ -n "$id" ]] || continue
        found=1; check_task "$id" || status=1
    done < <(config_command task-list)
    ((found == 1)) || { warn "没有可检测的任务。"; return 1; }
    return "$status"
}

delete_task() {
    local task_id="$1"
    load_task "$task_id" || return 1
    confirm "确定删除任务 ${TASK_NAME}？不会删除华为云 DNS 记录" n || return 0
    config_command task-delete "$task_id" || return 1
    rm -f -- "${STATE_DIR}/ddns-${task_id}.json" "${STATE_DIR}/last-${task_id}"
    ok "任务已删除，云端 DNS 记录已保留。"
    restart_daemon_if_running
}

task_detail_menu() {
    local task_id="$1" choice active
    while true; do
        load_task "$task_id" || return
        # 打开任务时顺手补齐活动解析，备用池为空或云端暂不可用均静默跳过。
        if [[ "$BACKUP_COUNT" =~ ^[1-9][0-9]*$ ]]; then
            active="$(task_active_count "$TASK_ID")"
            if [[ "$active" =~ ^[0-9]+$ ]] && ((active < MAX_ACTIVE_IPS)); then
                dns_command "$TASK_ID" rebalance >/dev/null 2>&1 || true
                load_task "$task_id" || return
            fi
        fi
        menu_title "任务管理"
        printf '  任务名称: %s\n' "$TASK_NAME"
        printf '  解析记录: %s\n' "$DOMAIN"
        printf '  记录类型: %s / IPv%s\n' "$RECORD_TYPE" "$IP_VERSION"
        printf '  华为账号: %s\n' "$ACCOUNT_NAME"
        printf '  任务状态: %s\n' "$([[ "$ENABLED" == 1 ]] && printf '启用' || printf '停用')"
        printf '  执行间隔: %s 秒\n' "$INTERVAL"
        printf '  DDNS 来源: %s 个\n' "$DDNS_COUNT"
        active="$(task_active_count "$TASK_ID")"
        printf '  当前解析: %s 个\n' "$active"
        printf '  备用解析: %s 个\n\n' "$BACKUP_COUNT"
        menu_item 1 "查看解析记录"
        menu_item 2 "添加活动解析 IP"
        menu_item 3 "删除活动解析 IP"
        menu_item 4 "立即检测 / 同步一轮"
        menu_item 5 "DDNS 来源管理"
        menu_item 6 "备用解析 IP 管理"
        menu_item 7 "修改任务设置"
        menu_item 8 "$([[ "$ENABLED" == 1 ]] && printf '停用任务' || printf '启用任务')"
        menu_item 9 "测试账号与域名"
        menu_item 10 "删除任务"
        menu_item 11 "一键删除全部活动解析 IP"
        menu_item 0 "返回"
        choice="$(prompt "请选择" "0")"
        case "$choice" in
            1) task_show_records "$task_id"; pause_menu;; 2) task_add_ips "$task_id"; pause_menu;;
            3) task_remove_ips "$task_id"; pause_menu;; 4) check_task "$task_id"; pause_menu;;
            5) ddns_menu "$task_id";; 6) backup_menu "$task_id";; 7) edit_task_settings "$task_id";;
            8) config_command task-set "$task_id" enabled "$([[ "$ENABLED" == 1 ]] && printf 0 || printf 1)"; restart_daemon_if_running;;
            9) dns_command "$task_id" test; pause_menu;; 10) delete_task "$task_id"; return;;
            11) task_remove_all_ips "$task_id"; pause_menu;;
            0) return;; *) warn "无效选项。";;
        esac
    done
}

task_menu() {
    local choice
    while true; do
        menu_title "DNS 任务管理"
        menu_item 1 "任务总览"
        menu_item 2 "新建 IPv4 / IPv6 任务"
        menu_item 3 "选择任务进行管理"
        menu_item 0 "返回"
        choice="$(prompt "请选择" "0")"
        case "$choice" in
            1) list_tasks; pause_menu;; 2) add_task; pause_menu;;
            3) select_task && task_detail_menu "$SELECTED_TASK_ID";; 0) return;; *) warn "无效选项。";;
        esac
    done
}

install_dependencies() {
    local packages=()
    command -v python3 >/dev/null 2>&1 || packages+=(python3)
    command -v ping >/dev/null 2>&1 || packages+=(iputils-ping)
    command -v flock >/dev/null 2>&1 || packages+=(util-linux)
    command -v curl >/dev/null 2>&1 || packages+=(curl)
    ((${#packages[@]} == 0)) && return 0
    info "正在安装依赖：${packages[*]}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ca-certificates python3 iputils util-linux curl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y ca-certificates python3 iputils util-linux curl
    else
        fail "请手动安装 python3、iputils、util-linux、curl、ca-certificates。"; return 1
    fi
}

install_service() {
    config_ready || { fail "请先添加账号和至少一个任务。"; return 1; }
    [[ "$(config_command task-count)" -gt 0 ]] || { fail "请先创建任务。"; return 1; }
    install_dependencies || return 1
    command -v systemctl >/dev/null 2>&1 || { fail "当前系统没有 systemd。"; return 1; }
    ensure_dirs
    if [[ -f "$SELF_PATH" ]]; then
        if [[ "$(readlink -f "$SELF_PATH" 2>/dev/null || printf '%s' "$SELF_PATH")" != "$(readlink -f "$BIN_PATH" 2>/dev/null || printf '%s' "$BIN_PATH")" ]]; then
            install -m 755 "$SELF_PATH" "$BIN_PATH"
        else
            chmod 755 "$BIN_PATH"
        fi
    else
        local downloaded_script
        downloaded_script="$(mktemp "${STATE_DIR}/script.XXXXXX")"
        curl -fL --retry 3 --connect-timeout 10 "$SCRIPT_URL" -o "$downloaded_script" || { rm -f -- "$downloaded_script"; return 1; }
        grep -q 'Huawei Cloud DNS IP guard' "$downloaded_script" || { rm -f -- "$downloaded_script"; fail "下载内容不是本脚本。"; return 1; }
        install -m 755 "$downloaded_script" "$BIN_PATH"; rm -f -- "$downloaded_script"
    fi
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Huawei Cloud DNS multi-task IP health guard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} --daemon
Restart=always
RestartSec=10
User=root
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    ok "多任务定时服务已启动，每个任务按自己的间隔独立调度。"
}

update_script() {
    local downloaded_script
    install_dependencies || return 1; ensure_dirs
    downloaded_script="$(mktemp "${STATE_DIR}/update.XXXXXX")"
    if ! curl -fL --retry 3 --connect-timeout 10 "$SCRIPT_URL" -o "$downloaded_script"; then
        rm -f -- "$downloaded_script"; fail "下载更新失败：${SCRIPT_URL}"; return 1
    fi
    grep -q 'Huawei Cloud DNS IP guard' "$downloaded_script" || { rm -f -- "$downloaded_script"; fail "下载内容无效。"; return 1; }
    install -m 755 "$downloaded_script" "$BIN_PATH"; rm -f -- "$downloaded_script"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl restart "$SERVICE_NAME"; ok "脚本已更新，服务已重启。"
    else
        ok "脚本已更新到 ${BIN_PATH}。"
    fi
    exec "$BIN_PATH"
}

stop_service() {
    command -v systemctl >/dev/null 2>&1 || { fail "当前系统没有 systemd。"; return 1; }
    systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
    ok "定时服务已停止，配置和 DNS 记录均保留。"
}

service_state() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME"; then
        printf '%s运行中%s' "$GREEN" "$RESET"
    else
        printf '%s未运行%s' "$YELLOW" "$RESET"
    fi
}

show_logs() {
    ensure_dirs
    printf '\n最近 200 条日志：\n\n'
    [[ -s "$LOG_FILE" ]] && tail -n 200 "$LOG_FILE" || printf '暂无日志。\n'
}

show_menu_header() {
    local account_count=0 task_count=0 ignored
    while IFS=$'\t' read -r ignored _; do [[ -n "$ignored" ]] && ((account_count++)); done < <(config_command account-list)
    task_count="$(config_command task-count)"
    printf '\n%s%s华为云 DNS 管理%s\n' "$BOLD" "$CYAN" "$RESET"
    printf '%s\n' '============================================================'
    printf '  华为账号: %s 个\n' "$account_count"
    printf '  DNS 任务: %s 个\n' "$task_count"
    printf '  定时服务: '; service_state; printf '\n'
    printf '%s\n' '------------------------------------------------------------'
}

main_menu() {
    local choice
    while true; do
        show_menu_header
        menu_item 1 "华为云账号管理"
        menu_item 2 "DNS 任务管理"
        menu_item 3 "立即运行全部任务"
        menu_item 4 "启动 / 更新定时服务"
        menu_item 5 "停止定时服务"
        menu_item 6 "查看运行日志"
        menu_item 7 "更新脚本"
        menu_item 0 "退出"
        choice="$(prompt "请选择" "0")"
        case "$choice" in
            1) account_menu;; 2) task_menu;; 3) check_all_tasks; pause_menu;;
            4) install_service; pause_menu;; 5) stop_service; pause_menu;;
            6) show_logs; pause_menu;; 7) update_script; pause_menu;; 0) exit 0;; *) warn "无效选项。";;
        esac
    done
}

daemon_main() {
    local id interval now last last_file
    ensure_dirs
    while true; do
        now="$(date +%s)"
        while IFS=$'\t' read -r id interval; do
            [[ -n "$id" ]] || continue
            in_range "$interval" 10 86400 || interval="$DEFAULT_INTERVAL"
            last_file="${STATE_DIR}/last-${id}"; last=0
            [[ -f "$last_file" ]] && IFS= read -r last < "$last_file"
            is_uint "$last" || last=0
            if ((now - last >= interval)); then
                printf '%s\n' "$now" > "$last_file"
                check_task "$id" &
            fi
        done < <(config_command enabled-runtime)
        sleep 5
    done
}

extract_task_option() {
    CLI_TASK_ID=""; CLI_ARGS=()
    while (($#)); do
        case "$1" in
            --task)
                (($# >= 2)) || { fail "--task 后缺少任务 ID。"; return 1; }
                CLI_TASK_ID="$2"; shift 2;;
            *) CLI_ARGS+=("$1"); shift;;
        esac
    done
}

show_help() {
    cat <<'EOF'
用法：
  sudo bash huwei.sh                         打开管理菜单
  sudo bash huwei.sh --accounts              查看华为云账号（密钥脱敏）
  sudo bash huwei.sh --tasks                 查看任务及任务 ID
  sudo bash huwei.sh --list --task ID        查看任务的 A/AAAA 记录
  sudo bash huwei.sh --add IP... --task ID   添加 IPv4/IPv6 地址
  sudo bash huwei.sh --remove IP... --task ID 删除地址
  sudo bash huwei.sh --backup-list --task ID 查看备用 IP
  sudo bash huwei.sh --backup-add IP... --task ID 添加备用 IP
  sudo bash huwei.sh --backup-remove IP... --task ID 删除备用 IP
  sudo bash huwei.sh --check [--task ID]     检测指定任务或全部任务
  sudo bash huwei.sh --ddns-sync --task ID   立即同步任务的 DDNS 来源
  sudo bash huwei.sh --start | --stop        启停多任务定时服务

--task 可填写任务 ID，也可填写任务名称。
只有一个任务时，--list/--add/--remove 可省略 --task。
EOF
}

main() {
    local local_action cli_ip
    case "${1:-}" in -h|--help) show_help; exit 0;; esac
    require_root
    install_dependencies || exit 1
    require_python || exit 1
    ensure_dirs
    migrate_config || { fail "配置迁移或校验失败，请检查 ${CONFIG_FILE}。"; exit 1; }

    case "${1:-}" in
        "")
            if ! config_ready; then
                warn "首次使用：请先添加一个华为云账号。"
                add_account || exit 1
                if confirm "现在创建第一个 IPv4/IPv6 任务" y; then add_task || true; fi
            fi
            main_menu;;
        --accounts) list_accounts;;
        --tasks) list_tasks;;
        --list)
            shift; extract_task_option "$@" || exit 1
            ((${#CLI_ARGS[@]} == 0)) || { fail "--list 不接受其他参数。"; exit 1; }
            load_task "$CLI_TASK_ID" || exit 1; dns_command "$TASK_ID" summary;;
        --add|--remove)
            local_action="${1#--}"; shift; extract_task_option "$@" || exit 1
            ((${#CLI_ARGS[@]} > 0)) || { fail "请提供至少一个 IP。"; exit 1; }
            load_task "$CLI_TASK_ID" || exit 1
            for cli_ip in "${CLI_ARGS[@]}"; do
                valid_ip_for_version "$cli_ip" "$IP_VERSION" || { fail "地址 ${cli_ip} 与任务 IPv${IP_VERSION} 不匹配。"; exit 1; }
            done
            dns_command "$TASK_ID" "$local_action" "${CLI_ARGS[@]}";;
        --backup-list|--backup-add|--backup-remove)
            local_action="${1#--}"; shift; extract_task_option "$@" || exit 1
            [[ -n "$CLI_TASK_ID" ]] || { fail "备用 IP 操作必须指定 --task。"; exit 1; }
            if [[ "$local_action" == "list" ]]; then
                ((${#CLI_ARGS[@]} == 0)) || { fail "--backup-list 不接受 IP 参数。"; exit 1; }
                config_command backup-list "$CLI_TASK_ID"
            else
                ((${#CLI_ARGS[@]} > 0)) || { fail "请提供至少一个备用 IP。"; exit 1; }
                load_task "$CLI_TASK_ID" || exit 1
                for cli_ip in "${CLI_ARGS[@]}"; do
                    valid_ip_for_version "$cli_ip" "$IP_VERSION" || { fail "地址 ${cli_ip} 与任务 IPv${IP_VERSION} 不匹配。"; exit 1; }
                done
                config_command "backup-${local_action#backup-}" "$TASK_ID" "${CLI_ARGS[@]}" || exit 1
                if [[ "$local_action" == "backup-add" ]]; then
                    dns_command "$TASK_ID" rebalance || warn "备用 IP 已保存，但本次云端补位失败，将在下次任务检查时重试。"
                fi
            fi;;
        --check)
            shift; extract_task_option "$@" || exit 1
            ((${#CLI_ARGS[@]} == 0)) || { fail "--check 不接受其他参数。"; exit 1; }
            if [[ -n "$CLI_TASK_ID" ]]; then check_task "$CLI_TASK_ID"; else check_all_tasks; fi;;
        --ddns-sync)
            shift; extract_task_option "$@" || exit 1
            [[ -n "$CLI_TASK_ID" ]] || { fail "--ddns-sync 必须指定 --task ID。"; exit 1; }
            dns_command "$CLI_TASK_ID" sync-ddns;;
        --start) install_service;; --stop) stop_service;; --daemon) daemon_main;;
        *) fail "未知参数：$1"; show_help; exit 1;;
    esac
}

if [[ "${HUAWEI_DNS_GUARD_LIBRARY_ONLY:-0}" != 1 ]]; then
    main "$@"
fi
