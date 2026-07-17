#!/usr/bin/env bash

# Huawei Cloud DNS IP guard
# Manages one A record set containing multiple IPv4 addresses. Each address is
# checked in several ping rounds; addresses that fail every attempt are removed.

set -uo pipefail
export LC_ALL=C

APP="huawei-dns-guard"
BASE_DIR="${HUAWEI_DNS_GUARD_BASE_DIR:-/etc/${APP}}"
CONFIG_FILE="${BASE_DIR}/config.json"
STATE_DIR="${HUAWEI_DNS_GUARD_STATE_DIR:-/var/lib/${APP}}"
LOG_FILE="${HUAWEI_DNS_GUARD_LOG_FILE:-/var/log/${APP}.log}"
LOCK_FILE="${STATE_DIR}/check.lock"
BIN_PATH="${HUAWEI_DNS_GUARD_BIN_PATH:-/usr/local/sbin/${APP}}"
SERVICE_NAME="${APP}"
SERVICE_FILE="${HUAWEI_DNS_GUARD_SERVICE_FILE:-/etc/systemd/system/${SERVICE_NAME}.service}"
SELF_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"

DEFAULT_TTL=300
DEFAULT_INTERVAL=300
DEFAULT_PING_COUNT=3
DEFAULT_PING_TIMEOUT=2
DEFAULT_CHECK_ROUNDS=3
DEFAULT_ROUND_DELAY=2
DEFAULT_MAX_PARALLEL=20
CONFIG_TEST_OK=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RESET=$'\033[0m'
    BOLD=$'\033[1m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    RED=$'\033[0;31m'
    CYAN=$'\033[0;36m'
else
    RESET=""
    BOLD=""
    GREEN=""
    YELLOW=""
    RED=""
    CYAN=""
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
    if ! command -v python3 >/dev/null 2>&1; then
        fail "缺少 python3。Debian/Ubuntu 请先运行：apt-get install -y python3 ca-certificates"
        return 1
    fi
}

ensure_dirs() {
    install -d -m 700 "$BASE_DIR" "$STATE_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
}

pause_menu() {
    local ignored
    printf '\n按回车返回主菜单...'
    IFS= read -r ignored || true
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
    local label="$1" has_old="$2" value
    if [[ "$has_old" == "1" ]]; then
        printf '%s [回车保留原值]: ' "$label" >&2
    else
        printf '%s: ' "$label" >&2
    fi
    # AK/SK are intentionally visible while entering so they can be checked.
    IFS= read -r value || true
    printf '%s\n' "$value"
}

confirm() {
    local label="$1" default="${2:-n}" answer
    if [[ "$default" == "y" ]]; then
        printf '%s [回车=是，n=否]: ' "$label" >&2
    else
        printf '%s [y=是，回车=否]: ' "$label" >&2
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

is_uint() {
    [[ "${1:-}" =~ ^[0-9]+$ ]]
}

in_range() {
    local value="$1" minimum="$2" maximum="$3"
    is_uint "$value" && ((10#$value >= minimum && 10#$value <= maximum))
}

valid_domain() {
    local domain="${1%.}"
    [[ ${#domain} -le 253 ]] || return 1
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
    [[ "$domain" == *.* ]]
}

valid_ipv4() {
    local ip="$1" a b c d extra octet
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS=. read -r a b c d extra <<< "$ip"
    [[ -z "${extra:-}" ]] || return 1
    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" == "0" || "$octet" != 0* ]] || return 1
        ((10#$octet >= 0 && 10#$octet <= 255)) || return 1
    done
}

config_ready() {
    [[ -f "$CONFIG_FILE" ]] || return 1
    python3 - "$CONFIG_FILE" <<'PY' >/dev/null 2>&1
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
for key in ("ak", "sk", "domain"):
    if not str(data.get(key, "")).strip():
        raise SystemExit(1)
PY
}

load_runtime_config() {
    DOMAIN=""
    TTL="$DEFAULT_TTL"
    INTERVAL="$DEFAULT_INTERVAL"
    PING_COUNT="$DEFAULT_PING_COUNT"
    PING_TIMEOUT="$DEFAULT_PING_TIMEOUT"
    CHECK_ROUNDS="$DEFAULT_CHECK_ROUNDS"
    ROUND_DELAY="$DEFAULT_ROUND_DELAY"
    MAX_PARALLEL="$DEFAULT_MAX_PARALLEL"

    [[ -f "$CONFIG_FILE" ]] || return 0
    while IFS=$'\t' read -r key value; do
        case "$key" in
            domain) DOMAIN="$value" ;;
            ttl) TTL="$value" ;;
            interval) INTERVAL="$value" ;;
            ping_count) PING_COUNT="$value" ;;
            ping_timeout) PING_TIMEOUT="$value" ;;
            check_rounds) CHECK_ROUNDS="$value" ;;
            round_delay) ROUND_DELAY="$value" ;;
            max_parallel) MAX_PARALLEL="$value" ;;
        esac
    done < <(python3 - "$CONFIG_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
defaults = {
    "domain": "",
    "ttl": 300,
    "interval": 300,
    "ping_count": 3,
    "ping_timeout": 2,
    "check_rounds": 3,
    "round_delay": 2,
    "max_parallel": 20,
}
for key, default in defaults.items():
    value = data.get(key, default)
    print(f"{key}\t{value}")
PY
)
}

load_saved_secrets() {
    OLD_AK=""
    OLD_SK=""
    [[ -f "$CONFIG_FILE" ]] || return 0
    {
        IFS= read -r OLD_AK || true
        IFS= read -r OLD_SK || true
    } < <(python3 - "$CONFIG_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
print(str(data.get("ak", "")))
print(str(data.get("sk", "")))
PY
)
}

save_config() {
    local ak="$1" sk="$2"
    ensure_dirs
    python3 - "$CONFIG_FILE" "$ak" "$sk" "$DOMAIN" \
        "$TTL" "$INTERVAL" "$PING_COUNT" \
        "$PING_TIMEOUT" "$CHECK_ROUNDS" "$ROUND_DELAY" "$MAX_PARALLEL" <<'PY'
import json
import os
import sys
import tempfile

(
    path, ak, sk, domain, ttl, interval,
    ping_count, ping_timeout, check_rounds, round_delay, max_parallel,
) = sys.argv[1:]
data = {
    "ak": ak,
    "sk": sk,
    "domain": domain.rstrip(".").lower(),
    "ttl": int(ttl),
    "interval": int(interval),
    "ping_count": int(ping_count),
    "ping_timeout": int(ping_timeout),
    "check_rounds": int(check_rounds),
    "round_delay": int(round_delay),
    "max_parallel": int(max_parallel),
}
directory = os.path.dirname(path)
fd, temp = tempfile.mkstemp(prefix=".config.", dir=directory)
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
PY
    chmod 600 "$CONFIG_FILE"
}

# This helper performs Huawei Cloud SDK-HMAC-SHA256 signing and all DNS API
# operations. Keeping record-set changes in one process avoids fragile JSON
# parsing in shell and preserves IPs added concurrently by another process.
dns_command() {
    local action="$1"
    shift
    python3 - "$CONFIG_FILE" "$action" "$@" <<'PY'
import datetime
import hashlib
import hmac
import ipaddress
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


CONFIG_PATH = sys.argv[1]
ACTION = sys.argv[2]
ARGS = sys.argv[3:]


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    for key in ("ak", "sk", "domain"):
        if not str(config.get(key, "")).strip():
            raise RuntimeError(f"配置缺少 {key}")
    return config


cfg = load_config()


def normalize_name(value):
    return str(value).strip().rstrip(".").lower()


def canonical_query(items):
    encoded = []
    for key, value in items:
        encoded.append((
            urllib.parse.quote(str(key), safe="~"),
            urllib.parse.quote(str(value), safe="~"),
        ))
    encoded.sort()
    return "&".join(f"{key}={value}" for key, value in encoded)


def api_request(method, path, query=None, body=None):
    endpoint = "https://dns.myhuaweicloud.com"

    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        raise RuntimeError("API Endpoint 必须是有效的 https 地址")

    base_path = parsed.path.rstrip("/")
    request_path = base_path + path
    items = []
    for key, value in (query or {}).items():
        if isinstance(value, (list, tuple)):
            items.extend((key, item) for item in value)
        elif value is not None:
            items.append((key, value))
    query_string = canonical_query(items)
    url = urllib.parse.urlunsplit((
        parsed.scheme,
        parsed.netloc,
        request_path,
        query_string,
        "",
    ))

    payload = b""
    if body is not None:
        payload = json.dumps(
            body, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

    sdk_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = parsed.netloc
    headers_to_sign = {"host": host, "x-sdk-date": sdk_date}
    if body is not None:
        headers_to_sign["content-type"] = "application/json; charset=utf-8"
    signed_header_names = sorted(headers_to_sign)
    signed_headers = ";".join(signed_header_names)
    canonical_headers = "".join(
        f"{name}:{' '.join(headers_to_sign[name].strip().split())}\n"
        for name in signed_header_names
    )
    canonical_uri = urllib.parse.quote(
        urllib.parse.unquote(request_path), safe="/-_.~"
    )
    if not canonical_uri.startswith("/"):
        canonical_uri = "/" + canonical_uri
    if not canonical_uri.endswith("/"):
        canonical_uri += "/"

    canonical_request = "\n".join((
        method.upper(),
        canonical_uri,
        query_string,
        canonical_headers,
        signed_headers,
        hashlib.sha256(payload).hexdigest(),
    ))
    algorithm = "SDK-HMAC-SHA256"
    string_to_sign = "\n".join((
        algorithm,
        sdk_date,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ))
    signature = hmac.new(
        str(cfg["sk"]).encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    authorization = (
        f"{algorithm} Access={cfg['ak']}, SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    headers = {
        "Host": host,
        "X-Sdk-Date": sdk_date,
        "Authorization": authorization,
        "Accept": "application/json",
        "User-Agent": "huawei-dns-guard/1.0",
    }
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"

    request = urllib.request.Request(
        url,
        data=payload if body is not None else None,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        message = raw
        try:
            detail = json.loads(raw)
            message = (
                detail.get("error_msg")
                or detail.get("message")
                or detail.get("error_code")
                or raw
            )
        except json.JSONDecodeError:
            pass
        raise RuntimeError(f"华为云 API HTTP {error.code}: {message}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"连接华为云 DNS API 失败: {error.reason}") from error


def list_public_zones():
    zones = []
    limit = 500
    offset = 0
    for _ in range(100):
        data = api_request(
            "GET",
            "/v2/zones",
            {"type": "public", "limit": limit, "offset": offset},
        )
        page = data.get("zones", [])
        zones.extend(page)
        if len(page) < limit:
            break
        offset += limit
    return zones


def find_zone():
    domain = normalize_name(cfg["domain"])
    matches = []
    for zone in list_public_zones():
        zone_name = normalize_name(zone.get("name", ""))
        if domain == zone_name or domain.endswith("." + zone_name):
            matches.append((len(zone_name), zone))
    if not matches:
        raise RuntimeError(
            f"当前账号中找不到域名 {domain} 所属的公网域名，请检查 AK/SK 和域名"
        )
    return max(matches, key=lambda item: item[0])[1]


def find_recordset(zone_id):
    domain = normalize_name(cfg["domain"])
    data = api_request(
        "GET",
        f"/v2/zones/{zone_id}/recordsets",
        {"type": "A", "name": domain + ".", "limit": 500},
    )
    matches = [
        item for item in data.get("recordsets", [])
        if normalize_name(item.get("name", "")) == domain
        and str(item.get("type", "")).upper() == "A"
    ]
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]
    default_matches = [
        item for item in matches
        if str(item.get("line", "")).lower() in ("", "default_view")
    ]
    if len(default_matches) == 1:
        return default_matches[0]
    raise RuntimeError("发现多个同名 A 记录线路，无法确定要管理哪一个记录集")


def clean_records(values):
    result = []
    seen = set()
    for value in values:
        try:
            ip = str(ipaddress.IPv4Address(str(value).strip()))
        except ipaddress.AddressValueError as error:
            raise RuntimeError(f"无效 IPv4 地址: {value}") from error
        if ip not in seen:
            result.append(ip)
            seen.add(ip)
    return sorted(result, key=lambda value: int(ipaddress.IPv4Address(value)))


def current_records(recordset):
    if not recordset:
        return []
    records = []
    for value in recordset.get("records", []):
        try:
            records.append(str(ipaddress.IPv4Address(str(value).strip())))
        except ipaddress.AddressValueError:
            continue
    return clean_records(records)


def record_body(records, ttl, description="", creating=False):
    body = {"ttl": int(ttl), "records": records}
    if creating:
        body["name"] = normalize_name(cfg["domain"]) + "."
        body["type"] = "A"
    if description:
        body["description"] = description
    return body


def create_or_update(zone, recordset, records, ttl):
    zone_id = zone["id"]
    description = "Managed by huawei-dns-guard"
    if recordset:
        description = str(recordset.get("description", "")) or description
        return api_request(
            "PUT",
            f"/v2/zones/{zone_id}/recordsets/{recordset['id']}",
            body=record_body(records, ttl, description),
        )
    return api_request(
        "POST",
        f"/v2/zones/{zone_id}/recordsets",
        body=record_body(records, ttl, description, creating=True),
    )


def print_summary(zone, recordset):
    print(f"公网域名: {normalize_name(zone.get('name', ''))}")
    print(f"管理记录: {normalize_name(cfg['domain'])}  A")
    if not recordset:
        print("记录状态: 尚未创建")
        print("IP 数量: 0")
        return
    print(f"记录状态: {recordset.get('status', 'UNKNOWN')}")
    print(f"TTL: {recordset.get('ttl', cfg.get('ttl', 300))} 秒")
    records = current_records(recordset)
    print(f"IP 数量: {len(records)}")
    for index, ip in enumerate(records, 1):
        print(f"  {index:>3}. {ip}")


def main():
    zone = find_zone()
    recordset = find_recordset(zone["id"])

    if ACTION in ("summary", "test"):
        print_summary(zone, recordset)
        return

    if ACTION == "records":
        for ip in current_records(recordset):
            print(ip)
        return

    if ACTION == "add":
        additions = clean_records(ARGS)
        existing = current_records(recordset)
        merged = clean_records(existing + additions)
        create_or_update(zone, recordset, merged, int(cfg.get("ttl", 300)))
        added = len(set(merged) - set(existing))
        print(f"已写入华为云 DNS：新增 {added} 个，当前共 {len(merged)} 个 IP。")
        return

    if ACTION == "remove":
        removals = set(clean_records(ARGS))
        existing = current_records(recordset)
        removed = [ip for ip in existing if ip in removals]
        remaining = [ip for ip in existing if ip not in removals]
        if not recordset or not removed:
            print("华为云 DNS 中没有需要删除的 IP。")
            return
        if remaining:
            ttl = int(recordset.get("ttl", cfg.get("ttl", 300)))
            create_or_update(zone, recordset, remaining, ttl)
        else:
            api_request(
                "DELETE",
                f"/v2/zones/{zone['id']}/recordsets/{recordset['id']}",
            )
        print(f"已从华为云 DNS 删除 {len(removed)} 个 IP，剩余 {len(remaining)} 个。")
        return

    raise RuntimeError(f"未知操作: {ACTION}")


try:
    main()
except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
    print(f"错误：{error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

log_msg() {
    local level="$1"
    shift
    local message="$*" line
    line="[$(date '+%F %T')] [${level}] ${message}"
    ensure_dirs
    printf '%s\n' "$line" >> "$LOG_FILE"
    case "$level" in
        完成) ok "$message" ;;
        注意) warn "$message" ;;
        错误) fail "$message" ;;
        *) info "$message" ;;
    esac
}

restart_daemon_if_running() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl restart "$SERVICE_NAME"
        ok "定时检测服务已重启并加载新配置。"
    fi
}

setup_config() {
    local ak sk value has_old_ak=0 has_old_sk=0
    CONFIG_TEST_OK=0
    require_python || return 1
    load_runtime_config
    load_saved_secrets
    [[ -n "$OLD_AK" ]] && has_old_ak=1
    [[ -n "$OLD_SK" ]] && has_old_sk=1

    printf '\n%s华为云 DNS 配置%s\n' "$BOLD" "$RESET"
    printf 'AK/SK 可在华为云“我的凭证 -> 访问密钥”中创建。\n\n'

    ak="$(prompt_secret "Access Key ID" "$has_old_ak")"
    [[ -n "$ak" ]] || ak="$OLD_AK"
    sk="$(prompt_secret "Secret Access Key" "$has_old_sk")"
    [[ -n "$sk" ]] || sk="$OLD_SK"
    if [[ -z "$ak" || -z "$sk" ]]; then
        fail "Access Key ID 和 Secret Access Key 不能为空。"
        return 1
    fi

    while true; do
        value="$(prompt "要管理的完整域名，例如 vpn.example.com" "$DOMAIN")"
        value="$(trim "${value%.}")"
        if valid_domain "$value"; then
            DOMAIN="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
            break
        fi
        fail "域名格式无效。"
    done

    while true; do
        value="$(prompt "DNS TTL（秒）" "$TTL")"
        if in_range "$value" 1 2147483647; then TTL="$value"; break; fi
        fail "TTL 必须是 1-2147483647 秒。"
    done
    while true; do
        value="$(prompt "定时检测间隔（秒）" "$INTERVAL")"
        if in_range "$value" 10 86400; then INTERVAL="$value"; break; fi
        fail "检测间隔必须是 10-86400 秒。"
    done
    while true; do
        value="$(prompt "每轮每个 IP 最多 ping 几次" "$PING_COUNT")"
        if in_range "$value" 1 10; then PING_COUNT="$value"; break; fi
        fail "次数必须是 1-10。"
    done
    while true; do
        value="$(prompt "连续检测几轮，全失败才删除" "$CHECK_ROUNDS")"
        if in_range "$value" 1 10; then CHECK_ROUNDS="$value"; break; fi
        fail "轮数必须是 1-10。"
    done
    while true; do
        value="$(prompt "单次 ping 超时（秒）" "$PING_TIMEOUT")"
        if in_range "$value" 1 30; then PING_TIMEOUT="$value"; break; fi
        fail "超时必须是 1-30 秒。"
    done
    while true; do
        value="$(prompt "失败轮次之间等待（秒）" "$ROUND_DELAY")"
        if in_range "$value" 0 60; then ROUND_DELAY="$value"; break; fi
        fail "等待时间必须是 0-60 秒。"
    done
    while true; do
        value="$(prompt "同时检测的最大 IP 数" "$MAX_PARALLEL")"
        if in_range "$value" 1 100; then MAX_PARALLEL="$value"; break; fi
        fail "并发数必须是 1-100。"
    done

    save_config "$ak" "$sk"
    ok "配置已保存到 ${CONFIG_FILE}（权限 600）。"
    info "正在验证华为云鉴权并查找域名..."
    if dns_command test; then
        CONFIG_TEST_OK=1
        ok "华为云 DNS 连接正常。"
    else
        warn "配置已保存，但连接测试失败。请按上面的错误检查 AK/SK 或域名。"
    fi
    restart_daemon_if_running
}

ensure_config() {
    if ! config_ready; then
        warn "请先完成华为云 DNS 配置。"
        setup_config || return 1
    fi
    load_runtime_config
}

collect_ips() {
    INPUT_IPS=()
    local line ip existing
    printf '请粘贴 IPv4，一行一个；输入空行或单独一行 . 结束：\n'
    while IFS= read -r line; do
        line="$(trim "${line//$'\r'/}")"
        [[ -n "$line" && "$line" != "." ]] || break
        if ! valid_ipv4 "$line"; then
            warn "已跳过无效 IPv4：$line"
            continue
        fi
        existing=0
        for ip in "${INPUT_IPS[@]}"; do
            if [[ "$ip" == "$line" ]]; then
                existing=1
                break
            fi
        done
        ((existing == 1)) || INPUT_IPS+=("$line")
    done
    if ((${#INPUT_IPS[@]} == 0)); then
        warn "没有输入有效 IP。"
        return 1
    fi
}

bulk_add_ips() {
    ensure_config || return 1
    collect_ips || return 1
    info "正在把 ${#INPUT_IPS[@]} 个 IP 合并到 ${DOMAIN} 的 A 记录..."
    if dns_command add "${INPUT_IPS[@]}"; then
        ok "华为云 DNS 已接受更新。"
    else
        fail "批量添加失败。"
        return 1
    fi
}

bulk_remove_ips() {
    ensure_config || return 1
    collect_ips || return 1
    if ! confirm "确定从 ${DOMAIN} 的 A 记录中删除这些 IP" "n"; then
        info "已取消。"
        return 0
    fi
    if dns_command remove "${INPUT_IPS[@]}"; then
        ok "删除操作已完成。"
    else
        fail "删除失败。"
        return 1
    fi
}

show_records() {
    ensure_config || return 1
    printf '\n'
    dns_command summary
}

check_one_ip() {
    local ip="$1" result_file="$2"
    local round=1 attempt
    while ((round <= CHECK_ROUNDS)); do
        attempt=1
        while ((attempt <= PING_COUNT)); do
            if ping -4 -n -c 1 -W "$PING_TIMEOUT" "$ip" >/dev/null 2>&1; then
                printf 'up %s %s\n' "$round" "$attempt" > "$result_file"
                return 0
            fi
            ((attempt++))
        done
        if ((round < CHECK_ROUNDS && ROUND_DELAY > 0)); then
            sleep "$ROUND_DELAY"
        fi
        ((round++))
    done
    printf 'down\n' > "$result_file"
    return 1
}

check_all() (
    local records_output ip index running pid result temp_dir
    local -a ips pids failed

    ensure_config || exit 1
    command -v ping >/dev/null 2>&1 || { fail "缺少 ping 命令。"; exit 1; }
    command -v flock >/dev/null 2>&1 || { fail "缺少 flock 命令（util-linux）。"; exit 1; }
    load_runtime_config
    ensure_dirs

    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        warn "已有一轮检测正在运行，本次跳过。"
        exit 0
    fi

    if ! records_output="$(dns_command records)"; then
        log_msg "错误" "读取 ${DOMAIN} 的华为云 DNS 记录失败。"
        exit 1
    fi

    ips=()
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && ips+=("$ip")
    done <<< "$records_output"
    if ((${#ips[@]} == 0)); then
        log_msg "注意" "${DOMAIN} 当前没有 A 记录 IP，跳过检测。"
        exit 0
    fi

    log_msg "信息" "开始检测 ${DOMAIN} 的 ${#ips[@]} 个 IP：${CHECK_ROUNDS} 轮，每轮最多 ${PING_COUNT} 次。"
    temp_dir="$(mktemp -d "${STATE_DIR}/check.XXXXXX")"
    pids=()
    running=0
    index=0
    for ip in "${ips[@]}"; do
        check_one_ip "$ip" "${temp_dir}/${index}" &
        pids+=("$!")
        ((running++))
        ((index++))
        if ((running >= MAX_PARALLEL)); then
            for pid in "${pids[@]}"; do wait "$pid" || true; done
            pids=()
            running=0
        fi
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    failed=()
    index=0
    for ip in "${ips[@]}"; do
        result="$(cat "${temp_dir}/${index}" 2>/dev/null || printf 'down')"
        if [[ "$result" == up* ]]; then
            log_msg "完成" "${ip} 可达，保留解析。"
        else
            failed+=("$ip")
            log_msg "注意" "${ip} 连续 ${CHECK_ROUNDS} 轮均不可达，准备删除解析。"
        fi
        ((index++))
    done
    rm -rf -- "$temp_dir"

    if ((${#failed[@]} == 0)); then
        log_msg "完成" "本轮检测结束，所有 IP 均可达。"
        exit 0
    fi

    if dns_command remove "${failed[@]}"; then
        log_msg "完成" "本轮已从 ${DOMAIN} 删除 ${#failed[@]} 个失效 IP。"
    else
        log_msg "错误" "失效 IP 已确认，但更新华为云 DNS 失败；下轮会再次检测。"
        exit 1
    fi
)

install_dependencies() {
    local packages=()
    command -v python3 >/dev/null 2>&1 || packages+=(python3)
    command -v ping >/dev/null 2>&1 || packages+=(iputils-ping)
    command -v flock >/dev/null 2>&1 || packages+=(util-linux)
    ((${#packages[@]} == 0)) && return 0

    info "正在安装依赖：${packages[*]}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ca-certificates python3 iputils util-linux
    elif command -v yum >/dev/null 2>&1; then
        yum install -y ca-certificates python3 iputils util-linux
    else
        fail "未找到 apt-get、dnf 或 yum，请手动安装：python3、iputils-ping、util-linux、ca-certificates。"
        return 1
    fi
}

install_service() {
    ensure_config || return 1
    install_dependencies || return 1
    command -v systemctl >/dev/null 2>&1 || {
        fail "当前系统没有 systemd，无法安装定时服务。仍可用菜单手动检测。"
        return 1
    }
    if [[ ! -f "$SELF_PATH" ]]; then
        fail "当前运行方式无法读取脚本自身，请把 huwei.sh 保存到本机后再运行。"
        return 1
    fi

    ensure_dirs
    if [[ "$(readlink -f "$SELF_PATH" 2>/dev/null || printf '%s' "$SELF_PATH")" != \
          "$(readlink -f "$BIN_PATH" 2>/dev/null || printf '%s' "$BIN_PATH")" ]]; then
        install -m 755 "$SELF_PATH" "$BIN_PATH"
    else
        chmod 755 "$BIN_PATH"
    fi

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Huawei Cloud DNS IP health guard
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
    ok "定时检测已启动，检测间隔 ${INTERVAL} 秒。"
    info "服务状态：systemctl status ${SERVICE_NAME}"
}

stop_service() {
    if ! command -v systemctl >/dev/null 2>&1; then
        fail "当前系统没有 systemd。"
        return 1
    fi
    systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
    ok "定时检测已停止。配置和 DNS 记录均已保留。"
}

show_logs() {
    ensure_dirs
    printf '\n最近 100 条检测日志：\n\n'
    if [[ -s "$LOG_FILE" ]]; then
        tail -n 100 "$LOG_FILE"
    else
        printf '暂无日志。\n'
    fi
}

service_state() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME"; then
        printf '%s运行中%s' "$GREEN" "$RESET"
    else
        printf '%s未运行%s' "$YELLOW" "$RESET"
    fi
}

show_menu_header() {
    load_runtime_config
    printf '\n%s%s华为云 DNS IP 健康管理%s\n' "$BOLD" "$CYAN" "$RESET"
    printf '%s\n' '============================================================'
    if config_ready; then
        printf '域名：%s    TTL：%s 秒    定时服务：' "$DOMAIN" "$TTL"
        service_state
        printf '\n规则：%s 轮，每轮最多 ping %s 次；任意一次成功即保留\n' \
            "$CHECK_ROUNDS" "$PING_COUNT"
    else
        printf '状态：尚未配置华为云 AK/SK 和域名\n'
    fi
    printf '%s\n' '------------------------------------------------------------'
}

main_menu() {
    local choice
    while true; do
        show_menu_header
        printf '%s\n' \
            '  1) 首次配置 / 更新华为云 AK/SK、域名和检测规则' \
            '  2) 批量添加 IP 到域名解析' \
            '  3) 查看当前域名解析 IP' \
            '  4) 立即检测一轮并删除失效 IP' \
            '  5) 手动批量删除 IP' \
            '  6) 启动/更新定时检测服务' \
            '  7) 停止定时检测服务' \
            '  8) 查看检测日志' \
            '  0) 退出'
        printf '\n请选择: '
        IFS= read -r choice || choice=0
        case "$choice" in
            1) setup_config; pause_menu ;;
            2) bulk_add_ips; pause_menu ;;
            3) show_records; pause_menu ;;
            4) check_all; pause_menu ;;
            5) bulk_remove_ips; pause_menu ;;
            6) install_service; pause_menu ;;
            7) stop_service; pause_menu ;;
            8) show_logs; pause_menu ;;
            0) exit 0 ;;
            *) warn "无效选项。"; pause_menu ;;
        esac
    done
}

show_help() {
    cat <<EOF
用法：
  sudo bash huwei.sh               打开菜单
  sudo bash huwei.sh --check       立即检测并清理失效 IP
  sudo bash huwei.sh --list        查看当前 A 记录
  sudo bash huwei.sh --add IP...   添加一个或多个 IP
  sudo bash huwei.sh --remove IP... 删除一个或多个 IP
  sudo bash huwei.sh --start       安装并启动定时服务
  sudo bash huwei.sh --stop        停止定时服务
EOF
}

daemon_main() {
    local sleep_seconds
    ensure_config || exit 1
    install_dependencies || exit 1
    while true; do
        check_all || true
        load_runtime_config
        sleep_seconds="$INTERVAL"
        in_range "$sleep_seconds" 10 86400 || sleep_seconds="$DEFAULT_INTERVAL"
        sleep "$sleep_seconds"
    done
}

main() {
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
    esac

    require_root
    # A fresh Debian cloud host can run the script directly; install the
    # runtime tools before any command needs them.
    install_dependencies || exit 1
    require_python || exit 1

    case "${1:-}" in
        "")
            # First run is one-click: after a successful configuration test,
            # install and start the background service automatically.
            if ! config_ready; then
                setup_config || exit 1
                if ((CONFIG_TEST_OK == 1)); then
                    install_service || warn "定时服务启动失败，可稍后在菜单选择 6 重试。"
                else
                    warn "连接测试未通过，暂不启动定时服务；修正配置后再选择菜单 6。"
                fi
            fi
            main_menu
            ;;
        --check) check_all ;;
        --list) show_records ;;
        --add)
            shift
            (($# > 0)) || { fail "请在 --add 后提供至少一个 IPv4。"; exit 1; }
            ensure_config || exit 1
            dns_command add "$@"
            ;;
        --remove)
            shift
            (($# > 0)) || { fail "请在 --remove 后提供至少一个 IPv4。"; exit 1; }
            ensure_config || exit 1
            dns_command remove "$@"
            ;;
        --start) install_service ;;
        --stop) stop_service ;;
        --daemon) daemon_main ;;
        *) fail "未知参数：$1"; show_help; exit 1 ;;
    esac
}

main "$@"
