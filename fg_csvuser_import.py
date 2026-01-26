#!/usr/bin/env python3
import argparse
import csv
import getpass
import logging
import os
import sys
import time
from configparser import ConfigParser
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests
import urllib3

DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 3
DEFAULT_VDOM = "root"
DEFAULT_LOG_FILE = "fortigate_user_import.log"
DEFAULT_CONFIG_FILE = "fg_import.conf"
TOKEN_ENDPOINTS = [
    "cmdb/user/fortitoken",
    "cmdb/user/fortitoken2",
]


@dataclass
class Summary:
    created: int = 0
    skipped: int = 0
    failed: int = 0
    token_assigned: int = 0
    token_missing: int = 0


class FortiGateClient:
    def __init__(
        self,
        host: str,
        token: str,
        vdom: str = DEFAULT_VDOM,
        verify: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> None:
        self.host = host.rstrip("/")
        self.base_url = f"{self.host}/api/v2"
        self.vdom = vdom
        self.verify = verify
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        url = f"{self.base_url}/{path.lstrip('/')}"
        merged_params = {"vdom": self.vdom}
        if params:
            merged_params.update(params)

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            try:
                resp = self.session.request(
                    method,
                    url,
                    params=merged_params,
                    json=json_body,
                    timeout=self.timeout,
                    verify=self.verify,
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.retries:
                    time.sleep(attempt)
                    continue
                raise

            if resp.status_code >= 500 and attempt < self.retries:
                time.sleep(attempt)
                continue
            return resp

        if last_exc:
            raise last_exc
        raise RuntimeError("Request failed without exception")

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        return self._request("GET", path, params=params, json_body=None)

    def post(self, path: str, json_body: Dict[str, Any]) -> requests.Response:
        return self._request("POST", path, params=None, json_body=json_body)

    def put(self, path: str, json_body: Dict[str, Any]) -> requests.Response:
        return self._request("PUT", path, params=None, json_body=json_body)


def setup_logging(log_file: str) -> None:
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(fmt)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


def parse_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    value = value.strip().lower()
    if value in ("1", "true", "yes", "y", "on"):
        return True
    if value in ("0", "false", "no", "n", "off"):
        return False
    return None


def read_config(path: str) -> Dict[str, str]:
    if not os.path.exists(path):
        return {}
    config = ConfigParser()
    config.read(path)
    if "fortigate" not in config:
        return {}
    section = config["fortigate"]
    return {
        "host": section.get("host", "").strip(),
        "token": section.get("token", "").strip(),
        "vdom": section.get("vdom", "").strip(),
        "verify": section.get("verify", "").strip(),
    }


def write_config(path: str, host: str, token: str, vdom: str, verify: bool) -> None:
    config = ConfigParser()
    config["fortigate"] = {
        "host": host,
        "token": token,
        "vdom": vdom,
        "verify": "true" if verify else "false",
    }
    with open(path, "w", encoding="utf-8") as handle:
        config.write(handle)


def prompt_for_missing(
    host: Optional[str],
    token: Optional[str],
    vdom: Optional[str],
    config_path: str,
    verify: bool,
) -> Tuple[str, str, str]:
    if not sys.stdin.isatty():
        missing = []
        if not host:
            missing.append("--host")
        if not token:
            missing.append("--token")
        raise SystemExit(
            "Missing required settings: "
            + ", ".join(missing)
            + f". Provide them via CLI or config file {config_path}."
        )

    if not host:
        host = input("FortiGate host (https://<hostname>): ").strip()
    if not token:
        token = getpass.getpass("API token: ").strip()
    if not vdom:
        vdom_in = input(f"VDOM [{DEFAULT_VDOM}]: ").strip()
        vdom = vdom_in or DEFAULT_VDOM

    save = input(f"Save settings to {config_path}? [y/N]: ").strip().lower()
    if save == "y":
        write_config(config_path, host, token, vdom, verify)

    return host, token, vdom


def normalize_host(host: str) -> str:
    if not host.startswith("http://") and not host.startswith("https://"):
        host = f"https://{host}"
    return host.rstrip("/")


def parse_results(payload: Optional[Dict[str, Any]]) -> Any:
    if payload is None:
        return None
    if isinstance(payload, dict) and "results" in payload:
        return payload["results"]
    return payload


def log_http_error(resp: requests.Response, context: str) -> None:
    status = resp.status_code
    if status == 401:
        logging.error("%s: Unauthorized (401). Check API token.", context)
    elif status == 403:
        logging.error("%s: Forbidden (403). Check API permissions.", context)
    elif status == 404:
        logging.error("%s: Not found (404). Check endpoint or object.", context)
    elif status == 409:
        logging.warning("%s: Conflict (409). Object already exists.", context)
    else:
        logging.error("%s: HTTP %s", context, status)

    try:
        data = resp.json()
    except ValueError:
        data = resp.text
    if data:
        logging.error("%s: Response: %s", context, data)


def ensure_group_exists(client: FortiGateClient, group: str) -> Optional[Dict[str, Any]]:
    group_path = f"cmdb/user/group/{quote(group)}"
    resp = client.get(group_path)
    if resp.status_code == 404:
        logging.error("Group '%s' not found.", group)
        return None
    if not resp.ok:
        log_http_error(resp, f"GET {group_path}")
        return None
    try:
        payload = resp.json()
    except ValueError:
        logging.error("Invalid JSON for group '%s'.", group)
        return None
    data = parse_results(payload)
    if isinstance(data, list):
        if not data:
            logging.error("Group '%s' not found in response.", group)
            return None
        return data[0]
    if isinstance(data, dict):
        return data
    logging.error("Unexpected group response for '%s'.", group)
    return None


def create_user(
    client: FortiGateClient,
    username: str,
    password: str,
    email: str,
    dry_run: bool,
) -> str:
    payload = {
        "name": username,
        "type": "password",
        "passwd": password,
        "email": email,
    }
    if dry_run:
        logging.info("DRY-RUN create user '%s'.", username)
        return "created"

    resp = client.post("cmdb/user/local", payload)
    if resp.status_code in (200, 201):
        logging.info("Created user '%s'.", username)
        return "created"
    if resp.status_code == 409:
        logging.warning("User '%s' already exists.", username)
        return "exists"

    log_http_error(resp, f"POST cmdb/user/local ({username})")
    return "failed"


def update_user(
    client: FortiGateClient,
    username: str,
    password: Optional[str],
    email: Optional[str],
    dry_run: bool,
) -> bool:
    payload: Dict[str, Any] = {}
    if password:
        payload["passwd"] = password
    if email:
        payload["email"] = email
    if not payload:
        return True
    if dry_run:
        logging.info("DRY-RUN update user '%s'.", username)
        return True

    user_path = f"cmdb/user/local/{quote(username)}"
    resp = client.put(user_path, payload)
    if resp.ok:
        logging.info("Updated user '%s'.", username)
        return True

    log_http_error(resp, f"PUT {user_path}")
    return False


def list_local_users(client: FortiGateClient) -> Optional[List[Dict[str, Any]]]:
    resp = client.get("cmdb/user/local")
    if not resp.ok:
        log_http_error(resp, "GET cmdb/user/local")
        return None
    try:
        payload = resp.json()
    except ValueError:
        logging.error("Invalid JSON from user/local list.")
        return None
    data = parse_results(payload)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    logging.error("Unexpected user list response.")
    return None


def list_groups(client: FortiGateClient) -> Optional[List[Dict[str, Any]]]:
    resp = client.get("cmdb/user/group")
    if not resp.ok:
        log_http_error(resp, "GET cmdb/user/group")
        return None
    try:
        payload = resp.json()
    except ValueError:
        logging.error("Invalid JSON from group list.")
        return None
    data = parse_results(payload)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    logging.error("Unexpected group list response.")
    return None


def export_users(client: FortiGateClient, output_path: str) -> bool:
    users = list_local_users(client)
    if users is None:
        return False

    groups = list_groups(client)
    if groups is None:
        return False

    user_to_groups: Dict[str, List[str]] = {}
    for group in groups:
        group_name = group.get("name")
        if not group_name:
            continue
        members_raw = group.get("member", [])
        if isinstance(members_raw, dict):
            members = [members_raw]
        elif isinstance(members_raw, list):
            members = members_raw
        else:
            members = []
        for member in members:
            if not isinstance(member, dict):
                continue
            member_name = member.get("name")
            if not member_name:
                continue
            user_to_groups.setdefault(member_name, []).append(group_name)

    rows: List[Dict[str, str]] = []
    for user in users:
        username = user.get("name")
        if not username:
            continue
        email = user.get("email") or ""
        groups_for_user = user_to_groups.get(username, [])
        group_value = ""
        if groups_for_user:
            groups_for_user = sorted(set(groups_for_user))
            if len(groups_for_user) > 1:
                logging.info(
                    "User '%s' has multiple groups (%s). Exporting first.",
                    username,
                    ",".join(groups_for_user),
                )
            group_value = groups_for_user[0]
        rows.append(
            {
                "username": username,
                "password": "",
                "email": email,
                "group": group_value,
            }
        )

    rows.sort(key=lambda item: item["username"].lower())
    with open(output_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["username", "password", "email", "group"])
        writer.writeheader()
        writer.writerows(rows)

    logging.info("Exported %s users to %s.", len(rows), output_path)
    return True


def add_user_to_group(
    client: FortiGateClient,
    group_name: str,
    username: str,
    group_obj: Dict[str, Any],
    dry_run: bool,
) -> bool:
    members_raw = group_obj.get("member", [])
    if isinstance(members_raw, dict):
        members = [members_raw]
    elif isinstance(members_raw, list):
        members = members_raw
    else:
        members = []

    existing = {m.get("name") for m in members if isinstance(m, dict)}
    if username in existing:
        logging.info("User '%s' already in group '%s'.", username, group_name)
        return True

    new_members = members + [{"name": username}]
    payload = {"member": new_members}

    if dry_run:
        logging.info("DRY-RUN add user '%s' to group '%s'.", username, group_name)
        return True

    group_path = f"cmdb/user/group/{quote(group_name)}"
    resp = client.put(group_path, payload)
    if resp.ok:
        logging.info("Added user '%s' to group '%s'.", username, group_name)
        return True

    log_http_error(resp, f"PUT {group_path}")
    return False


def token_serial(token: Dict[str, Any]) -> Optional[str]:
    for key in ("serial-number", "serial", "serial_number", "id", "name"):
        value = token.get(key)
        if value:
            return str(value)
    return None


def token_sort_key(serial: str) -> Tuple[int, Any, str]:
    if serial.isdigit():
        return (0, int(serial), serial)
    return (1, serial.lower(), serial)


def token_is_free(token: Dict[str, Any]) -> bool:
    for key in (
        "assigned-user",
        "assigned_user",
        "assigned-to",
        "assigned_to",
        "user",
        "user-name",
        "username",
    ):
        value = token.get(key)
        if isinstance(value, str) and value.strip():
            return False
        if value:
            return False

    status = str(token.get("status", "")).lower()
    if status in ("assigned", "used", "bound"):
        return False
    if status in ("available", "free", "unassigned", "unused", "new", ""):
        return True

    return True


def fetch_tokens(
    client: FortiGateClient,
    token_cache: Dict[str, Any],
) -> bool:
    if token_cache.get("disabled"):
        return False

    for endpoint in TOKEN_ENDPOINTS:
        resp = client.get(endpoint)
        if resp.status_code == 404:
            continue
        if not resp.ok:
            log_http_error(resp, f"GET {endpoint}")
            token_cache["disabled"] = True
            return False
        try:
            payload = resp.json()
        except ValueError:
            logging.error("Invalid JSON from token endpoint '%s'.", endpoint)
            token_cache["disabled"] = True
            return False
        data = parse_results(payload)
        if isinstance(data, list):
            token_cache["tokens"] = data
        elif isinstance(data, dict):
            token_cache["tokens"] = [data]
        else:
            token_cache["tokens"] = []
        token_cache["endpoint"] = endpoint
        return True

    logging.error("No compatible FortiToken endpoint found (tried %s).", TOKEN_ENDPOINTS)
    token_cache["disabled"] = True
    return False


def get_free_token(
    client: FortiGateClient,
    token_cache: Dict[str, Any],
    reserved_tokens: set,
) -> Optional[str]:
    if token_cache.get("tokens") is None:
        if not fetch_tokens(client, token_cache):
            return None

    free_tokens: List[str] = []
    for token in token_cache.get("tokens", []):
        serial = token_serial(token)
        if not serial:
            continue
        if serial in reserved_tokens:
            continue
        if token_is_free(token):
            free_tokens.append(serial)

    if not free_tokens:
        return None

    free_tokens.sort(key=token_sort_key)
    return free_tokens[0]


def assign_token(
    client: FortiGateClient,
    username: str,
    serial: str,
    token_endpoint: Optional[str],
    dry_run: bool,
) -> bool:
    if dry_run:
        logging.info("DRY-RUN assign token '%s' to user '%s'.", serial, username)
        return True

    user_path = f"cmdb/user/local/{quote(username)}"
    payload = {"two-factor": "fortitoken", "fortitoken": serial}
    resp = client.put(user_path, payload)
    if resp.ok:
        logging.info("Assigned token '%s' to user '%s'.", serial, username)
        return True

    log_http_error(resp, f"PUT {user_path} (assign token)")

    if token_endpoint:
        token_path = f"{token_endpoint}/{quote(serial)}"
        resp = client.put(token_path, {"user": username})
        if resp.ok:
            logging.info("Assigned token '%s' via token endpoint to '%s'.", serial, username)
            return True
        log_http_error(resp, f"PUT {token_path}")

    return False


def load_csv(csv_path: str) -> List[Dict[str, str]]:
    with open(csv_path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"username", "password", "email", "group"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(
                "CSV must include headers: username,password,email,group"
            )
        rows = []
        for row in reader:
            if not row:
                continue
            rows.append({
                "username": (row.get("username") or "").strip(),
                "password": (row.get("password") or "").strip(),
                "email": (row.get("email") or "").strip(),
                "group": (row.get("group") or "").strip(),
            })
        return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create FortiGate local users from CSV."
    )
    parser.add_argument("--host", help="FortiGate base URL (https://<host>)")
    parser.add_argument("--token", help="API token")
    parser.add_argument("--vdom", help="VDOM (default: root)")
    parser.add_argument("--csv", dest="csv_path", help="CSV file path")
    parser.add_argument(
        "--export-users",
        dest="export_path",
        help="Export existing local users to CSV and exit",
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="Config file path")
    parser.add_argument("--dry-run", action="store_true", help="Only show actions")
    parser.add_argument("--log-file", default=DEFAULT_LOG_FILE, help="Log file path")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retry count for 5xx")
    parser.add_argument(
        "--verify",
        dest="verify",
        action="store_true",
        default=None,
        help="Enable TLS verification",
    )
    parser.add_argument(
        "--no-verify",
        dest="verify",
        action="store_false",
        default=None,
        help="Disable TLS verification (default)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.log_file)

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    config = read_config(args.config)

    host = args.host or config.get("host")
    token = args.token or config.get("token")
    vdom = args.vdom or config.get("vdom") or DEFAULT_VDOM

    verify_config = parse_bool(config.get("verify"))
    if args.verify is not None:
        verify = args.verify
    elif verify_config is not None:
        verify = verify_config
    else:
        verify = False

    if not host or not token:
        host, token, vdom = prompt_for_missing(
            host, token, vdom, args.config, verify
        )

    host = normalize_host(host)

    client = FortiGateClient(
        host=host,
        token=token,
        vdom=vdom,
        verify=verify,
        timeout=args.timeout,
        retries=args.retries,
    )

    if not args.csv_path and not args.export_path:
        logging.error("Either --csv or --export-users is required.")
        return 1

    if args.export_path:
        if export_users(client, args.export_path):
            return 0
        return 2

    try:
        rows = load_csv(args.csv_path)
    except Exception as exc:
        logging.error("Failed to read CSV: %s", exc)
        return 1

    summary = Summary()
    token_cache: Dict[str, Any] = {"tokens": None, "endpoint": None, "disabled": False}
    reserved_tokens: set = set()

    for row in rows:
        username = row["username"]
        password = row["password"]
        email = row["email"]
        group_name = row["group"]

        if not username or not password or not email or not group_name:
            logging.error("Skipping row with missing fields: %s", row)
            summary.skipped += 1
            continue

        group_obj = ensure_group_exists(client, group_name)
        if not group_obj:
            summary.skipped += 1
            continue

        create_status = create_user(client, username, password, email, args.dry_run)
        if create_status == "failed":
            summary.failed += 1
            continue

        existing_user = create_status == "exists"
        if create_status == "created":
            summary.created += 1
        else:
            if not update_user(client, username, password, email, args.dry_run):
                summary.failed += 1
                continue

        if not add_user_to_group(client, group_name, username, group_obj, args.dry_run):
            summary.failed += 1
            continue

        free_token = get_free_token(client, token_cache, reserved_tokens)
        if not free_token:
            logging.warning("No free token available for '%s'.", username)
            summary.token_missing += 1
            if existing_user:
                summary.skipped += 1
            continue

        if assign_token(
            client,
            username,
            free_token,
            token_cache.get("endpoint"),
            args.dry_run,
        ):
            reserved_tokens.add(free_token)
            summary.token_assigned += 1
        else:
            summary.failed += 1
            continue

        if existing_user:
            summary.skipped += 1

    logging.info(
        "Summary: created=%s skipped=%s failed=%s token_assigned=%s token_missing=%s",
        summary.created,
        summary.skipped,
        summary.failed,
        summary.token_assigned,
        summary.token_missing,
    )

    if args.dry_run:
        logging.info("Dry-run mode enabled: no changes were sent to FortiGate.")

    return 0 if summary.failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
