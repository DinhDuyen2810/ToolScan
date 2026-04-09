from __future__ import annotations

import html as html_lib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import paramiko
import requests
import urllib3
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template, request
from requests import Response, Session
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
        nextCmd,
    )
except Exception:
    CommunityData = ContextData = ObjectIdentity = ObjectType = SnmpEngine = UdpTransportTarget = None
    getCmd = nextCmd = None

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except Exception:
    PlaywrightTimeoutError = Exception
    sync_playwright = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
SSH_DATABASE_PATH = DATA_DIR / 'servers.json'
WEB_DATABASE_PATH = DATA_DIR / 'websites.json'
SOLUTION_DATABASE_PATH = DATA_DIR / 'solutions.json'

DEFAULT_SERVERS = [
    {'ip': '163.223.58.4', 'username': 'root', 'password': 't0ikonho@123', 'snmp_community': 'public'},
    {'ip': '163.223.58.5', 'username': 'root', 'password': 't0ikonho@123', 'snmp_community': 'public'},
    {'ip': '163.223.58.12', 'username': 'root', 'password': 'v2labadmin@123', 'snmp_community': 'public'},
    {'ip': '163.223.58.13', 'username': 'root', 'password': 'v2labadmin@123', 'snmp_community': 'public'},
    {'ip': '163.223.58.14', 'username': 'root', 'password': 'v2labadmin@123', 'snmp_community': 'public'},
]

DEFAULT_WEBSITES = [
    {'domain': 'v2secure.vn'},
    {'domain': 'jira-int.v2secure.vn'},
    {'domain': 'confluence-int.v2secure.vn'},
    {'domain': 'authentik-int.v2secure.vn'},
    {'domain': 'mail.v2secure.vn'},
]

DEFAULT_SOLUTIONS = [
    {
        'name': 'SIEM',
        'endpoint': '163.223.58.132',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'v2secure',
        'snmp_port': 161,
    },
    {
        'name': 'WAF01',
        'endpoint': '163.223.58.130',
        'username': 'admin',
        'password': 'admin',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'WAF02',
        'endpoint': '163.223.58.131',
        'username': 'admin',
        'password': 'admin',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'EDR',
        'endpoint': '163.223.58.133',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NAC',
        'endpoint': '163.223.58.134',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_MCNB',
        'endpoint': '163.223.58.135',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_CSDL',
        'endpoint': '163.223.58.136',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_Tools',
        'endpoint': '163.223.58.137',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_LAN',
        'endpoint': '163.223.58.138',
        'username': 'admin',
        'password': 'admin',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_DMZ',
        'endpoint': '163.223.58.139',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_V2Cloud',
        'endpoint': '163.223.58.144',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_MGT',
        'endpoint': '163.223.58.146',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'PAM',
        'endpoint': '163.223.58.143',
        'username': 'TTS_SOC_DNDuyen',
        'password': 'DNDuyenSOC@2026$#',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': False,
        'snmp_enabled': False,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NOC',
        'endpoint': 'http://163.223.58.140/cacti/',
        'username': 'admin',
        'password': 'V2labadmin@123',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': False,
        'snmp_enabled': False,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
]

CPU_RE = re.compile(r'CPU=([-]?[0-9]+(?:[.,][0-9]+)?)')
RAM_RE = re.compile(r'RAM=([-]?[0-9]+(?:[.,][0-9]+)?)')
STORAGE_RE = re.compile(r'STORAGE=([-]?[0-9]+(?:[.,][0-9]+)?)')
PASSWORD_INPUT_RE = re.compile(r'<input[^>]+type=["\']?password', re.IGNORECASE)
USERNAME_HINTS = ('user', 'username', 'login', 'email', 'mail', 'account', 'uid')
PASSWORD_HINTS = ('pass', 'password', 'passwd', 'pwd')
LOGIN_WORDS = ('login', 'log in', 'sign in', 'đăng nhập', 'authentication')
DEFAULT_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/128.0 Safari/537.36'
    )
}


def parse_float_loose(value: str) -> float:
    return float(str(value).strip().replace(',', '.'))


def ensure_databases() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SSH_DATABASE_PATH.exists():
        save_servers(DEFAULT_SERVERS)
    if not WEB_DATABASE_PATH.exists():
        save_websites(DEFAULT_WEBSITES)
    if not SOLUTION_DATABASE_PATH.exists():
        save_solutions(DEFAULT_SOLUTIONS)


def read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def normalize_server(raw: dict[str, Any]) -> dict[str, str]:
    return {
        'ip': str(raw.get('ip', '')).strip(),
        'username': str(raw.get('username', '')).strip(),
        'password': str(raw.get('password', '')).strip(),
        'snmp_community': str(raw.get('snmp_community', raw.get('community', 'public'))).strip(),
    }


def validate_servers(servers: list[dict[str, Any]]) -> list[dict[str, str]]:
    cleaned = [normalize_server(item) for item in servers]
    if len(cleaned) != 5:
        raise ValueError('Database SSH phải có đúng 5 dòng máy.')
    for index, server in enumerate(cleaned, start=1):
        if not (server['ip'] and server['username'] and server['password'] and server['snmp_community']):
            raise ValueError(f'Dòng SSH {index} đang thiếu IP, username, password hoặc SNMP CommunityString.')
    return cleaned


def normalize_website(raw: Any) -> dict[str, str]:
    value = raw if isinstance(raw, str) else raw.get('domain', '')
    return {'domain': str(value).strip().replace(' ', '')}


def validate_websites(websites: list[Any]) -> list[dict[str, str]]:
    cleaned = [normalize_website(item) for item in websites]
    if len(cleaned) != 5:
        raise ValueError('Database website phải có đúng 5 dòng domain.')
    for index, website in enumerate(cleaned, start=1):
        if not website['domain']:
            raise ValueError(f'Dòng website {index} đang thiếu domain.')
    return cleaned


def to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}


def normalize_solution(raw: dict[str, Any]) -> dict[str, Any]:
    endpoint = raw.get('endpoint', raw.get('target', ''))
    return {
        'name': str(raw.get('name', '')).strip(),
        'endpoint': str(endpoint).strip(),
        'username': str(raw.get('username', '')).strip(),
        'password': str(raw.get('password', '')).strip(),
        'ssh_username': str(raw.get('ssh_username', raw.get('ssh_user', ''))).strip(),
        'ssh_password': str(raw.get('ssh_password', raw.get('ssh_pass', ''))).strip(),
        'checkservice': to_bool(raw.get('checkservice', False)),
        'snmp_enabled': to_bool(raw.get('snmp_enabled', raw.get('use_snmp', True))),
        'snmp_port': int(str(raw.get('snmp_port', raw.get('port', 161)) or '161')),
        'snmp_version': str(raw.get('snmp_version', raw.get('version', '2c'))).strip().lower() or '2c',
        'snmp_community': str(raw.get('snmp_community', raw.get('community', 'public'))).strip() or 'public',
        'snmp_timeout': int(str(raw.get('snmp_timeout', 2)) or '2'),
        'snmp_retries': int(str(raw.get('snmp_retries', 0)) or '0'),
    }


def validate_solutions(solutions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned = [normalize_solution(item) for item in solutions]
    if not cleaned:
        raise ValueError('Database giải pháp phải có ít nhất 1 dòng.')
    for index, solution in enumerate(cleaned, start=1):
        if not (
            solution['name']
            and solution['endpoint']
            and solution['username']
            and solution['password']
            and solution['snmp_community']
        ):
            raise ValueError(
                f'Dòng giải pháp {index} đang thiếu tên, endpoint, '
                f'username/password giao diện hoặc SNMP CommunityString.'
            )
    return cleaned


def load_servers() -> list[dict[str, str]]:
    ensure_databases()
    try:
        data = read_json_file(SSH_DATABASE_PATH)
        if not isinstance(data, list):
            raise ValueError('Database SSH không đúng định dạng.')
        return validate_servers(data)
    except Exception:
        save_servers(DEFAULT_SERVERS)
        return [item.copy() for item in DEFAULT_SERVERS]


def save_servers(servers: list[dict[str, Any]]) -> list[dict[str, str]]:
    cleaned = validate_servers(servers)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SSH_DATABASE_PATH.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
    return cleaned


def load_websites() -> list[dict[str, str]]:
    ensure_databases()
    try:
        data = read_json_file(WEB_DATABASE_PATH)
        if not isinstance(data, list):
            raise ValueError('Database website không đúng định dạng.')
        return validate_websites(data)
    except Exception:
        save_websites(DEFAULT_WEBSITES)
        return [item.copy() for item in DEFAULT_WEBSITES]


def save_websites(websites: list[Any]) -> list[dict[str, str]]:
    cleaned = validate_websites(websites)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    WEB_DATABASE_PATH.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
    return cleaned


def load_solutions() -> list[dict[str, Any]]:
    ensure_databases()
    try:
        data = read_json_file(SOLUTION_DATABASE_PATH)
        if not isinstance(data, list):
            raise ValueError('Database giải pháp không đúng định dạng.')
        return validate_solutions(data)
    except Exception:
        save_solutions(DEFAULT_SOLUTIONS)
        return [dict(item) for item in DEFAULT_SOLUTIONS]


def save_solutions(solutions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned = validate_solutions(solutions)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SOLUTION_DATABASE_PATH.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
    return cleaned


@app.get('/')
def index() -> str:
    ensure_databases()
    return render_template('index.html')


@app.get('/health')
def health() -> Any:
    return jsonify({'ok': True})


@app.get('/api/database')
def get_ssh_database() -> Any:
    return jsonify({'servers': load_servers()})


@app.post('/api/database')
def update_ssh_database() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        servers = save_servers(payload.get('servers', []))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'message': 'Đã lưu database SSH thành công.', 'servers': servers})


@app.get('/api/web-database')
def get_web_database() -> Any:
    return jsonify({'websites': load_websites()})


@app.post('/api/web-database')
def update_web_database() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        websites = save_websites(payload.get('websites', []))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'message': 'Đã lưu database website thành công.', 'websites': websites})


@app.get('/api/solution-database')
def get_solution_database() -> Any:
    return jsonify({'solutions': load_solutions()})


@app.post('/api/solution-database')
def update_solution_database() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        solutions = save_solutions(payload.get('solutions', []))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'message': 'Đã lưu database giải pháp thành công.', 'solutions': solutions})


@app.post('/api/scan')
def scan_servers() -> Any:
    servers = load_servers()
    results = run_parallel_checks(servers, check_one_server)
    success_count = sum(1 for item in results if item['is_success'])
    return jsonify({
        'results': results,
        'summary': {
            'total': len(results),
            'success': success_count,
            'failed': len(results) - success_count,
        },
    })


@app.post('/api/web-scan')
def scan_websites() -> Any:
    websites = load_websites()
    results = run_parallel_checks(websites, check_one_website)
    success_count = sum(1 for item in results if item['is_success'])
    return jsonify({
        'results': results,
        'summary': {
            'total': len(results),
            'success': success_count,
            'failed': len(results) - success_count,
        },
    })


@app.post('/api/solution-scan')
def scan_solutions() -> Any:
    solutions = load_solutions()
    results = run_parallel_checks(solutions, check_one_solution)
    running_count = sum(1 for item in results if item['is_running'])
    login_success_count = sum(1 for item in results if item['is_success'])
    issue_count = len(results) - login_success_count
    running_services = sum(int(item.get('service_running_count', 0) or 0) for item in results)
    total_services = sum(int(item.get('service_total_count', 0) or 0) for item in results)
    return jsonify({
        'results': results,
        'summary': {
            'total': len(results),
            'running': running_count,
            'login_success': login_success_count,
            'issues': issue_count,
            'running_services': running_services,
            'total_services': total_services,
        },
    })


def run_parallel_checks(
    items: list[dict[str, Any]],
    checker: Callable[[int, dict[str, Any]], tuple[int, dict[str, Any]]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any] | None] = [None] * len(items)
    max_workers = min(6, len(items)) or 1

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(checker, index, item): index
            for index, item in enumerate(items)
        }
        for future in as_completed(future_map):
            index = future_map[future]
            try:
                _, result = future.result()
            except Exception as exc:
                item = items[index]
                result = {
                    'name': item.get('name') or item.get('ip') or item.get('domain') or f'item-{index + 1}',
                    'status': 'Lỗi xử lý',
                    'is_success': False,
                    'error': str(exc),
                }
            results[index] = result

    return [item for item in results if item is not None]


def log_server_metric_source(ip: str, source: str, message: str, metrics: dict[str, float] | None = None) -> None:
    metric_text = ''
    if metrics:
        metric_text = ' | ' + ', '.join(
            f'{key.upper()}={value:.1f}%'
            for key, value in metrics.items()
        )
    print(f'[SERVER_SCAN] {ip} | {source} | {message}{metric_text}', flush=True)


def log_solution_metric_source(name: str, source: str, message: str, metrics: dict[str, str] | None = None) -> None:
    metric_text = ''
    if metrics:
        metric_text = ' | ' + ', '.join(f'{k}={v}' for k, v in metrics.items())
    print(f'[SOLUTION_SCAN] {name} | {source} | {message}{metric_text}', flush=True)


def parse_snmp_numeric(value: Any) -> float:
    if value is None:
        raise ValueError('SNMP value is None')
    raw = str(value).strip().replace(',', '.')
    match = re.search(r'-?\d+(?:\.\d+)?', raw)
    if not match:
        raise ValueError(f'Không parse được giá trị SNMP: {raw}')
    return float(match.group(0))


def snmp_supported() -> bool:
    return all(item is not None for item in (
        SnmpEngine, CommunityData, ContextData, ObjectIdentity, ObjectType, UdpTransportTarget, getCmd, nextCmd
    ))


def snmp_get_values(host: str, community: str, port: int, timeout: int, retries: int, oid_list: list[str]) -> dict[str, Any]:
    if not snmp_supported():
        return {}
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, int(port)), timeout=float(timeout), retries=int(retries)),
        ContextData(),
        *[ObjectType(ObjectIdentity(oid)) for oid in oid_list],
    )
    error_indication, error_status, error_index, var_binds = next(iterator)
    if error_indication or error_status:
        return {}
    values: dict[str, Any] = {}
    for var_bind in var_binds:
        values[str(var_bind[0])] = var_bind[1]
    return values


def snmp_walk_values(host: str, community: str, port: int, timeout: int, retries: int, base_oid: str) -> list[tuple[str, Any]]:
    if not snmp_supported():
        return []
    results: list[tuple[str, Any]] = []
    for error_indication, error_status, error_index, var_binds in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, int(port)), timeout=float(timeout), retries=int(retries)),
        ContextData(),
        ObjectType(ObjectIdentity(base_oid)),
        lexicographicMode=False,
    ):
        if error_indication or error_status:
            return []
        for var_bind in var_binds:
            results.append((str(var_bind[0]), var_bind[1]))
    return results


def fetch_server_metrics_snmp(server: dict[str, Any]) -> dict[str, float]:
    ip = server['ip']
    community = server['snmp_community']

    if not snmp_supported():
        raise RuntimeError('pysnmp chưa được cài hoặc không khả dụng.')

    oid_values = snmp_get_values(
        host=ip,
        community=community,
        port=161,
        timeout=2,
        retries=0,
        oid_list=[
            '1.3.6.1.4.1.2021.11.11.0',
            '1.3.6.1.4.1.2021.4.5.0',
            '1.3.6.1.4.1.2021.4.6.0',
            '1.3.6.1.4.1.2021.4.15.0',
            '1.3.6.1.4.1.2021.4.14.0',
            '1.3.6.1.2.1.25.2.3.1.5.41',
            '1.3.6.1.2.1.25.2.3.1.6.41',
        ],
    )

    required_oids = [
        '1.3.6.1.4.1.2021.11.11.0',
        '1.3.6.1.4.1.2021.4.5.0',
        '1.3.6.1.4.1.2021.4.6.0',
        '1.3.6.1.4.1.2021.4.15.0',
        '1.3.6.1.4.1.2021.4.14.0',
        '1.3.6.1.2.1.25.2.3.1.5.41',
        '1.3.6.1.2.1.25.2.3.1.6.41',
    ]
    missing = [oid for oid in required_oids if oid not in oid_values]
    if missing:
        raise RuntimeError(f'SNMP thiếu OID: {", ".join(missing)}')

    cpu_idle = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.11.11.0'])
    mem_total_real = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.4.5.0'])
    mem_avail_real = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.4.6.0'])
    mem_cached = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.4.15.0'])
    mem_buffer = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.4.14.0'])
    storage_size = parse_snmp_numeric(oid_values['1.3.6.1.2.1.25.2.3.1.5.41'])
    storage_used = parse_snmp_numeric(oid_values['1.3.6.1.2.1.25.2.3.1.6.41'])

    if mem_total_real <= 0:
        raise RuntimeError('memTotalReal <= 0')
    if storage_size <= 0:
        raise RuntimeError('hrStorageSize <= 0')

    cpu_percent = max(0.0, min(100.0, 100.0 - cpu_idle))
    ram_used = mem_total_real - mem_avail_real - mem_cached - mem_buffer
    ram_percent = max(0.0, min(100.0, (ram_used / mem_total_real) * 100.0))
    storage_percent = max(0.0, min(100.0, (storage_used / storage_size) * 100.0))

    return {
        'cpu': cpu_percent,
        'ram': ram_percent,
        'storage': storage_percent,
    }


def parse_ssh_metrics(output: str) -> dict[str, float]:
    cpu_match = CPU_RE.search(output)
    ram_match = RAM_RE.search(output)
    storage_match = STORAGE_RE.search(output)

    if not (cpu_match and ram_match and storage_match):
        raise RuntimeError(f'Không parse được output SSH: {output.strip()}')

    cpu_value = parse_float_loose(cpu_match.group(1))
    ram_value = parse_float_loose(ram_match.group(1))
    storage_value = parse_float_loose(storage_match.group(1))

    if cpu_value < 0 or cpu_value > 100:
        raise RuntimeError(f'CPU parse bất thường: {cpu_value} từ output: {output.strip()}')
    if ram_value < 0 or ram_value > 100:
        raise RuntimeError(f'RAM parse bất thường: {ram_value} từ output: {output.strip()}')
    if storage_value < 0 or storage_value > 100:
        raise RuntimeError(f'Storage parse bất thường: {storage_value} từ output: {output.strip()}')

    return {
        'cpu': cpu_value,
        'ram': ram_value,
        'storage': storage_value,
    }


def fetch_server_metrics_ssh(server: dict[str, Any]) -> dict[str, float]:
    ip = server['ip']
    username = server['username']
    password = server['password']

    command = r"""sh -lc '
LC_ALL=C top -bn1 | grep -m1 "%Cpu\|Cpu(s)" ;
LC_ALL=C top -bn1 | grep -m1 "MiB Mem\|KiB Mem\|GiB Mem" ;
df -P / | awk "NR==2 {print \$5}"
'"""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=ip,
            port=22,
            username=username,
            password=password,
            timeout=8,
            auth_timeout=8,
            banner_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=20)
        _ = stdin

        stdout_text = stdout.read().decode('utf-8', errors='ignore')
        stderr_text = stderr.read().decode('utf-8', errors='ignore')
        exit_code = stdout.channel.recv_exit_status()

        if exit_code != 0 and not stdout_text.strip():
            raise RuntimeError(stderr_text.strip() or 'Lệnh SSH lấy metrics trả về lỗi.')

        lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
        if len(lines) < 3:
            raise RuntimeError(f'Output SSH không đủ dữ liệu: {stdout_text.strip()}')

        cpu_line = lines[0]
        mem_line = lines[1]
        storage_line = lines[2]

        cpu_idle_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*id', cpu_line, re.IGNORECASE)
        if not cpu_idle_match:
            raise RuntimeError(f'Không tìm được CPU idle từ top: {cpu_line}')
        cpu_idle = parse_float_loose(cpu_idle_match.group(1))
        cpu_value = max(0.0, min(100.0, 100.0 - cpu_idle))

        mem_numbers = re.findall(r'([0-9]+(?:[.,][0-9]+)?)', mem_line)
        if len(mem_numbers) < 3:
            raise RuntimeError(f'Không parse được dòng RAM từ top: {mem_line}')

        mem_total = parse_float_loose(mem_numbers[0])

        used_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s+used', mem_line, re.IGNORECASE)
        if used_match:
            mem_used = parse_float_loose(used_match.group(1))
        else:
            mem_used = parse_float_loose(mem_numbers[2])

        if mem_total <= 0:
            raise RuntimeError(f'Tổng RAM không hợp lệ: {mem_total}')
        ram_value = max(0.0, min(100.0, (mem_used / mem_total) * 100.0))

        storage_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*%', storage_line)
        if storage_match:
            storage_value = parse_float_loose(storage_match.group(1))
        else:
            storage_value = parse_float_loose(storage_line.replace('%', '').strip())
        storage_value = max(0.0, min(100.0, storage_value))

        metrics = {
            'cpu': cpu_value,
            'ram': ram_value,
            'storage': storage_value,
        }

        log_server_metric_source(ip, 'SSH_RAW', f'CPU_LINE={cpu_line} | MEM_LINE={mem_line} | STORAGE_LINE={storage_line}')
        return metrics
    finally:
        client.close()


def fetch_solution_metrics_ssh_priority(solution: dict[str, Any]) -> tuple[dict[str, str], str]:
    host = parse_solution_host(solution.get('endpoint', ''))
    if not host:
        return {}, 'invalid endpoint'

    ssh_username = solution.get('ssh_username', '')
    ssh_password = solution.get('ssh_password', '')
    if not ssh_username or not ssh_password:
        return {}, 'missing ssh credentials'

    command = r"""sh -lc '
LC_ALL=C top -bn1 | grep -m1 "%Cpu\|Cpu(s)" ;
LC_ALL=C top -bn1 | grep -m1 "MiB Mem\|KiB Mem\|GiB Mem" ;
df -P / | awk "NR==2 {print \$5}"
'"""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=22,
            username=ssh_username,
            password=ssh_password,
            timeout=8,
            auth_timeout=8,
            banner_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )

        stdin, stdout, stderr = client.exec_command(command, timeout=20)
        _ = stdin

        stdout_text = stdout.read().decode('utf-8', errors='ignore')
        stderr_text = stderr.read().decode('utf-8', errors='ignore')
        exit_code = stdout.channel.recv_exit_status()

        if exit_code != 0 and not stdout_text.strip():
            return {}, stderr_text.strip() or 'ssh metrics command failed'

        lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
        if len(lines) < 3:
            return {}, f'not enough ssh output: {stdout_text.strip()}'

        cpu_line, mem_line, storage_line = lines[0], lines[1], lines[2]

        cpu_idle_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*id', cpu_line, re.IGNORECASE)
        if not cpu_idle_match:
            return {}, f'cannot parse cpu line: {cpu_line}'
        cpu_idle = parse_float_loose(cpu_idle_match.group(1))
        cpu_percent = max(0.0, min(100.0, 100.0 - cpu_idle))

        mem_numbers = re.findall(r'([0-9]+(?:[.,][0-9]+)?)', mem_line)
        if len(mem_numbers) < 3:
            return {}, f'cannot parse mem line: {mem_line}'

        mem_total = parse_float_loose(mem_numbers[0])

        used_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s+used', mem_line, re.IGNORECASE)
        if used_match:
            mem_used = parse_float_loose(used_match.group(1))
        else:
            mem_used = parse_float_loose(mem_numbers[2])

        if mem_total <= 0:
            return {}, 'mem total <= 0'
        ram_percent = max(0.0, min(100.0, (mem_used / mem_total) * 100.0))

        storage_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*%', storage_line)
        storage_percent = parse_float_loose((storage_match.group(1) if storage_match else storage_line).replace('%', '').strip())
        storage_percent = max(0.0, min(100.0, storage_percent))

        metrics = {
            'cpu_percent': f'{cpu_percent:.1f}%',
            'ram_percent': f'{ram_percent:.1f}%',
            'storage_percent': f'{storage_percent:.1f}%',
        }
        return metrics, f'SSH metrics from {host}'
    except Exception as exc:
        return {}, str(exc)
    finally:
        client.close()


def check_one_server(index: int, server: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    ip = server['ip']
    username = server['username']

    snmp_error = ''
    ssh_error = ''

    try:
        snmp_metrics = fetch_server_metrics_snmp(server)
        log_server_metric_source(ip, 'SNMP', 'Lấy dữ liệu thành công', snmp_metrics)
        return index, {
            'ip': ip,
            'username': username,
            'metric_source': 'SNMP',
            'cpu_percent': f"{snmp_metrics['cpu']:.1f}%",
            'ram_percent': f"{snmp_metrics['ram']:.1f}%",
            'storage_percent': f"{snmp_metrics['storage']:.1f}%",
            'status': 'Lấy bằng SNMP thành công',
            'is_success': True,
            'error': '',
        }
    except Exception as exc:
        snmp_error = str(exc)
        log_server_metric_source(ip, 'SNMP', f'Lỗi: {snmp_error}')

    try:
        ssh_metrics = fetch_server_metrics_ssh(server)
        log_server_metric_source(ip, 'SSH', 'Fallback thành công', ssh_metrics)
        return index, {
            'ip': ip,
            'username': username,
            'metric_source': 'SSH',
            'cpu_percent': f"{ssh_metrics['cpu']:.1f}%",
            'ram_percent': f"{ssh_metrics['ram']:.1f}%",
            'storage_percent': f"{ssh_metrics['storage']:.1f}%",
            'status': 'SNMP lỗi, fallback SSH thành công',
            'is_success': True,
            'error': f'SNMP lỗi: {snmp_error}',
        }
    except Exception as exc:
        ssh_error = str(exc)
        log_server_metric_source(ip, 'SSH', f'Fallback lỗi: {ssh_error}')

    return index, {
        'ip': ip,
        'username': username,
        'metric_source': 'NONE',
        'cpu_percent': 'N/A',
        'ram_percent': 'N/A',
        'storage_percent': 'N/A',
        'status': 'SNMP và SSH đều lỗi',
        'is_success': False,
        'error': f'SNMP lỗi: {snmp_error}; SSH lỗi: {ssh_error}',
    }


def check_one_website(index: int, website: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    domain = normalize_website(website)['domain']
    candidate_urls = build_candidate_urls(domain)
    errors: list[str] = []

    for url in candidate_urls:
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False,
                stream=True,
                headers=DEFAULT_HEADERS,
            )
            status_code = response.status_code
            reason = (response.reason or '').strip()
            checked_url = response.url or url
            response.close()

            status_text = f'{status_code} {reason}'.strip()
            return index, {
                'domain': domain,
                'checked_url': checked_url,
                'http_status': status_text,
                'status': '200 OK' if status_code == 200 else status_text,
                'is_success': status_code == 200,
                'error': '' if status_code == 200 else status_text,
            }
        except RequestException as exc:
            errors.append(describe_request_error(exc))

    return index, {
        'domain': domain,
        'checked_url': candidate_urls[-1],
        'http_status': 'N/A',
        'status': errors[-1] if errors else 'Không truy cập được',
        'is_success': False,
        'error': '; '.join(errors),
    }


def parse_solution_host(endpoint: str) -> str:
    cleaned = (endpoint or '').strip()
    if not cleaned:
        return ''
    if cleaned.startswith(('http://', 'https://')):
        return urlparse(cleaned).hostname or ''
    if '/' in cleaned:
        cleaned = cleaned.split('/', 1)[0]
    if ':' in cleaned:
        cleaned = cleaned.split(':', 1)[0]
    return cleaned


def format_percent(value: float | int | None) -> str:
    if value is None:
        return 'N/A'
    try:
        return f"{float(value):.1f}%"
    except Exception:
        return 'N/A'


def fetch_solution_metrics_snmp(solution: dict[str, Any]) -> tuple[dict[str, str], str]:
    if not solution.get('snmp_enabled', True):
        return {}, 'SNMP disabled'
    if not snmp_supported():
        return {}, 'pysnmp not installed'

    host = parse_solution_host(solution.get('endpoint', ''))
    if not host:
        return {}, 'invalid endpoint'

    community = solution.get('snmp_community') or 'public'
    port = int(solution.get('snmp_port', 161) or 161)
    timeout = int(solution.get('snmp_timeout', 2) or 2)
    retries = int(solution.get('snmp_retries', 0) or 0)

    metrics = {'cpu_percent': 'N/A', 'ram_percent': 'N/A', 'storage_percent': 'N/A'}

    cpu_idle_values = snmp_get_values(
        host,
        community,
        port,
        timeout,
        retries,
        ['1.3.6.1.4.1.2021.11.11.0'],
    )
    try:
        cpu_idle = parse_snmp_numeric(cpu_idle_values['1.3.6.1.4.1.2021.11.11.0'])
        metrics['cpu_percent'] = format_percent(100.0 - cpu_idle)
    except Exception:
        pass

    mem_values = snmp_get_values(
        host,
        community,
        port,
        timeout,
        retries,
        [
            '1.3.6.1.4.1.2021.4.5.0',
            '1.3.6.1.4.1.2021.4.6.0',
            '1.3.6.1.4.1.2021.4.15.0',
            '1.3.6.1.4.1.2021.4.14.0',
        ],
    )
    try:
        mem_total_real = parse_snmp_numeric(mem_values['1.3.6.1.4.1.2021.4.5.0'])
        mem_avail_real = parse_snmp_numeric(mem_values['1.3.6.1.4.1.2021.4.6.0'])
        mem_cached = parse_snmp_numeric(mem_values['1.3.6.1.4.1.2021.4.15.0'])
        mem_buffer = parse_snmp_numeric(mem_values['1.3.6.1.4.1.2021.4.14.0'])
        ram_used = mem_total_real - mem_avail_real - mem_cached - mem_buffer
        if mem_total_real > 0:
            metrics['ram_percent'] = format_percent((ram_used / mem_total_real) * 100.0)
    except Exception:
        pass

    storage_values = snmp_get_values(
        host,
        community,
        port,
        timeout,
        retries,
        [
            '1.3.6.1.2.1.25.2.3.1.5.41',
            '1.3.6.1.2.1.25.2.3.1.6.41',
        ],
    )
    try:
        storage_size = parse_snmp_numeric(storage_values['1.3.6.1.2.1.25.2.3.1.5.41'])
        storage_used = parse_snmp_numeric(storage_values['1.3.6.1.2.1.25.2.3.1.6.41'])
        if storage_size > 0:
            metrics['storage_percent'] = format_percent((storage_used / storage_size) * 100.0)
    except Exception:
        pass

    if all(metrics[k] == 'N/A' for k in metrics):
        return {}, f'SNMP no metrics from {host}:{port}'
    return metrics, f'SNMP metrics from {host}:{port}'


def check_one_solution(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    cleaned = normalize_solution(solution)
    name = cleaned['name']
    endpoint = cleaned['endpoint']
    username = cleaned['username']
    password = cleaned['password']
    checkservice = cleaned['checkservice']

    snmp_metrics, snmp_note = fetch_solution_metrics_snmp(cleaned)
    if snmp_metrics:
        log_solution_metric_source(name, 'SNMP', snmp_note, snmp_metrics)

        candidate_urls = build_solution_urls(endpoint)
        web_result = None
        for url in candidate_urls:
            web_result = attempt_solution_login(name, endpoint, username, password, url, checkservice, cleaned)
            if web_result.get('is_success') or web_result.get('is_running'):
                break

        if web_result is None:
            web_result = {
                'name': name,
                'endpoint': endpoint,
                'username': username,
                'checked_url': endpoint,
                'http_status': 'N/A',
                'login_status': 'Chưa kiểm tra',
                'running_status': 'Đang chạy',
                'status': 'Đang chạy',
                'note': snmp_note,
                'is_success': False,
                'is_running': True,
                'checkservice': checkservice,
                'service_summary': 'Không kiểm tra',
                'services': [],
                'service_running_count': 0,
                'service_total_count': 0,
            }

        web_result.update(snmp_metrics)
        web_result['metric_source'] = 'SNMP'
        web_result['note'] = f"{web_result.get('note', '')} | {snmp_note}".strip(' |')
        return index, web_result

    log_solution_metric_source(name, 'SNMP', snmp_note or 'SNMP failed')

    ssh_metrics, ssh_note = fetch_solution_metrics_ssh_priority(cleaned)
    if ssh_metrics:
        log_solution_metric_source(name, 'SSH', ssh_note, ssh_metrics)

        candidate_urls = build_solution_urls(endpoint)
        web_result = None
        for url in candidate_urls:
            web_result = attempt_solution_login(name, endpoint, username, password, url, checkservice, cleaned)
            if web_result.get('is_success') or web_result.get('is_running'):
                break

        if web_result is None:
            web_result = {
                'name': name,
                'endpoint': endpoint,
                'username': username,
                'checked_url': endpoint,
                'http_status': 'N/A',
                'login_status': 'Chưa kiểm tra',
                'running_status': 'Đang chạy',
                'status': 'Đang chạy',
                'note': ssh_note,
                'is_success': False,
                'is_running': True,
                'checkservice': checkservice,
                'service_summary': 'Không kiểm tra',
                'services': [],
                'service_running_count': 0,
                'service_total_count': 0,
            }

        web_result.update(ssh_metrics)
        web_result['metric_source'] = 'SSH'
        web_result['note'] = f"{web_result.get('note', '')} | {ssh_note}".strip(' |')
        return index, web_result

    log_solution_metric_source(name, 'SSH', ssh_note or 'SSH failed')

    candidate_urls = build_solution_urls(endpoint)
    best_result = None

    for url in candidate_urls:
        result = attempt_solution_login(name, endpoint, username, password, url, checkservice, cleaned)
        if best_result is None or solution_result_score(result) > solution_result_score(best_result):
            best_result = result
        if result['is_success']:
            break

    if best_result is None:
        best_result = {
            'name': name,
            'endpoint': endpoint,
            'username': username,
            'checked_url': candidate_urls[-1] if candidate_urls else endpoint,
            'http_status': 'N/A',
            'login_status': 'Không truy cập được',
            'running_status': 'Không chạy',
            'status': 'Không truy cập được',
            'note': f'SNMP failed: {snmp_note}; SSH failed: {ssh_note}; web failed',
            'is_success': False,
            'is_running': False,
            'checkservice': checkservice,
            'service_summary': 'Không kiểm tra',
            'services': [],
            'service_running_count': 0,
            'service_total_count': 0,
            'cpu_percent': 'N/A',
            'ram_percent': 'N/A',
            'storage_percent': 'N/A',
        }

    best_result['metric_source'] = 'WEB'
    best_result['note'] = f"SNMP failed: {snmp_note}; SSH failed: {ssh_note}; {best_result.get('note', '')}".strip('; ')
    log_solution_metric_source(
        name,
        'WEB',
        best_result.get('note', 'web metrics/login result'),
        {
            'cpu_percent': best_result.get('cpu_percent', 'N/A'),
            'ram_percent': best_result.get('ram_percent', 'N/A'),
            'storage_percent': best_result.get('storage_percent', 'N/A'),
        },
    )
    return index, best_result


def build_candidate_urls(domain: str) -> list[str]:
    cleaned = domain.strip()
    if cleaned.startswith(('http://', 'https://')):
        return [cleaned]
    return [f'https://{cleaned}', f'http://{cleaned}']


def build_solution_urls(endpoint: str) -> list[str]:
    cleaned = endpoint.strip().replace(' ', '')
    if cleaned.startswith(('http://', 'https://')):
        return [cleaned]
    return [
        f'https://{cleaned}',
        f'https://{cleaned}:8443',
        f'https://{cleaned}:9443',
        f'http://{cleaned}',
        f'http://{cleaned}:8080',
    ]


def describe_request_error(exc: RequestException) -> str:
    text = str(exc).strip()
    return text or exc.__class__.__name__


def build_session() -> Session:
    session = requests.Session()
    session.verify = False
    session.headers.update(DEFAULT_HEADERS)
    return session


def score_metric_html(html: str) -> int:
    if not html:
        return 0
    score = 0
    for marker in ('cpuUsageText', 'memoryUsageText', 'ramUsageText', 'diskUsageText', 'storageUsageText'):
        if marker in html:
            score += 1
    return score


def fetch_best_solution_html(session: Session, final_url: str, fallback_url: str) -> str:
    candidates: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if url and url not in seen:
            seen.add(url)
            candidates.append(url)

    add(final_url)
    add(fallback_url)

    parsed = urlparse(final_url or fallback_url)
    if parsed.scheme and parsed.netloc:
        base = f'{parsed.scheme}://{parsed.netloc}'
        add(base)
        add(base + '/')
        add(base + '/dashboard')
        add(base + '/index')
        add(base + '/home')
        add(base + '/main')
        add(base + '/status')

    best_html = ''
    best_score = -1

    for url in candidates:
        try:
            resp = session.get(url, timeout=12, allow_redirects=True)
        except RequestException:
            continue

        content_type = (resp.headers.get('Content-Type') or '').lower()
        if 'html' not in content_type:
            continue

        html = resp.text or ''
        current_score = score_metric_html(html)

        if current_score > best_score:
            best_score = current_score
            best_html = html

        if current_score >= 3:
            return html

    return best_html


def should_try_browser_metric_fallback(metrics: dict[str, str]) -> bool:
    return metrics.get('cpu_percent') == 'N/A' or metrics.get('ram_percent') == 'N/A'


def score_metric_values(metrics: dict[str, str]) -> int:
    score = 0
    for key in ('cpu_percent', 'ram_percent', 'storage_percent'):
        if metrics.get(key) not in (None, '', 'N/A'):
            score += 1
    return score


def merge_metric_maps(primary: dict[str, str], secondary: dict[str, str]) -> dict[str, str]:
    merged = dict(primary)
    for key, value in (secondary or {}).items():
        if merged.get(key) in (None, '', 'N/A') and value not in (None, '', 'N/A'):
            merged[key] = value
    return merged


def collect_solution_candidate_urls(html: str, final_url: str, fallback_url: str) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if url and url not in seen:
            seen.add(url)
            candidates.append(url)

    add(final_url)
    add(fallback_url)

    parsed = urlparse(final_url or fallback_url)
    if parsed.scheme and parsed.netloc:
        base = f'{parsed.scheme}://{parsed.netloc}'
        for suffix in ('', '/', '/dashboard', '/index', '/home', '/main', '/status', '/system', '/monitor', '/overview'):
            add(base + suffix)

    soup = BeautifulSoup(html or '', 'html.parser')
    for tag_name, attr_name in (('a', 'href'), ('iframe', 'src'), ('frame', 'src')):
        for tag in soup.find_all(tag_name):
            target = (tag.get(attr_name) or '').strip()
            if not target or target.startswith(('javascript:', '#', 'mailto:')):
                continue
            lowered = target.lower()
            if any(word in lowered for word in ('dashboard', 'status', 'monitor', 'overview', 'system', 'home', 'main')):
                add(urljoin(final_url or fallback_url, target))

    return candidates


def fetch_best_solution_response(
    session: Session,
    html: str,
    final_url: str,
    fallback_url: str,
) -> Response | None:
    candidates = collect_solution_candidate_urls(html, final_url, fallback_url)
    best_response: Response | None = None
    best_score = -1

    for url in candidates:
        try:
            resp = session.get(url, timeout=12, allow_redirects=True)
        except RequestException:
            continue

        content_type = (resp.headers.get('Content-Type') or '').lower()
        if 'html' not in content_type:
            continue

        body = resp.text or ''
        score = score_metric_html(body)
        if looks_like_authenticated_html(body, resp.url or url):
            score += 3
        if 'engine-card' in body or 'status-badge' in body:
            score += 1

        if score > best_score:
            best_score = score
            best_response = resp

        if score >= 4:
            return resp

    return best_response


def looks_like_authenticated_html(text: str, url: str = '') -> bool:
    body = text or ''
    lowered = body.lower()
    url_lower = (url or '').lower()

    if any(marker in body for marker in ('cpuUsageText', 'memoryUsageText', 'ramUsageText', 'diskUsageText', 'storageUsageText')):
        return True
    if 'system information :: status' in lowered:
        return True
    if '/default/system/status' in url_lower:
        return True
    if 'engine-card' in body or 'status-badge' in body:
        return True
    return False


def fetch_rendered_solution_metrics(
    session: Session,
    html: str,
    final_url: str,
    fallback_url: str,
) -> tuple[dict[str, str], str]:
    if sync_playwright is None:
        return {}, ''

    candidates = collect_solution_candidate_urls(html, final_url, fallback_url)
    if not candidates:
        return {}, ''

    best_metrics: dict[str, str] = {}
    best_html = ''
    best_score = -1

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            cookie_urls: list[str] = []
            cookie_seen: set[str] = set()
            for url in candidates:
                parsed = urlparse(url)
                if not (parsed.scheme and parsed.netloc):
                    continue
                base = f'{parsed.scheme}://{parsed.netloc}'
                if base not in cookie_seen:
                    cookie_seen.add(base)
                    cookie_urls.append(base)

            cookie_payloads = []
            for cookie in session.cookies:
                for base_url in cookie_urls:
                    cookie_payloads.append({
                        'name': cookie.name,
                        'value': cookie.value,
                        'url': base_url,
                        'path': cookie.path or '/',
                    })
            if cookie_payloads:
                context.add_cookies(cookie_payloads)

            for url in candidates:
                page = context.new_page()
                try:
                    page.goto(url, wait_until='domcontentloaded', timeout=15000)
                    page.wait_for_timeout(3000)

                    page_metrics_raw = page.evaluate(
                        """() => {
                            const read = (id) => {
                                const el = document.getElementById(id);
                                if (!el) return '';
                                return (el.innerText || el.textContent || '').trim();
                            };
                            return {
                                cpu_percent: read('cpuUsageText'),
                                ram_percent: read('memoryUsageText') || read('ramUsageText'),
                                storage_percent: read('diskUsageText') || read('storageUsageText') || read('diskUsageTextWrapper')
                            };
                        }"""
                    )
                    page_html = page.content() or ''
                    page_metrics = {
                        'cpu_percent': normalize_percent_text((page_metrics_raw or {}).get('cpu_percent', '')),
                        'ram_percent': normalize_percent_text((page_metrics_raw or {}).get('ram_percent', '')),
                        'storage_percent': normalize_percent_text((page_metrics_raw or {}).get('storage_percent', '')),
                    }
                    page_metrics = merge_metric_maps(page_metrics, extract_solution_metrics(page_html))

                    current_score = score_metric_values(page_metrics)
                    if current_score > best_score:
                        best_score = current_score
                        best_metrics = page_metrics
                        best_html = page_html

                    for frame in page.frames:
                        if frame == page.main_frame:
                            continue
                        try:
                            frame_html = frame.content() or ''
                        except Exception:
                            continue
                        frame_metrics = extract_solution_metrics(frame_html)
                        try:
                            frame_metrics_raw = frame.evaluate(
                                """() => {
                                    const read = (id) => {
                                        const el = document.getElementById(id);
                                        if (!el) return '';
                                        return (el.innerText || el.textContent || '').trim();
                                    };
                                    return {
                                        cpu_percent: read('cpuUsageText'),
                                        ram_percent: read('memoryUsageText') || read('ramUsageText'),
                                        storage_percent: read('diskUsageText') || read('storageUsageText') || read('diskUsageTextWrapper')
                                    };
                                }"""
                            )
                            frame_metrics = merge_metric_maps(frame_metrics, {
                                'cpu_percent': normalize_percent_text((frame_metrics_raw or {}).get('cpu_percent', '')),
                                'ram_percent': normalize_percent_text((frame_metrics_raw or {}).get('ram_percent', '')),
                                'storage_percent': normalize_percent_text((frame_metrics_raw or {}).get('storage_percent', '')),
                            })
                        except Exception:
                            pass

                        frame_score = score_metric_values(frame_metrics)
                        if frame_score > best_score:
                            best_score = frame_score
                            best_metrics = frame_metrics
                            best_html = frame_html
                except PlaywrightTimeoutError:
                    pass
                except Exception:
                    pass
                finally:
                    page.close()

            browser.close()
    except Exception:
        return {}, ''

    return best_metrics, best_html


def attempt_solution_login(
    name: str,
    endpoint: str,
    username: str,
    password: str,
    url: str,
    checkservice: bool,
    solution: dict[str, Any],
) -> dict[str, Any]:
    session = build_session()

    try:
        response = session.get(url, timeout=12, allow_redirects=True)
    except RequestException as exc:
        return {
            'name': name,
            'endpoint': endpoint,
            'username': username,
            'checked_url': url,
            'http_status': 'N/A',
            'login_status': 'Không truy cập được',
            'running_status': 'Không chạy',
            'status': 'Không truy cập được',
            'note': describe_request_error(exc),
            'is_success': False,
            'is_running': False,
            'checkservice': checkservice,
            'service_summary': 'N/A',
            'services': [],
            'cpu_percent': 'N/A',
            'ram_percent': 'N/A',
            'storage_percent': 'N/A',
            'service_running_count': 0,
            'service_total_count': 0,
        }

    initial_status = response.status_code
    initial_status_text = format_status(response)
    checked_url = response.url or url
    is_running = initial_status < 500
    running_status = 'Đang chạy' if is_running else f'Lỗi dịch vụ {initial_status}'
    content_type = (response.headers.get('Content-Type') or '').lower()

    if initial_status in (401, 403) or 'www-authenticate' in response.headers:
        auth_result = try_basic_auth(session, url, username, password)
        if auth_result is not None:
            return finalize_solution_result(
                name=name,
                endpoint=endpoint,
                username=username,
                fallback_url=checked_url,
                fallback_status=initial_status_text,
                fallback_running=is_running,
                response=auth_result,
                success_note='Đăng nhập thành công bằng HTTP Basic Auth.',
                failure_note='Trang yêu cầu xác thực HTTP nhưng tài khoản chưa đăng nhập được.',
                checkservice=checkservice,
                session=session,
            )

    if 'html' in content_type:
        form_info = extract_login_form(response.text, checked_url)
        if form_info is not None:
            try:
                submit_response = submit_login_form(session, form_info, checked_url, username, password)
            except RequestException as exc:
                return {
                    'name': name,
                    'endpoint': endpoint,
                    'username': username,
                    'checked_url': checked_url,
                    'http_status': initial_status_text,
                    'login_status': 'Không đăng nhập được',
                    'running_status': running_status,
                    'status': 'Đang chạy nhưng login lỗi',
                    'note': describe_request_error(exc),
                    'is_success': False,
                    'is_running': is_running,
                    'checkservice': checkservice,
                    'service_summary': 'N/A',
                    'services': [],
                    'cpu_percent': 'N/A',
                    'ram_percent': 'N/A',
                    'storage_percent': 'N/A',
                    'service_running_count': 0,
                    'service_total_count': 0,
                }

            return finalize_solution_result(
                name=name,
                endpoint=endpoint,
                username=username,
                fallback_url=checked_url,
                fallback_status=initial_status_text,
                fallback_running=is_running,
                response=submit_response,
                success_note='Đăng nhập form thành công.',
                failure_note='Đăng nhập form chưa thành công hoặc hệ thống dùng xác thực đặc biệt.',
                checkservice=checkservice,
                session=session,
            )

        if initial_status < 400:
            return {
                'name': name,
                'endpoint': endpoint,
                'username': username,
                'checked_url': checked_url,
                'http_status': initial_status_text,
                'login_status': 'Không tìm thấy form đăng nhập',
                'running_status': running_status,
                'status': 'Đang chạy',
                'note': 'Trang có phản hồi nhưng tool chưa nhận diện được form login.',
                'is_success': False,
                'is_running': is_running,
                'checkservice': checkservice,
                'service_summary': 'Không kiểm tra',
                'services': [],
                'cpu_percent': 'N/A',
                'ram_percent': 'N/A',
                'storage_percent': 'N/A',
                'service_running_count': 0,
                'service_total_count': 0,
            }

    return {
        'name': name,
        'endpoint': endpoint,
        'username': username,
        'checked_url': checked_url,
        'http_status': initial_status_text,
        'login_status': 'Không đăng nhập được',
        'running_status': running_status,
        'status': 'Đang chạy' if is_running else 'Không chạy',
        'note': 'Có phản hồi HTTP nhưng chưa tự động login được.',
        'is_success': False,
        'is_running': is_running,
        'checkservice': checkservice,
        'service_summary': 'Không kiểm tra',
        'services': [],
        'cpu_percent': 'N/A',
        'ram_percent': 'N/A',
        'storage_percent': 'N/A',
        'service_running_count': 0,
        'service_total_count': 0,
    }


def try_basic_auth(session: Session, url: str, username: str, password: str) -> Response | None:
    try:
        return session.get(
            url,
            timeout=12,
            allow_redirects=True,
            auth=HTTPBasicAuth(username, password),
        )
    except RequestException:
        return None


def finalize_solution_result(
    *,
    name: str,
    endpoint: str,
    username: str,
    fallback_url: str,
    fallback_status: str,
    fallback_running: bool,
    response: Response,
    success_note: str,
    failure_note: str,
    checkservice: bool,
    session: Session | None = None,
) -> dict[str, Any]:
    status_text = format_status(response)
    final_url = response.url or fallback_url
    final_running = response.status_code < 500
    is_running = fallback_running or final_running
    running_status = 'Đang chạy' if is_running else 'Không chạy'
    login_success = looks_like_logged_in(response)

    best_html = response.text or ''
    best_response = response

    if session is not None:
        probed_response = fetch_best_solution_response(session, best_html, final_url, fallback_url)
        if probed_response is not None:
            probed_html = probed_response.text or ''
            if score_metric_html(probed_html) >= score_metric_html(best_html):
                best_html = probed_html
                best_response = probed_response
                final_url = probed_response.url or final_url
                status_text = format_status(probed_response)
                is_running = is_running or (probed_response.status_code < 500)
                running_status = 'Đang chạy' if is_running else 'Không chạy'
            if not login_success and looks_like_authenticated_html(probed_html, probed_response.url or final_url):
                login_success = True

    services: list[dict[str, str]] = []
    service_summary = 'Không kiểm tra'
    metrics = {
        'cpu_percent': 'N/A',
        'ram_percent': 'N/A',
        'storage_percent': 'N/A',
        'service_running_count': 0,
        'service_total_count': 0,
    }

    if login_success:
        if session is not None:
            discovered_html = fetch_best_solution_html(session, final_url, fallback_url)
            if score_metric_html(discovered_html) > score_metric_html(best_html):
                best_html = discovered_html

        static_metrics = extract_solution_metrics(best_html)
        metrics.update(static_metrics)

        if session is not None and should_try_browser_metric_fallback(metrics):
            rendered_metrics, rendered_html = fetch_rendered_solution_metrics(
                session=session,
                html=best_html or (response.text or ''),
                final_url=final_url,
                fallback_url=fallback_url,
            )
            metrics.update(merge_metric_maps(metrics, rendered_metrics))
            if score_metric_values(rendered_metrics) > score_metric_values(static_metrics) and rendered_html:
                best_html = rendered_html

        if checkservice:
            services = extract_services(best_html)
            if not services:
                services = extract_services(best_response.text or '')
            service_summary = summarize_services(services)
    elif checkservice:
        service_summary = 'Chưa login'

    service_running_count = sum(
        1 for item in services
        if item.get('status', '').strip().lower() == 'running'
    )
    service_total_count = len(services)
    display_running_status = service_summary if service_total_count else 'Đang chạy'
    metrics['service_running_count'] = service_running_count
    metrics['service_total_count'] = service_total_count

    if login_success:
        return {
            'name': name,
            'endpoint': endpoint,
            'username': username,
            'checked_url': final_url,
            'http_status': status_text,
            'login_status': 'Đăng nhập thành công',
            'running_status': display_running_status,
            'status': 'Đang chạy',
            'note': success_note,
            'is_success': True,
            'is_running': True,
            'checkservice': checkservice,
            'service_summary': service_summary,
            'services': services,
            **metrics,
        }

    return {
        'name': name,
        'endpoint': endpoint,
        'username': username,
        'checked_url': final_url,
        'http_status': status_text or fallback_status,
        'login_status': 'Không đăng nhập được',
        'running_status': running_status,
        'status': 'Đang chạy' if is_running else 'Không chạy',
        'note': failure_note,
        'is_success': False,
        'is_running': is_running,
        'checkservice': checkservice,
        'service_summary': service_summary,
        'services': [],
        **metrics,
    }


def extract_solution_metrics(html: str) -> dict[str, str]:
    html = html or ''
    soup = BeautifulSoup(html, 'html.parser')
    return {
        'cpu_percent': extract_metric_from_ids(html, soup, ['cpuUsageText']),
        'ram_percent': extract_metric_from_ids(html, soup, ['memoryUsageText', 'ramUsageText']),
        'storage_percent': extract_metric_from_ids(html, soup, ['diskUsageText', 'storageUsageText', 'diskUsageTextWrapper']),
    }


def extract_metric_from_ids(html: str, soup: BeautifulSoup, ids: list[str]) -> str:
    for element_id in ids:
        value = extract_percent_from_dom_id(soup, element_id)
        if value != 'N/A':
            return value

        value = extract_percent_from_exact_id_block(html, element_id)
        if value != 'N/A':
            return value

        value = extract_percent_from_js_assignment(html, element_id)
        if value != 'N/A':
            return value

    return 'N/A'


def extract_percent_from_dom_id(soup: BeautifulSoup, element_id: str) -> str:
    node = soup.find(id=element_id)
    if node is None:
        return 'N/A'

    own_text_parts: list[str] = []
    for child in node.children:
        if isinstance(child, str):
            own_text_parts.append(child)
    own_text = ' '.join(part.strip() for part in own_text_parts if part and part.strip())
    value = normalize_percent_text(own_text)
    if value != 'N/A':
        return value

    value = normalize_percent_text(node.get_text(' ', strip=True))
    if value != 'N/A':
        return value

    for descendant in node.find_all(True):
        value = normalize_percent_text(descendant.get_text(' ', strip=True))
        if value != 'N/A':
            return value

    return 'N/A'


def extract_percent_from_exact_id_block(html: str, element_id: str) -> str:
    if not html:
        return 'N/A'

    escaped_id = re.escape(element_id)
    patterns = [
        re.compile(
            rf"<(?P<tag>[a-zA-Z0-9:_-]+)[^>]*\bid=[\"']{escaped_id}[\"'][^>]*>(?P<content>.*?)</(?P=tag)>",
            re.IGNORECASE | re.DOTALL,
        ),
        re.compile(
            rf"<(?P<tag>[a-zA-Z0-9:_-]+)[^>]*\bid=[\"']{escaped_id}[\"'][^>]*>(?P<content>[^<]*?)<",
            re.IGNORECASE | re.DOTALL,
        ),
    ]

    for pattern in patterns:
        for match in pattern.finditer(html):
            content = match.group('content') or ''
            value = normalize_percent_text(strip_style_and_script_blocks(content))
            if value != 'N/A':
                return value

    return 'N/A'


def extract_percent_from_js_assignment(html: str, element_id: str) -> str:
    if not html:
        return 'N/A'

    escaped_id = re.escape(element_id)
    patterns = [
        re.compile(
            rf"getElementById\([\"']{escaped_id}[\"']\)\.(?:innerText|textContent|innerHTML)\s*=\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\$\([\"']#{escaped_id}[\"']\)\.(?:text|html|val)\(\s*[\"']([^\"']+)[\"']\s*\)",
            re.IGNORECASE,
        ),
        re.compile(
            rf"[\"']{escaped_id}[\"']\s*:\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
    ]

    for pattern in patterns:
        match = pattern.search(html)
        if match:
            value = normalize_percent_text(match.group(1))
            if value != 'N/A':
                return value

    return 'N/A'


def strip_style_and_script_blocks(text: str) -> str:
    cleaned = re.sub(r'<script\b[^>]*>.*?</script>', ' ', text or '', flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r'<style\b[^>]*>.*?</style>', ' ', cleaned, flags=re.IGNORECASE | re.DOTALL)
    return cleaned


def normalize_percent_text(raw_text: str) -> str:
    text = html_lib.unescape(raw_text or '')
    if not text:
        return 'N/A'

    text = BeautifulSoup(text, 'html.parser').get_text(' ', strip=True)
    text = html_lib.unescape(' '.join(text.split()))
    if not text:
        return 'N/A'

    match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*%', text)
    if not match:
        return 'N/A'
    return f"{parse_float_loose(match.group(1)):.1f}%"


def extract_services(html: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(html or '', 'html.parser')
    services: list[dict[str, str]] = []

    for card in soup.select('div.engine-card'):
        title_tag = card.select_one('div.engine-title')
        badge_tag = card.select_one('div.status-badge')

        name = title_tag.get_text(' ', strip=True) if title_tag else ''
        status = ''
        if badge_tag:
            status = (badge_tag.get('title') or badge_tag.get_text(' ', strip=True)).strip()

        if name:
            services.append({
                'name': name,
                'status': status or 'Unknown',
            })

    return services


def summarize_services(services: list[dict[str, str]]) -> str:
    if not services:
        return '0/0 service đang chạy'
    running = sum(
        1 for item in services
        if item.get('status', '').strip().lower() == 'running'
    )
    return f'{running}/{len(services)} service đang chạy'


def format_status(response: Response) -> str:
    reason = (response.reason or '').strip()
    return f'{response.status_code} {reason}'.strip()


def extract_login_form(html: str, base_url: str) -> dict[str, Any] | None:
    soup = BeautifulSoup(html, 'html.parser')
    candidate_forms: list[tuple[int, Any]] = []

    for form in soup.find_all('form'):
        score = 0
        inputs = form.find_all('input')

        for input_tag in inputs:
            input_type = (input_tag.get('type') or 'text').lower()
            field_name = (input_tag.get('name') or '').strip().lower()
            if input_type == 'password' or any(hint in field_name for hint in PASSWORD_HINTS):
                score += 4
            if any(hint in field_name for hint in USERNAME_HINTS):
                score += 2
            if input_type == 'hidden':
                score += 1

        form_text = ' '.join(filter(None, [form.get('id', ''), form.get('name', ''), form.get('action', '')]))
        if any(word in str(form_text).lower() for word in LOGIN_WORDS):
            score += 2

        if score > 0:
            candidate_forms.append((score, form))

    if not candidate_forms:
        return None

    candidate_forms.sort(key=lambda item: item[0], reverse=True)
    form = candidate_forms[0][1]
    method = (form.get('method') or 'post').strip().lower()
    action = urljoin(base_url, form.get('action') or base_url)

    fields: dict[str, str] = {}
    username_field = None
    password_field = None

    for element in form.find_all(['input', 'button', 'textarea', 'select']):
        name = (element.get('name') or '').strip()
        if not name:
            continue

        input_type = (element.get('type') or '').lower()
        value = element.get('value') or ''
        lowered = name.lower()

        if input_type == 'password' or any(hint in lowered for hint in PASSWORD_HINTS):
            password_field = password_field or name
            continue

        if any(hint in lowered for hint in USERNAME_HINTS) and input_type not in ('hidden', 'checkbox', 'radio'):
            username_field = username_field or name
            continue

        if input_type in ('hidden', 'checkbox', 'radio'):
            fields[name] = value
            continue

        if input_type in ('submit', 'button'):
            if value:
                fields[name] = value
            continue

        if input_type not in ('file', 'image') and value:
            fields[name] = value

    if password_field is None:
        return None

    if username_field is None:
        for item in form.find_all('input', attrs={'type': ['text', 'email', 'search', 'tel']}):
            field_name = (item.get('name') or '').strip()
            if field_name:
                username_field = field_name
                break

    if username_field is None:
        return None

    return {
        'method': method,
        'action': action,
        'fields': fields,
        'username_field': username_field,
        'password_field': password_field,
    }


def submit_login_form(
    session: Session,
    form_info: dict[str, Any],
    referer_url: str,
    username: str,
    password: str,
) -> Response:
    payload = dict(form_info['fields'])
    payload[form_info['username_field']] = username
    payload[form_info['password_field']] = password
    headers = {'Referer': referer_url}

    if form_info['method'] == 'get':
        return session.get(
            form_info['action'],
            params=payload,
            headers=headers,
            timeout=12,
            allow_redirects=True,
        )

    return session.post(
        form_info['action'],
        data=payload,
        headers=headers,
        timeout=12,
        allow_redirects=True,
    )


def looks_like_logged_in(response: Response) -> bool:
    if response.status_code >= 400:
        return False

    text = response.text or ''
    lowered = text.lower()
    url_lower = (response.url or '').lower()

    if looks_like_authenticated_html(text, response.url or ''):
        return True

    if PASSWORD_INPUT_RE.search(text):
        return False

    if any(word in url_lower for word in ('/login', '/signin', '/auth', '/authenticate')) and any(word in lowered for word in LOGIN_WORDS):
        return False

    return True


def solution_result_score(result: dict[str, Any]) -> int:
    if result.get('is_success'):
        return 3
    if result.get('is_running'):
        return 2
    if result.get('http_status') not in (None, '', 'N/A'):
        return 1
    return 0


if __name__ == '__main__':
    ensure_databases()
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '5000'))
    app.run(host=host, port=port, debug=False)