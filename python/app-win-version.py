#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 导入基础模块
import os, sys, subprocess

# 强制安装依赖
subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "cryptography"])

# 导入其他依赖
import requests, re, ssl, json, time, base64, secrets, shutil, signal, threading
from typing import Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# ======================== .env 加载 ========================
def _load_dotenv():
    env_file = os.path.join(os.getcwd(), '.env')
    if not os.path.exists(env_file):
        return
    with open(env_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, value = line.partition('=')
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
_load_dotenv()

# ======================== 环境变量定义 ========================
UPLOAD_URL = os.environ.get('UPLOAD_URL', '')     # 节点或订阅自动上传到订阅器的地址，需填写部署Merge-sub项目的首页，例如 https://merge.xxx.com
PROJECT_URL = os.environ.get('PROJECT_URL', '')   # 项目地址，例如：https://example.com,开启自动保活时或上传节点订阅需要填写
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() in ('true', 'yes') # 是否开启自动保活，true开启，false关闭，默认关闭
YT_WARPOUT = os.environ.get('YT_WARPOUT', 'false').lower() in ('true', 'yes')   # 是否开启youtube走warp出站，true开启，false关闭，默认关闭
FILE_PATH = os.environ.get('FILE_PATH', '.cache')  # 运行时文件存储路径，默认当前目录下的.cache文件夹
SUB_PATH = os.environ.get('SUB_PATH', 'sub')       # 获取订阅节点的token
UUID = os.environ.get('UUID', '0a6568ff-ea3c-4271-9020-450560e10d63') # 节点和哪吒v1使用的UUID，默认固定值，建议自行生成一个唯一的UUID
ARGO_PORT = int(os.environ.get('ARGO_PORT', '8001')) # 隧道端口,使用固定隧道token时需要在cloudflare里设置和这里一致
ARGO_DOMAIN = os.environ.get('ARGO_DOMAIN', '')  # 固定隧道域名，留空将使用临时隧道
ARGO_AUTH = os.environ.get('ARGO_AUTH', '')      # 固定密钥token或json，留空将使用临时隧道
S5_PORT = os.environ.get('S5_PORT', '')          # SOCKS5 端口，默认不启用
HY2_PORT = os.environ.get('HY2_PORT', '')        # Hysteria2 端口，默认不启用
TUIC_PORT = os.environ.get('TUIC_PORT', '')      # TUIC 端口，默认不启用
ANYTLS_PORT = os.environ.get('ANYTLS_PORT', '')  # AnyTLS 端口，默认不启用
REALITY_PORT = os.environ.get('REALITY_PORT', '') # Reality 端口，默认不启用
CFIP = os.environ.get('CFIP', 'spring.io')       # argo节点的优选域名或优选ip
CFPORT = int(os.environ.get('CFPORT', '443'))    # argo节点的优选域名或优选ip对应的端口
PORT = int(os.environ.get('PORT', '3000'))       # HTTP服务器端口，默认3000,用于提供订阅和前端伪装页
NAME = os.environ.get('NAME', '')               # 节点名称前缀
CHAT_ID = os.environ.get('CHAT_ID', '')         # Telegram机器人ID，例如1001234567890，关闭了log建议填写推送
BOT_TOKEN = os.environ.get('BOT_TOKEN', '')     # Telegram机器人Token，例如123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
DISABLE_ARGO = os.environ.get('DISABLE_ARGO', 'false').lower() in ('true', 'yes') # 是否禁用Argo隧道，true/yes禁用，false/no启用，默认启用
SHOW_LOG = os.environ.get('SHOW_LOG', 'true').lower() not in ('false', 'disable', 'no')  # 是否显示日志输出，true/yes显示，false/disable/no屏蔽，默认显示
# ==============================================================

# 控制日志输出
def log(*args, **kwargs):
    if SHOW_LOG:
        kwargs.setdefault('flush', True)
        print(*args, **kwargs)

# 全局变量
ROOT = os.getcwd()
runtimeFilePath = os.path.join(ROOT, FILE_PATH)
singBoxConfigPath = os.path.join(runtimeFilePath, 'config.json')
bootLogPath = os.path.join(runtimeFilePath, 'boot.log')
subPath = os.path.join(runtimeFilePath, 'sub.txt')
listPath = os.path.join(runtimeFilePath, 'list.txt')
keypairPath = os.path.join(runtimeFilePath, 'keypair.properties')
subscribePath = '/' + SUB_PATH.lstrip('/')

privateKey = ''
publicKey = ''

IS_WINDOWS = os.name == 'nt'
# ======================== 辅助函数 ========================

def is_valid_port(port):
    try:
        if port is None or port == '':
            return False
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

# ======================== 文件清理 ========================

paths_to_delete = ['boot.log', 'list.txt', 'config.json', 'config.yaml', 'cert.pem', 'private.key', 'tunnel.json', 'tunnel.yml']

def cleanup_old_files():
    for file in paths_to_delete:
        filepath = os.path.join(FILE_PATH, file)
        try:
            if os.path.exists(filepath):
                os.unlink(filepath)
        except:
            pass
    
    tmp_dir = os.path.join(ROOT, '.tmp')
    if os.path.exists(tmp_dir):
        try:
            shutil.rmtree(tmp_dir)
        except:
            pass

def cleanup_files(keep_sub=False):
    keep_files = set(['keypair.properties'])
    if keep_sub:
        keep_files.add('sub.txt')
    
    if os.path.exists(runtimeFilePath):
        try:
            for file in os.listdir(runtimeFilePath):
                if file in keep_files:
                    continue
                filepath = os.path.join(runtimeFilePath, file)
                try:
                    if os.path.isdir(filepath):
                        shutil.rmtree(filepath)
                    else:
                        os.unlink(filepath)
                except:
                    pass
        except Exception as e:
            log(f'Cleanup failed: {e}')
    
    tmp_dir = os.path.join(ROOT, '.tmp')
    if os.path.exists(tmp_dir):
        try:
            shutil.rmtree(tmp_dir)
        except:
            pass

def clear_console():
    os.system('clear' if os.name == 'posix' else 'cls')

def delete_nodes():
    try:
        if not UPLOAD_URL:
            return
        if not os.path.exists(subPath):
            return
        
        try:
            with open(subPath, 'r') as f:
                file_content = f.read()
        except:
            return
        
        decoded = base64.b64decode(file_content).decode('utf-8')
        nodes = [line for line in decoded.split('\n') 
                 if re.search(r'(vless|vmess|trojan|hysteria2|tuic):\/\/', line)]
        
        if not nodes:
            return
        
        try:
            requests.post(f'{UPLOAD_URL}/api/delete-nodes',
                         json={'nodes': nodes},
                         timeout=30)
        except:
            pass
    except Exception:
        pass

# ======================== Argo 隧道配置 ========================

def argo_type():
    if DISABLE_ARGO:
        log("DISABLE_ARGO is set to true, disable argo tunnel")
        return
    
    if not ARGO_AUTH or not ARGO_DOMAIN:
        log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnel")
        return
    
    if 'TunnelSecret' in ARGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(ARGO_AUTH)
        
        tunnel_id_match = re.search(r'"TunnelID":\s*"([^"]+)"', ARGO_AUTH)
        tunnel_id = tunnel_id_match.group(1) if tunnel_id_match else ""
        
        tunnel_yaml = f"""tunnel: {tunnel_id}
credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as f:
            f.write(tunnel_yaml)
    else:
        log(f"Using token connect to tunnel, please set {ARGO_PORT} in cloudflare")


def cloudflared_payload():
    if DISABLE_ARGO:
        return None
    if ARGO_AUTH and ARGO_DOMAIN:
        if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
            return json.dumps({
                'args': ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate',
                        '--protocol', 'http2', 'run', '--token', ARGO_AUTH]
            })
        elif 'TunnelSecret' in ARGO_AUTH:
            return json.dumps({
                'args': ['tunnel', '--edge-ip-version', 'auto', '--config',
                        os.path.join(FILE_PATH, 'tunnel.yml'), 'run']
            })
    return json.dumps({
        'args': [
            'tunnel', '--edge-ip-version', 'auto', '--no-autoupdate',
            '--protocol', 'http2', '--logfile', bootLogPath,
            '--loglevel', 'info', '--url', f'http://localhost:{ARGO_PORT}'
        ]
    })


# ======================== 首次运行自动下载官方 Windows 二进制 ========================
def _download_file(url, dest):
    log(f"Downloading -> {dest}")
    total = 0
    with requests.get(url, stream=True, timeout=(15, 300)) as r:
        log(f"HTTP {r.status_code}, size {r.headers.get('Content-Length', '?')} bytes")
        r.raise_for_status()
        with open(dest, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024 * 256):
                f.write(chunk)
                total += len(chunk)
                if total % (4 * 1024 * 1024) < 1024 * 256:
                    log(f"  downloaded {total // (1024 * 1024)} MB...")
    log(f"Download complete: {dest} ({total} bytes)")

SINGBOX_VER = '1.14.4'
GH_WEB = 'https://github.com'

def ensure_windows_binaries():
    import zipfile, traceback
    try:
        os.makedirs(runtimeFilePath, exist_ok=True)
        # Migrate previously downloaded binaries to their new names (no re-download)
        for old_name, new_name in (('sing-box.exe', 'web.exe'), ('cloudflared.exe', 'bot.exe')):
            old_path = os.path.join(runtimeFilePath, old_name)
            new_path = os.path.join(runtimeFilePath, new_name)
            if not os.path.isfile(new_path) and os.path.isfile(old_path):
                try:
                    os.rename(old_path, new_path)
                    log(f'renamed {old_name} -> {new_name}')
                except Exception:
                    pass
        sbx = os.path.join(runtimeFilePath, 'web.exe')
        if not os.path.isfile(sbx):
            zip_name = f'sing-box-{SINGBOX_VER}-windows-amd64.zip'
            zip_url = f'{GH_WEB}/SagerNet/sing-box/releases/download/v{SINGBOX_VER}/{zip_name}'
            log(f'step 1/2: downloading sing-box v{SINGBOX_VER} from {zip_url}')
            zip_path = os.path.join(runtimeFilePath, zip_name)
            _download_file(zip_url, zip_path)
            with zipfile.ZipFile(zip_path) as z:
                for member in z.namelist():
                    leaf = member.replace('\\', '/').rstrip('/').split('/')[-1]
                    if leaf in ('sing-box.exe', 'libcronet.dll'):
                        save_as = 'web.exe' if leaf == 'sing-box.exe' else leaf
                        with z.open(member) as fin, open(os.path.join(runtimeFilePath, save_as), 'wb') as fout:
                            shutil.copyfileobj(fin, fout)
                        log(f'extracted {save_as}')
            try:
                os.unlink(zip_path)
            except Exception:
                pass
        else:
            log('step 1/2: web.exe already present')
        cf = os.path.join(runtimeFilePath, 'bot.exe')
        if not DISABLE_ARGO and not os.path.isfile(cf):
            cf_url = f'{GH_WEB}/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe'
            log(f'step 2/2: downloading cloudflared from {cf_url}')
            _download_file(cf_url, cf)
        else:
            log('step 2/2: bot.exe already present or argo disabled')
        log('binaries ready')
    except Exception:
        traceback.print_exc()
        raise

# ======================== Windows .exe 服务（替代 c-shared 动态库） ========================
# sing-box / cloudflared 官方 Windows 版都只有 .exe，没有可加载的 .dll，
# 所以用子进程方式启动（start/stop 接口与服务管理代码对应）。

def locate_binary(env_name, exe_name):
    """查找顺序：环境变量 > 运行时目录(.cache) > 脚本所在目录 > 当前目录 > PATH"""
    candidates = []
    if os.environ.get(env_name):
        candidates.append(os.environ[env_name])
    candidates += [
        os.path.join(runtimeFilePath, exe_name),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), exe_name),
        os.path.join(os.getcwd(), exe_name),
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            return cand
    return shutil.which(exe_name)

class ExeService:
    def __init__(self, name, exe_path, args, cwd='.'):
        self.name = name
        self.exe_path = exe_path
        self.args = args
        self.cwd = cwd
        self.proc = None
    def start(self):
        if not self.exe_path:
            raise FileNotFoundError(f"{self.name}: executable not found")
        log(f"Starting {self.name}: {self.exe_path} {' '.join(self.args)}")
        self.proc = subprocess.Popen(
            [self.exe_path] + self.args, cwd=self.cwd,
            stdout=None if SHOW_LOG else subprocess.DEVNULL,
            stderr=None if SHOW_LOG else subprocess.DEVNULL)
    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try: self.proc.kill()
                except Exception: pass
        log(f"{self.name} stopped")

# ======================== Reality X25519 密钥对 ========================

def clamp_x25519_private_key(private_key: bytes) -> bytes:
    if len(private_key) != 32:
        raise ValueError('X25519 private key must be 32 bytes')
    key = bytearray(private_key)
    key[0] &= 248
    key[31] &= 127
    key[31] |= 64
    return bytes(key)

def base64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def decode_base64url_no_padding(value: str) -> bytes:
    value = value.strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('invalid base64url value')
    padding = '=' * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)

def derive_x25519_public_key(private_key_bytes: bytes) -> bytes:
    private_key_bytes = clamp_x25519_private_key(private_key_bytes)
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def generate_reality_keypair():
    private_bytes = clamp_x25519_private_key(secrets.token_bytes(32))
    public_bytes = derive_x25519_public_key(private_bytes)
    return {
        'privateKey': base64url_no_padding(private_bytes),
        'publicKey': base64url_no_padding(public_bytes)
    }

def write_keypair(private_key_value: str, public_key_value: str):
    os.makedirs(os.path.dirname(keypairPath), exist_ok=True)
    with open(keypairPath, 'w') as f:
        f.write(f'PrivateKey: {private_key_value}\nPublicKey: {public_key_value}\n')

def generate_or_load_keypair():
    global privateKey, publicKey
    
    if os.path.exists(keypairPath):
        with open(keypairPath, 'r') as f:
            content = f.read()
        private_match = re.search(r'PrivateKey:\s*(.*)', content)
        public_match = re.search(r'PublicKey:\s*(.*)', content)
        if private_match and public_match:
            try:
                loaded_private = decode_base64url_no_padding(private_match.group(1))
                loaded_public = decode_base64url_no_padding(public_match.group(1))
                normalized_private = clamp_x25519_private_key(loaded_private)
                derived_public = derive_x25519_public_key(normalized_private)
                if len(loaded_public) != 32 or derived_public != loaded_public:
                    raise ValueError('stored public key does not match private key')
                privateKey = base64url_no_padding(normalized_private)
                publicKey = base64url_no_padding(derived_public)
                if privateKey != private_match.group(1).strip() or publicKey != public_match.group(1).strip():
                    write_keypair(privateKey, publicKey)
                log(f'Private Key: {privateKey}')
                log(f'Public Key: {publicKey}')
                return
            except Exception as e:
                log(f'Invalid Reality keypair, regenerating: {e}')
    
    pair = generate_reality_keypair()
    privateKey = pair['privateKey']
    publicKey = pair['publicKey']
    write_keypair(privateKey, publicKey)
    log(f'Private Key: {privateKey}')
    log(f'Public Key: {publicKey}')

# ======================== TLS 证书 ========================

FALLBACK_EC_KEY = '''-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49
AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa
/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==
-----END EC PRIVATE KEY-----
'''

FALLBACK_CERT = '''-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy
MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h
aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR
BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+
eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==
-----END CERTIFICATE-----
'''

def ensure_tls_certificates(cert_path: str, key_path: str):
    if os.path.exists(cert_path) and os.path.exists(key_path) and tls_certificate_pair_is_valid(cert_path, key_path):
        return
    
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    temp_cert_path = f'{cert_path}.tmp'
    temp_key_path = f'{key_path}.tmp'
    for temp_path in (temp_cert_path, temp_key_path):
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except:
            pass
    
    try:
        subprocess.run(['openssl', 'version'], capture_output=True, check=True)
        subprocess.run([
            'openssl', 'ecparam', '-genkey', '-name', 'prime256v1', '-out', temp_key_path
        ], capture_output=True, check=True)
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-days', '3650',
            '-key', temp_key_path, '-out', temp_cert_path, '-subj', '/CN=bing.com'
        ], capture_output=True, check=True)
        if tls_certificate_pair_is_valid(temp_cert_path, temp_key_path):
            os.replace(temp_cert_path, cert_path)
            os.replace(temp_key_path, key_path)
            return
    except:
        pass
    
    for temp_path in (temp_cert_path, temp_key_path):
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except:
            pass
    
    with open(key_path, 'w') as f:
        f.write(FALLBACK_EC_KEY)
    with open(cert_path, 'w') as f:
        f.write(FALLBACK_CERT)
    if not tls_certificate_pair_is_valid(cert_path, key_path):
        raise RuntimeError('failed to create a valid TLS certificate pair')

def tls_certificate_pair_is_valid(cert_path: str, key_path: str) -> bool:
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        return False
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return True
    except Exception:
        return False

# ======================== sing-box 配置生成 ========================

def generate_singbox_config(cert_path: str, key_path: str) -> dict:
    inbounds = []
    
    inbounds.append({
        'type': 'vmess',
        'tag': 'vmess-ws-in',
        'listen': '::',
        'listen_port': ARGO_PORT,
        'users': [{'uuid': UUID}],
        'transport': {
            'type': 'ws',
            'path': '/vmess-argo',
            'early_data_header_name': 'Sec-WebSocket-Protocol'
        }
    })
    
    if is_valid_port(REALITY_PORT):
        inbounds.append({
            'type': 'vless',
            'tag': 'vless-reality',
            'listen': '::',
            'listen_port': int(REALITY_PORT),
            'users': [{'uuid': UUID, 'flow': 'xtls-rprx-vision'}],
            'tls': {
                'enabled': True,
                'server_name': 'www.iij.ad.jp',
                'reality': {
                    'enabled': True,
                    'handshake': {'server': 'www.iij.ad.jp', 'server_port': 443},
                    'private_key': privateKey,
                    'short_id': ['']
                }
            }
        })
    
    if is_valid_port(HY2_PORT):
        inbounds.append({
            'type': 'hysteria2',
            'tag': 'hysteria-in',
            'listen': '::',
            'listen_port': int(HY2_PORT),
            'users': [{'password': UUID}],
            'masquerade': 'https://bing.com',
            'tls': {
                'enabled': True,
                'alpn': ['h3'],
                'certificate_path': cert_path,
                'key_path': key_path
            }
        })
    
    if is_valid_port(TUIC_PORT):
        inbounds.append({
            'type': 'tuic',
            'tag': 'tuic-in',
            'listen': '::',
            'listen_port': int(TUIC_PORT),
            'users': [{'uuid': UUID, 'password': UUID}],
            'congestion_control': 'bbr',
            'tls': {
                'enabled': True,
                'alpn': ['h3'],
                'certificate_path': cert_path,
                'key_path': key_path
            }
        })
    
    if is_valid_port(S5_PORT):
        inbounds.append({
            'type': 'socks',
            'tag': 's5-in',
            'listen': '::',
            'listen_port': int(S5_PORT),
            'users': [{
                'username': UUID[:8],
                'password': UUID[-12:]
            }]
        })
    
    if is_valid_port(ANYTLS_PORT):
        inbounds.append({
            'type': 'anytls',
            'tag': 'anytls-in',
            'listen': '::',
            'listen_port': int(ANYTLS_PORT),
            'users': [{'password': UUID}],
            'tls': {
                'enabled': True,
                'certificate_path': cert_path,
                'key_path': key_path
            }
        })
    
    endpoints = [{
        'type': 'wireguard',
        'tag': 'wireguard-out',
        'mtu': 1280,
        'address': ['172.16.0.2/32', '2606:4700:110:8dfe:d141:69bb:6b80:925/128'],
        'private_key': 'YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=',
        'peers': [{
            'address': 'engage.cloudflareclient.com',
            'port': 2408,
            'public_key': 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
            'allowed_ips': ['0.0.0.0/0', '::/0'],
            'reserved': [78, 135, 76]
        }]
    }]
    
    rule_set = [
        {'tag': 'netflix', 'type': 'remote', 'format': 'binary',
         'url': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs'}
    ]
    wireguard_rule_sets = ['netflix']
    
    need_youtube_warp = YT_WARPOUT
    if not need_youtube_warp:
        try:
            result = subprocess.run(
                ['curl', '-o', os.devnull, '-m', '2', '-s', '-w', '%{http_code}',
                 'https://www.youtube.com'],
                capture_output=True, text=True, timeout=5
            )
            need_youtube_warp = result.stdout.strip() != '200'
        except:
            need_youtube_warp = True
    
    if need_youtube_warp:
        rule_set.append({
            'tag': 'youtube', 'type': 'remote', 'format': 'binary',
            'url': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs'
        })
        wireguard_rule_sets.append('youtube')
        log('Add YouTube outbound rule')
    
    route = {
        'default_http_client': 'http-client-direct',
        'rule_set': rule_set,
        'rules': [{'rule_set': wireguard_rule_sets, 'outbound': 'wireguard-out'}],
        'final': 'direct'
    }
    
    return {
        'log': {'disabled': True, 'level': 'error', 'timestamp': True},
        'http_clients': [{'tag': 'http-client-direct'}],
        'inbounds': inbounds,
        'endpoints': endpoints,
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
        'route': route
    }

# ======================== 隧道域名检测 ========================

def wait_for_quick_tunnel_domain(log_path: str, timeout_ms: int) -> Optional[str]:
    deadline = time.time() + timeout_ms / 1000
    last_content = ""
    
    while time.time() < deadline:
        try:
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    content = f.read()
                if content != last_content:
                    last_content = content
                    matches = re.findall(r'https://([A-Za-z0-9.-]+\.trycloudflare\.com)', content)
                    if matches:
                        return matches[-1]
        except:
            pass
        time.sleep(1)
    return None

def extract_domain() -> Optional[str]:
    if DISABLE_ARGO:
        return None
    if ARGO_AUTH and ARGO_DOMAIN:
        log(f'ARGO_DOMAIN: {ARGO_DOMAIN}')
        return ARGO_DOMAIN
    
    log('Waiting for quick tunnel domain in log...')
    domain = wait_for_quick_tunnel_domain(bootLogPath, 30000)
    if not domain:
        log('Quick tunnel domain not found, retrying...')
        try:
            os.unlink(bootLogPath)
        except:
            pass
        time.sleep(5)
        domain = wait_for_quick_tunnel_domain(bootLogPath, 30000)
    
    if domain:
        log(f'ArgoDomain: {domain}')
    else:
        log('ArgoDomain not found')
    return domain

# ======================== ISP 信息 ========================

def get_meta_info() -> str:
    try:
        response = requests.get('https://api.ip.sb/geoip', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('country_code') and data.get('isp'):
                return f"{data['country_code']}-{data['isp']}".replace(' ', '_')
    except:
        pass
    
    try:
        response = requests.get('http://ip-api.com/json', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
                return f"{data['countryCode']}-{data['org']}".replace(' ', '_')
    except:
        pass
    
    return 'Unknown'

# ======================== 节点链接生成 ========================

def get_server_ip() -> str:
    try:
        response = requests.get('http://ipv4.ip.sb', timeout=3)
        if response.status_code == 200:
            return response.text.strip()
    except:
        pass
    
    try:
        result = subprocess.run(['curl', '-sm', '3', 'ipv4.ip.sb'], 
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    
    try:
        response = requests.get('http://ipv6.ip.sb', timeout=3)
        if response.status_code == 200:
            return f"[{response.text.strip()}]"
    except:
        pass
    
    try:
        result = subprocess.run(['curl', '-sm', '3', 'ipv6.ip.sb'],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return f"[{result.stdout.strip()}]"
    except:
        pass
    
    return ""

def generate_links(argo_domain: Optional[str]) -> str:
    server_ip = get_server_ip()
    isp = get_meta_info()
    node_name = f"{NAME}-{isp}" if NAME else isp
    
    time.sleep(2)
    
    sub_txt = ''
    
    if not DISABLE_ARGO and argo_domain:
        vmess_config = {
            'v': '2','ps': node_name,'add': CFIP,'port': CFPORT,'id': UUID,'aid': '0','scy': 'auto','net': 'ws','type': 'none',
            'host': argo_domain,'path': '/vmess-argo?ed=2560','tls': 'tls','sni': argo_domain,'alpn': '','fp': 'firefox'
        }
        vmess_node = f"vmess://{base64.b64encode(json.dumps(vmess_config).encode()).decode()}"
        sub_txt = vmess_node
    
    if is_valid_port(TUIC_PORT):
        sub_txt += f"\ntuic://{UUID}:{UUID}@{server_ip}:{TUIC_PORT}?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#{node_name}"
    
    if is_valid_port(HY2_PORT):
        sub_txt += f"\nhysteria2://{UUID}@{server_ip}:{HY2_PORT}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#{node_name}"
    
    if is_valid_port(REALITY_PORT):
        sub_txt += f"\nvless://{UUID}@{server_ip}:{REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk={publicKey}&type=tcp&headerType=none#{node_name}"
    
    if is_valid_port(ANYTLS_PORT):
        sub_txt += f"\nanytls://{UUID}@{server_ip}:{ANYTLS_PORT}?security=tls&sni={server_ip}&fp=chrome&insecure=1&allowInsecure=1#{node_name}"
    
    if is_valid_port(S5_PORT):
        s5_auth = base64.b64encode(f"{UUID[:8]}:{UUID[-12:]}".encode()).decode()
        sub_txt += f"\nsocks://{s5_auth}@{server_ip}:{S5_PORT}#{node_name}"
    
    encoded = base64.b64encode(sub_txt.encode()).decode()
    log(f'\033[32m{encoded}\033[0m')
    log('\033[35mLogs will be deleted in 45 seconds, you can copy the above nodes\033[0m')
    
    with open(subPath, 'w') as f:
        f.write(base64.b64encode(sub_txt.encode()).decode())
    with open(listPath, 'w') as f:
        f.write(sub_txt)
    
    log(f'{FILE_PATH}/sub.txt saved successfully')
    return sub_txt

# ======================== Telegram 推送 ========================

def send_telegram():
    if not BOT_TOKEN or not CHAT_ID:
        log('TG variables is empty, Skipping push nodes to TG')
        return
    
    try:
        with open(subPath, 'r') as f:
            message = f.read()
        
        escaped_name = re.sub(r'([_*[\]()~`>#+=|{}.!-])', r'\\\1', NAME)
        text = f"**{escaped_name}节点推送通知**\n```{message}```"
        
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        params = {
            'chat_id': CHAT_ID,
            'text': text,
            'parse_mode': 'MarkdownV2'
        }
        requests.post(url, params=params, timeout=30)
        log('Telegram message sent successfully')
    except Exception as error:
        log(f'Failed to send Telegram message: {error}')

# ======================== 节点上传 ========================

def upload_nodes():
    if UPLOAD_URL and PROJECT_URL:
        subscription_url = f"{PROJECT_URL}/{SUB_PATH}"
        json_data = {'subscription': [subscription_url]}
        try:
            response = requests.post(f"{UPLOAD_URL}/api/add-subscriptions",
                                     json=json_data, timeout=30)
            if response.status_code == 200:
                log('Subscription uploaded successfully')
        except:
            pass
    elif UPLOAD_URL:
        if not os.path.exists(listPath):
            return
        with open(listPath, 'r') as f:
            content = f.read()
        nodes = [line for line in content.split('\n')
                 if re.search(r'(vless|vmess|trojan|hysteria2|tuic):\/\/', line)]
        if not nodes:
            return
        try:
            response = requests.post(f"{UPLOAD_URL}/api/add-nodes",
                                     json={'nodes': nodes}, timeout=30)
            if response.status_code == 200:
                log('Subscription uploaded successfully')
        except:
            pass

# ======================== 自动保活 ========================

def add_visit_task():
    if not AUTO_ACCESS or not PROJECT_URL:
        log('Skipping adding automatic access task')
        return
    
    try:
        requests.post('https://oooo.serv00.net/add-url',
                      json={'url': PROJECT_URL}, timeout=30)
        log('Automatic access task added successfully')
    except Exception as error:
        log(f'Add URL failed: {error}')

# ======================== HTTP 服务器 ========================

class SubscriptionHandler(BaseHTTPRequestHandler):
    sub_content = ""

    def do_GET(self):
        if self.path == subscribePath:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            encoded = base64.b64encode(self.sub_content.encode()).decode()
            self.wfile.write(encoded.encode())
        elif self.path == '/':
            try:
                with open('index.html', 'r', encoding='utf-8') as f:
                    html_content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(html_content.encode('utf-8'))
            except Exception:
                fallback_html = 'Hello world!<br><br>You can access /{SUB_PATH}(Default: /sub) get your nodes!'
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(fallback_html.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def log_message(self, format, *args):
        pass

def start_http_server(sub_txt: str, port: int):
    SubscriptionHandler.sub_content = sub_txt
    try:
        server = HTTPServer(('0.0.0.0', port), SubscriptionHandler)
        print(f'Server is running on port {PORT}', flush=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server
    except OSError as e:
        # Non-fatal on shared hosting: port taken (10048) or in a Windows
        # excluded range (10013). The subscription lives in sub.txt and the
        # node is served through the Argo tunnel, so continue without it.
        log(f'HTTP subscription server disabled: cannot bind port {port} ({e}). Continuing.')
        return None

# ======================== 主流程 ========================

def start_server():
    global privateKey, publicKey
    
    # 1. 删除旧节点
    delete_nodes()
    
    # 2. 创建运行目录 + 清理文件
    if not os.path.exists(FILE_PATH):
        os.makedirs(FILE_PATH)
        log(f'{FILE_PATH} is created')
    cleanup_old_files()
    
    # 3. 生成 Argo 隧道配置
    argo_type()
    
    # 4. 定位 Windows 可执行文件
    ensure_windows_binaries()
    singbox_exe = locate_binary('SINGBOX_EXE', 'web.exe')
    if not singbox_exe:
        raise FileNotFoundError(
            'web.exe not found: put web.exe (sing-box) and libcronet.dll in '
            f'{runtimeFilePath} or next to this script, or set SINGBOX_EXE')
    cronet = os.path.join(os.path.dirname(singbox_exe), 'libcronet.dll')
    if not os.path.isfile(cronet):
        log('Warning: libcronet.dll not found next to web.exe '
            '(only needed for naive outbound; current config does not use it)')

    cloudflared_exe = None
    if not DISABLE_ARGO:
        cloudflared_exe = locate_binary('CLOUDFLARED_EXE', 'bot.exe')
        if not cloudflared_exe:
            log('Warning: bot.exe (cloudflared) not found, argo tunnel disabled for this run')
    
    # 5. 生成 Reality 密钥对
    if REALITY_PORT:
        generate_or_load_keypair()
    
    # 6. 生成 TLS 证书
    cert_path = os.path.join(FILE_PATH, 'cert.pem')
    key_path = os.path.join(FILE_PATH, 'private.key')
    needs_tls = bool(HY2_PORT or TUIC_PORT or ANYTLS_PORT)
    if needs_tls:
        ensure_tls_certificates(cert_path, key_path)
    
    # 7. 生成 sing-box config.json
    sbx_config = generate_singbox_config(cert_path, key_path)
    with open(singBoxConfigPath, 'w') as f:
        json.dump(sbx_config, f, indent=2)
    
    # 8. 创建并启动服务
    services = []
    
    # sing-box服务：sing-box run -c <config> -D . --disable-color
    singbox_service = ExeService(
        'web', singbox_exe,
        ['run', '-c', singBoxConfigPath, '-D', '.', '--disable-color'])
    services.append(singbox_service)

    # cloudflared服务：直接复用原 payload 里的 args 数组
    cloudflared_service = None
    if cloudflared_exe:
        cf_payload = cloudflared_payload()
        if cf_payload:
            cf_args = json.loads(cf_payload).get('args', [])
            cloudflared_service = ExeService('bot', cloudflared_exe, cf_args)
            services.append(cloudflared_service)
    
    # 信号处理
    def stop_all():
        log("\nStopping all services...")
        for service in reversed(services):
            try:
                service.stop()
            except:
                pass
        sys.exit(0)
    
    signal.signal(signal.SIGINT, lambda s, f: stop_all())
    try:
        signal.signal(signal.SIGTERM, lambda s, f: stop_all())
    except (ValueError, OSError, AttributeError):
        pass  # SIGTERM handling is limited on Windows; Ctrl+C / SIGINT is the reliable path
    
    # 启动所有服务
    for service in services:
        service.start()
    
    time.sleep(1)
    log('web is running')
    if cloudflared_service:
        log('bot is running')
    
    # 9. 等待并检测隧道域名
    time.sleep(5)
    argo_domain = extract_domain()
    
    # 10. 生成节点链接
    sub_txt = generate_links(argo_domain)
    
    # 11. 启动 HTTP 服务器
    http_server = start_http_server(sub_txt, PORT)
    
    # 12. Telegram 推送 + 节点上传
    send_telegram()
    upload_nodes()
    add_visit_task()
    
    # 13. 45秒后清理文件 + 清屏
    def delayed_cleanup():
        time.sleep(45)
        cleanup_files(keep_sub=True)
        clear_console()
        print('App is running')
    
    cleanup_thread = threading.Thread(target=delayed_cleanup, daemon=True)
    cleanup_thread.start()
    
    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_all()
        if http_server:
            http_server.shutdown()

if __name__ == '__main__':
    start_server()
