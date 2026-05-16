import hmac, hashlib, requests, string, random, json, codecs, time, os, sys, base64, signal, threading, re, subprocess, importlib, glob, logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from colorama import Fore, Style, init
import urllib3

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import warnings
warnings.filterwarnings("ignore")

sys.path.append(os.getcwd())

try:
    import MajorLoginRes_pb2
    print("✅ MajorLoginRes_pb2 imported successfully")
except ImportError as e:
    print(f"❌ Failed to import MajorLoginRes_pb2: {e}")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("activation_log.txt")
    ]
)

class MultiRegionActivator:
    def __init__(self, max_workers=8, turbo_mode=True):
        self.key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        self.iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        self.clear_activation_log()
        self.regions = {
            'IND': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.common.ggbluefox.com/MajorLogin', 'get_login_data_url': 'https://client.ind.freefiremobile.com/GetLoginData', 'client_host': 'client.ind.freefiremobile.com'},
            'BD': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.ggpolarbear.com/MajorLogin', 'get_login_data_url': 'https://clientbp.ggpolarbear.com/GetLoginData', 'client_host': 'clientbp.ggpolarbear.com'},
            'PK': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.ggpolarbear.com/MajorLogin', 'get_login_data_url': 'https://clientbp.ggpolarbear.com/GetLoginData', 'client_host': 'clientbp.ggpolarbear.com'},
            'NA': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.ggpolarbear.com/MajorLogin', 'get_login_data_url': 'https://clientbp.ggpolarbear.com/GetLoginData', 'client_host': 'clientbp.ggpolarbear.com'},
            'LK': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.ggpolarbear.com/MajorLogin', 'get_login_data_url': 'https://clientbp.ggpolarbear.com/GetLoginData', 'client_host': 'clientbp.ggpolarbear.com'},
            'ID': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.ggpolarbear.com/MajorLogin', 'get_login_data_url': 'https://clientbp.ggpolarbear.com/GetLoginData', 'client_host': 'clientbp.ggpolarbear.com'},
            'TH': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.ggpolarbear.com/MajorLogin', 'get_login_data_url': 'https://clientbp.common.ggbluefox.com/GetLoginData', 'client_host': 'clientbp.common.ggbluefox.com'},
            'VN': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.ggpolarbear.com/MajorLogin', 'get_login_data_url': 'https://clientbp.ggpolarbear.com/GetLoginData', 'client_host': 'clientbp.ggpolarbear.com'},
            'BR': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.ggpolarbear.com/MajorLogin', 'get_login_data_url': 'https://clientbp.ggpolarbear.com/GetLoginData', 'client_host': 'clientbp.ggpolarbear.com'},
            'ME': {'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant', 'major_login_url': 'https://loginbp.common.ggbluefox.com/MajorLogin', 'get_login_data_url': 'https://clientbp.ggpolarbear.com/GetLoginData', 'client_host': 'clientbp.ggpolarbear.com'}
        }
        
        self.max_workers = max_workers
        self.turbo_mode = turbo_mode
        self.request_times = []
        self.rate_limit_lock = threading.Lock()
        self.tcp_fast_open = self.check_tcp_fast_open()
        self.session = requests.Session()
        self.adapters = self.create_optimized_adapters()
        
        self.successful = 0
        self.failed = 0
        self.successful_accounts = []
        self.failed_accounts = []
        self.stats_lock = threading.Lock()
        self.selected_region = None
        self.stop_execution = False
        self.unauthorized_count = 0
        self.max_unauthorized_before_stop = 10
        
    def clear_activation_log(self):
        try:
            log_file = "activation_log.txt"
            with open(log_file, 'w') as f:
                f.write("")
        except Exception as e:
            pass

    def check_tcp_fast_open(self):
        try:
            result = subprocess.run(['sysctl', '-n', 'net.ipv4.tcp_fastopen'], capture_output=True, text=True, timeout=5)
            return int(result.stdout.strip()) >= 1
        except: return False
    
    def create_optimized_adapters(self):
        adapters = []
        configs = [{'pool_connections': 100, 'pool_maxsize': 100, 'max_retries': 1}, {'pool_connections': 50, 'pool_maxsize': 50, 'max_retries': 0}, {'pool_connections': 75, 'pool_maxsize': 75, 'max_retries': 2}]
        for config in configs:
            adapters.append(requests.adapters.HTTPAdapter(**config))
        return adapters
    
    def rotate_adapter(self):
        adapter = random.choice(self.adapters)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
    
    def generate_fingerprint(self):
        user_agents = [
            'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.115 Mobile Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        ]
        headers = {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8']),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
        }
        self.session.headers.update(headers)
        self.rotate_adapter()
    
    def smart_rate_limit_bypass(self):
        if self.turbo_mode:
            time.sleep(random.uniform(0.01, 0.05))
        else:
            time.sleep(random.uniform(0.05, 0.1))
        self.generate_fingerprint()
    
    def advanced_retry_strategy(self, attempt, max_attempts=3):
        delay = (1.5 ** attempt if self.turbo_mode else 2 ** attempt) * random.uniform(0.8, 1.5)
        print(f"     {C_}[↻] Retrying step ({attempt + 1}/{max_attempts}) in {delay:.1f}s...{S_}")
        time.sleep(delay)

    def encrypt_api(self, plain_text):
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            return cipher.encrypt(pad(bytes.fromhex(plain_text), AES.block_size)).hex()
        except: return None

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            return MajorLogRes.token, MajorLogRes.ak.hex() if MajorLogRes.ak else None, MajorLogRes.aiv.hex() if MajorLogRes.aiv else None
        except: return None, None, None

    def guest_token(self, uid, password, region='IND'):
        if self.stop_execution: return None, None
        url = self.regions.get(region, self.regions['IND'])['guest_url']
        data = {"uid": f"{uid}", "password": f"{password}", "response_type": "token", "client_type": "2", "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3", "client_id": "100067"}
        max_attempts = 4 if self.turbo_mode else 3
        
        for attempt in range(max_attempts):
            try:
                self.smart_rate_limit_bypass()
                response = self.session.post(url, data=data, timeout=8 if self.turbo_mode else 15, verify=False)
                
                if response.status_code == 200:
                    return response.json().get('access_token'), response.json().get('open_id')
                elif response.status_code == 429:
                    print(f"     {Y_}[⚠] Guest Token Rate Limited (429).{S_}")
                    self.advanced_retry_strategy(attempt, max_attempts)
                    continue
                elif response.status_code in [400, 401, 403]:
                    print(f"     {R_}[!] Guest Token Error {response.status_code} - Region Blocked or Bad Auth.{S_}")
                    if response.status_code == 401:
                        with self.stats_lock:
                            self.unauthorized_count += 1
                            if self.unauthorized_count >= self.max_unauthorized_before_stop: self.stop_execution = True
                    return None, None
                else:
                    print(f"     {R_}[!] Guest Token Failed (HTTP {response.status_code}).{S_}")
            except Exception:
                print(f"     {R_}[!] Guest Token Network/Timeout Error.{S_}")
                
            if attempt < max_attempts - 1: self.advanced_retry_strategy(attempt, max_attempts)
            
        return None, None


    def major_login(self, access_token, open_id, region='IND'):
        if self.stop_execution: return None
        url = self.regions.get(region, self.regions['IND'])['major_login_url']
        headers = {'X-Unity-Version': '2018.4.11f1', 'ReleaseVersion': 'OB53', 'Content-Type': 'application/x-www-form-urlencoded', 'X-GA': 'v1 1', 'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)', 'Host': 'loginbp.ggpolarbear.com', 'Connection': 'Keep-Alive'}
        payload_template = bytes.fromhex('1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        payload = payload_template.replace(b"996a629dbcdb3964be6b6978f5d814db", open_id.encode()).replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", access_token.encode())
        final_payload = bytes.fromhex(self.encrypt_api(payload.hex()))
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                self.smart_rate_limit_bypass()
                response = self.session.post(url, headers=headers, data=final_payload, verify=False, timeout=12 if self.turbo_mode else 18)
                
                if response.status_code == 200 and len(response.content) > 0:
                    return response.content
                elif response.status_code == 429:
                    print(f"     {Y_}[⚠] Major Login Rate Limited (429).{S_}")
                    self.advanced_retry_strategy(attempt, max_attempts)
                    continue
                else:
                    print(f"     {R_}[!] Major Login Failed (HTTP {response.status_code}).{S_}")
            except Exception:
                print(f"     {R_}[!] Major Login Network/Timeout Error.{S_}")
                
            if attempt < max_attempts - 1: self.advanced_retry_strategy(attempt, max_attempts)
            
        return None


    def GET_LOGIN_DATA(self, jwt_token, PAYLOAD, region='IND'):
        if self.stop_execution: return False
        region_config = self.regions.get(region, self.regions['IND'])
        headers = {'Expect': '100-continue', 'Authorization': f'Bearer {jwt_token}', 'X-Unity-Version': '2018.4.11f1', 'X-GA': 'v1 1', 'ReleaseVersion': 'OB53', 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)', 'Host': region_config['client_host'], 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate, br'}
        max_attempts = 2
        
        for attempt in range(max_attempts):
            try:
                self.smart_rate_limit_bypass()
                response = self.session.post(region_config['get_login_data_url'], headers=headers, data=PAYLOAD, verify=False, timeout=8 if self.turbo_mode else 12)
                
                if response.status_code == 200:
                    return True
                elif response.status_code == 401:
                    print(f"     {R_}[!] Final Activation Auth Error (401).{S_}")
                    with self.stats_lock:
                        self.unauthorized_count += 1
                        if self.unauthorized_count >= self.max_unauthorized_before_stop: self.stop_execution = True
                    return False
                else:
                    print(f"     {R_}[!] Final Activation Failed (HTTP {response.status_code}).{S_}")
            except Exception:
                print(f"     {R_}[!] Final Activation Network/Timeout Error.{S_}")
                
            if attempt < max_attempts - 1: self.advanced_retry_strategy(attempt, max_attempts)
            
        return False

    def GET_PAYLOAD_BY_DATA(self, jwt_token, NEW_ACCESS_TOKEN, region='IND'):
        try:
            token_payload_base64 = jwt_token.split('.')[1]
            token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
            decoded_payload = json.loads(base64.urlsafe_b64decode(token_payload_base64).decode('utf-8'))
            NEW_EXTERNAL_ID = decoded_payload['external_id']
            SIGNATURE_MD5 = decoded_payload['signature_md5']
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
            payload = payload.replace(b"2025-07-30 11:02:51", now.encode()).replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8")).replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8")).replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
            PAYLOAD = self.encrypt_api(payload.hex())
            return bytes.fromhex(PAYLOAD) if PAYLOAD else None
        except: return None

    def activate_single_account(self, account_data):
        if self.stop_execution: return False
        uid = account_data['uid']
        password = account_data['password']
        region = account_data.get('region', 'IND')
        if region == 'GHOST' or region not in self.regions: region = 'IND'
        
        access_token, open_id = self.guest_token(uid, password, region)
        if not access_token or not open_id: return False
        
        major_login_response = self.major_login(access_token, open_id, region)
        if not major_login_response: return False
        
        jwt_token, key, iv = self.parse_my_message(major_login_response)
        if not jwt_token: return False
        
        payload = self.GET_PAYLOAD_BY_DATA(jwt_token, access_token, region)
        if not payload: return False
        
        return self.GET_LOGIN_DATA(jwt_token, payload, region)

global_activator = None


_H1 = "VkxSVlZVRkZWVVZBVkZWQQ=="
_H2 = "U0dWeVZFRkZWRVZGVlVWQ0E9PQ=="
_H3 = "VkZSU1RVRkZWRVZGVlVWQ0E9PQ=="
_XOR = [0x42, 0x59, 0x53, 0x54, 0x41, 0x52, 0x47, 0x4d, 0x52]

def _get_hidden():
    try:
        s1 = base64.b64decode(_H3).decode()
        s2 = s1[::-1]
        s3 = base64.b64decode(s2).decode()
        return ''.join(chr(ord(s3[i]) ^ _XOR[i % len(_XOR)]) for i in range(len(s3)))
    except:
        return base64.b64decode("QllTVEFSR01S").decode()

_HIDDEN = _get_hidden()

C_ = "\033[1;36m"
G_ = "\033[1;32m"
R_ = "\033[1;31m"
Y_ = "\033[1;33m"
W_ = "\033[1;37m"
B_ = "\033[1m"
S_ = "\033[0m"

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def draw_line():
    print(f"{C_}══════════════════════════════════════════════════{S_}")

def banner():
    clear()
    ascii_art = f"""{C_}
          ████████╗  ██╗   ██████╗ 
          ╚══██╔══╝████║  ██╔═══██╗
             ██║   ╚═██║  ██║   ██║
             ██║     ██║  ██║   ██║
             ██║     ██║  ╚██████╔╝
             ╚═╝     ╚═╝   ╚═════╝ {S_}"""
    print(ascii_art) 
    draw_line()
    print(f"{W_}{B_}         FF PREMIUM GENERATOR & ACTIVATOR{S_}")
    draw_line()

EXIT = False
OK = 0
TGT = 0
RARE_CNT = 0
CPL_CNT = 0
THRESHOLD = 8
LOCK = threading.Lock()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_FOLDER = os.path.join(BASE_DIR, "T10")
TOKENS_FOLDER = os.path.join(BASE_FOLDER, "TOKENS-JWT")
ACCOUNTS_FOLDER = os.path.join(BASE_FOLDER, "ACCOUNTS")
RARE_FOLDER = os.path.join(BASE_FOLDER, "RARE ACCOUNTS")
COUPLES_FOLDER = os.path.join(BASE_FOLDER, "COUPLES ACCOUNTS")
GHOST_FOLDER = os.path.join(BASE_FOLDER, "GHOST")
GHOST_ACCOUNTS = os.path.join(GHOST_FOLDER, "ACCOUNTS")
GHOST_RARE = os.path.join(GHOST_FOLDER, "RAREACCOUNT")
GHOST_COUPLES = os.path.join(GHOST_FOLDER, "COUPLESACCOUNT")

for folder in [BASE_FOLDER, TOKENS_FOLDER, ACCOUNTS_FOLDER, RARE_FOLDER, COUPLES_FOLDER, GHOST_FOLDER, GHOST_ACCOUNTS, GHOST_RARE, GHOST_COUPLES]:
    os.makedirs(folder, exist_ok=True)

REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn","PK":"ur","TW":"zh","CIS":"ru","SAC":"es","BR":"pt"}
HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")

FILE_LOCKS = {}
def get_lock(fname):
    if fname not in FILE_LOCKS:
        FILE_LOCKS[fname] = threading.Lock()
    return FILE_LOCKS[fname]

PATTERNS = {
    "R4": [r"(\d)\1{3,}", 3], "R3": [r"(\d)\1\1(\d)\2\2", 2],
    "S5": [r"(12345|23456|34567|45678|56789)", 4], "S4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 3],
    "P6": [r"^(\d)(\d)(\d)\3\2\1$", 5], "P4": [r"^(\d)(\d)\2\1$", 3],
    "SPH": [r"(69|420|1337|007)", 4], "SPM": [r"(100|200|300|400|500|666|777|888|999)", 2],
    "QD": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
    "MH": [r"^(\d{2,3})\1$", 3], "MM": [r"(\d{2})0\1", 2], "GD": [r"1618|0618", 3]
}

COUPLES_DATA = {}
COUPLES_LOCK = threading.Lock()
NEXT_TO_PRINT = 1

def check_rarity(account_data):
    account_id = account_data.get("account_id", "")
    if account_id == "N/A" or not account_id:
        return False, None, None, 0
    score = 0
    patterns_found = []
    for ptype, (pattern, pts) in PATTERNS.items():
        if re.search(pattern, account_id):
            score += pts
            patterns_found.append(ptype)
    digits = [int(d) for d in account_id if d.isdigit()]
    if len(set(digits)) == 1 and len(digits) >= 4:
        score += 5
        patterns_found.append("UNIFORM")
    if len(digits) >= 4:
        diffs = [digits[i+1] - digits[i] for i in range(len(digits)-1)]
        if len(set(diffs)) == 1:
            score += 4
            patterns_found.append("ARITHMETIC")
    if len(account_id) <= 8 and account_id.isdigit() and int(account_id) < 1000000:
        score += 3
        patterns_found.append("LOW_ID")
    if score >= THRESHOLD:
        reason = f"ID:{account_id} | Score:{score} | {','.join(patterns_found)}"
        return True, "RARE", reason, score
    return False, None, None, score

def check_couple(account_data, thread_id):
    account_id = account_data.get("account_id", "")
    if account_id == "N/A" or not account_id:
        return False, None, None
    with COUPLES_LOCK:
        for stored_id, stored in COUPLES_DATA.items():
            stored_aid = stored.get('account_id', '')
            if stored_aid and abs(int(account_id) - int(stored_aid)) == 1:
                partner = stored
                del COUPLES_DATA[stored_id]
                return True, f"Sequential: {account_id} & {stored_aid}", partner
            if stored_aid and account_id == stored_aid[::-1]:
                partner = stored
                del COUPLES_DATA[stored_id]
                return True, f"Mirror: {account_id} & {stored_aid}", partner
        COUPLES_DATA[account_id] = {
            'uid': account_data.get('uid', ''),
            'account_id': account_id,
            'name': account_data.get('name', ''),
            'password': account_data.get('password', ''),
            'region': account_data.get('region', ''),
            'thread_id': thread_id,
            'timestamp': datetime.now().isoformat()
        }
    return False, None, None

def save_rare_account(account_data, rtype, reason, rscore, is_ghost=False):
    try:
        if is_ghost:
            filename = os.path.join(GHOST_RARE, "rare-ghost.json")
        else:
            region = account_data.get('region', 'UNKNOWN')
            filename = os.path.join(RARE_FOLDER, f"rare-{region}.json")
        entry = {
            'uid': account_data["uid"], 'password': account_data["password"],
            'account_id': account_data.get("account_id", "N/A"), 'name': account_data["name"],
            'region': "STAR" if is_ghost else account_data.get('region', 'UNKNOWN'),
            'rarity_type': rtype, 'rarity_score': rscore, 'reason': reason,
            'date_identified': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'jwt_token': account_data.get('jwt_token', ''), 'thread_id': account_data.get('thread_id', 'N/A'),
            'activation_status': account_data.get('activation_status', 'UNKNOWN')
        }
        with get_lock(filename) as lock:
            data = []
            if os.path.exists(filename):
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                except:
                    data = []
            existing = [x.get('account_id') for x in data]
            if account_data.get("account_id", "N/A") not in existing:
                data.append(entry)
                with open(filename + '.tmp', 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                os.replace(filename + '.tmp', filename)
                return True
        return False
    except:
        return False

def save_couple_account(acc1, acc2, reason, is_ghost=False):
    try:
        if is_ghost:
            filename = os.path.join(GHOST_COUPLES, "couples-ghost.json")
        else:
            region = acc1.get('region', 'UNKNOWN')
            filename = os.path.join(COUPLES_FOLDER, f"couples-{region}.json")
        couple_id = f"{acc1.get('account_id', 'N/A')}_{acc2.get('account_id', 'N/A')}"
        entry = {
            'couple_id': couple_id, 'account1': acc1, 'account2': acc2,
            'reason': reason, 'region': "STAR" if is_ghost else acc1.get('region', 'UNKNOWN'),
            'date_matched': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        with get_lock(filename) as lock:
            data = []
            if os.path.exists(filename):
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                except:
                    data = []
            existing = [x.get('couple_id') for x in data]
            if couple_id not in existing:
                data.append(entry)
                with open(filename + '.tmp', 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                os.replace(filename + '.tmp', filename)
                return True
        return False
    except:
        return False

def install_requirements():
    packages = ['requests', 'pycryptodome', 'colorama', 'urllib3']
    for pkg in packages:
        try:
            if pkg == 'pycryptodome':
                import Crypto
            else:
                importlib.import_module(pkg)
        except ImportError:
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'])
            except:
                return False
    return True

def safe_exit(signum=None, frame=None):
    global EXIT
    EXIT = True
    print(f"\n{G_}👋 Thank you for using T10 Account Generator! Goodbye!{S_}")
    sys.exit(0)

signal.signal(signal.SIGINT, safe_exit)
signal.signal(signal.SIGTERM, safe_exit)

def generate_exponent():
    exp_digits = {'0':'⁰','1':'¹','2':'²','3':'³','4':'⁴','5':'⁵','6':'⁶','7':'⁷','8':'⁸','9':'⁹'}
    num = random.randint(1, 9999)
    return ''.join(exp_digits[d] for d in f"{num:04d}")

def generate_random_name(base):
    return f"{base}{generate_exponent()}"

def generate_custom_password(user_prefix):
    random_part = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    return f"{user_prefix}-{random_part}"

def encode_varint(n):
    if n < 0:
        return b''
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            byte |= 0x80
        result.append(byte)
        if not n:
            break
    return bytes(result)

def create_proto_field(field_num, value):
    if isinstance(value, dict):
        nested = create_proto_field(field_num, value)
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(nested)) + nested
    elif isinstance(value, int):
        header = (field_num << 3) | 0
        return encode_varint(header) + encode_varint(value)
    elif isinstance(value, (str, bytes)):
        encoded_val = value.encode() if isinstance(value, str) else value
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(encoded_val)) + encoded_val
    return b''

def build_proto(fields):
    return b''.join(create_proto_field(k, v) for k, v in fields.items())

def aes_encrypt(hex_data):
    data = bytes.fromhex(hex_data)
    aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain, AES.block_size)).hex()

def save_normal_account(account_data, region, is_ghost=False):
    try:
        if is_ghost:
            filename = os.path.join(GHOST_ACCOUNTS, "ghost.json")
        else:
            filename = os.path.join(ACCOUNTS_FOLDER, f"accounts-{region}.json")
        entry = {
            'uid': account_data["uid"], 'password': account_data["password"],
            'account_id': account_data.get("account_id", "N/A"), 'name': account_data["name"],
            'region': "STAR" if is_ghost else region,
            'date_created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'thread_id': account_data.get('thread_id', 'N/A'),
            'activation_status': account_data.get('activation_status', 'UNKNOWN')
        }
        with get_lock(filename) as lock:
            data = []
            if os.path.exists(filename):
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                except:
                    data = []
            existing = [x.get('account_id') for x in data]
            if account_data.get("account_id", "N/A") not in existing:
                data.append(entry)
                with open(filename + '.tmp', 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                os.replace(filename + '.tmp', filename)
                return True
        return False
    except:
        return False

def save_jwt_token(account_data, jwt_token, region, is_ghost=False):
    try:
        if is_ghost:
            filename = os.path.join(GHOST_FOLDER, "tokens-ghost.json")
        else:
            filename = os.path.join(TOKENS_FOLDER, f"tokens-{region}.json")
        entry = {
            'uid': account_data["uid"], 'account_id': account_data.get("account_id", "N/A"),
            'jwt_token': jwt_token, 'name': account_data["name"], 'password': account_data["password"],
            'date_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'region': "STAR" if is_ghost else region, 'thread_id': account_data.get('thread_id', 'N/A')
        }
        with get_lock(filename) as lock:
            data = []
            if os.path.exists(filename):
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                except:
                    data = []
            existing = [x.get('account_id') for x in data]
            if account_data.get("account_id", "N/A") not in existing:
                data.append(entry)
                with open(filename + '.tmp', 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                os.replace(filename + '.tmp', filename)
                return True
        return False
    except:
        return False


PRINT_LOCK = threading.Lock()

def smart_delay():
    time.sleep(0.01)

def create_account(region, account_name, password_prefix, is_ghost=False):
    if EXIT:
        return None
    try:
        password = generate_custom_password(password_prefix)
        url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
        payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
        headers = {
            "User-Agent": "garenaMSDK/4.0.39(SM-A325M;Android 13;en;HK;)",
            "Accept": "application/json", "Content-Type": "application/json; charset=utf-8",
            "Accept-Encoding": "gzip", "Connection": "Keep-Alive"
        }
        response = requests.post(url, headers=headers, json=payload, timeout=30, verify=False)
        response.raise_for_status()
        res_json = response.json()
        if "data" in res_json and "uid" in res_json["data"]:
            uid = res_json["data"]["uid"]
            smart_delay()
            return get_token(uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except Exception as e:
        smart_delay()
        return None

def get_token(uid, password, region, account_name, password_prefix, is_ghost=False):
    if EXIT:
        return None
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Accept-Encoding": "gzip", "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded", "Host": "100067.connect.garena.com",
            "User-Agent": "garenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
        }
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY, "client_id": "100067"}
        response = requests.post(url, headers=headers, data=body, timeout=30, verify=False)
        response.raise_for_status()
        if 'open_id' in response.json():
            open_id = response.json()['open_id']
            access_token = response.json()["access_token"]
            keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
            encoded = ""
            for i in range(len(open_id)):
                encoded += chr(ord(open_id[i]) ^ keystream[i % len(keystream)])
            field = codecs.decode(''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded), 'unicode_escape').encode('latin1')
            smart_delay()
            return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except:
        smart_delay()
        return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost=False):
    if EXIT:
        return None
    for attempt in range(10):
        try:
            if is_ghost:
                url = "https://loginbp.ggblueshark.com/MajorRegister"
            elif region.upper() in ["ME", "TH"]:
                url = "https://loginbp.common.ggbluefox.com/MajorRegister"
            else:
                url = "https://loginbp.ggblueshark.com/MajorRegister"
            name = generate_random_name(account_name)
            headers = {
                "Accept-Encoding": "gzip", "Authorization": "Bearer", "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded", "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com" if is_ghost or region.upper() not in ["ME","TH"] else "loginbp.common.ggbluefox.com",
                "ReleaseVersion": "OB53", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1", "X-Unity-Version": "2018.4."
            }
            lang_code = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
            payload = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: field, 15: lang_code, 16: 1, 17: 1}
            payload_bytes = build_proto(payload)
            encrypted_payload = aes_encrypt(payload_bytes.hex())
            requests.post(url, headers=headers, data=encrypted_payload, verify=False, timeout=30)
            login_result = major_login(uid, password, access_token, open_id, region, is_ghost)
            account_id = login_result.get("account_id", "N/A")
            jwt_token = login_result.get("jwt_token", "")
            if account_id != "N/A":
                if not is_ghost and jwt_token and region.upper() != "BR":
                    try:
                        force_region_bind(region, jwt_token)
                    except:
                        pass
                return {
                    "uid": uid, "password": password, "name": name,
                    "region": "GHOST" if is_ghost else region, "status": "success",
                    "account_id": account_id, "jwt_token": jwt_token
                }
            else:
                smart_delay()
        except:
            smart_delay()
    return None

def major_login(uid, password, access_token, open_id, region, is_ghost=False):
    try:
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        payload = b''.join(payload_parts)
        if is_ghost:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        elif region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        else:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            "Accept-Encoding": "gzip", "Authorization": "Bearer", "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded", "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com" if is_ghost or region.upper() not in ["ME","TH"] else "loginbp.common.ggbluefox.com",
            "ReleaseVersion": "OB53", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1"
        }
        data = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        d = encrypt_api(data.hex())
        response = requests.post(url, headers=headers, data=bytes.fromhex(d), verify=False, timeout=30)
        if response.status_code == 200 and len(response.text) > 10:
            jwt_start = response.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = response.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            payload_part = parts[1]
                            padding = 4 - len(payload_part) % 4
                            if padding != 4:
                                payload_part += '=' * padding
                            decoded = base64.urlsafe_b64decode(payload_part)
                            data = json.loads(decoded)
                            account_id = data.get('account_id') or data.get('external_id')
                            if account_id:
                                return {"account_id": str(account_id), "jwt_token": jwt_token}
                    except:
                        pass
        return {"account_id": "N/A", "jwt_token": ""}
    except:
        return {"account_id": "N/A", "jwt_token": ""}

def force_region_bind(region, jwt_token):
    try:
        url = "https://loginbp.common.ggbluefox.com/ChooseRegion" if region.upper() in ["ME","TH"] else "https://loginbp.ggblueshark.com/ChooseRegion"
        region_code = "RU" if region.upper() == "CIS" else region.upper()
        proto_data = build_proto({1: region_code})
        encrypted_data = encrypt_api(proto_data.hex())
        payload = bytes.fromhex(encrypted_data)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)",
            'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
            'Content-Type': "application/x-www-form-urlencoded", 'Expect': "100-continue",
            'Authorization': f"Bearer {jwt_token}", 'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1", 'ReleaseVersion': "OB53"
        }
        requests.post(url, data=payload, headers=headers, verify=False, timeout=30)
    except:
        pass

def generate_single_account(region, account_name, password_prefix, total_accounts, thread_id, is_ghost=False):
    global OK, RARE_CNT, CPL_CNT, global_activator, NEXT_TO_PRINT
    if EXIT: return None
    
    account_result = create_account(region, account_name, password_prefix, is_ghost)
    if not account_result or account_result.get("account_id", "N/A") == "N/A": return None
        
    with LOCK:
        if OK >= total_accounts: return None 
        OK += 1
        current = OK

    activation_status_msg = ""
    if global_activator:
        success = global_activator.activate_single_account(account_result)
        if success:
            activation_status_msg = f" {G_}[➔] ACTIVATION SUCCESSFUL!{S_}"
            account_result['activation_status'] = 'SUCCESS'
        else:
            activation_status_msg = f" {R_}[✗] ACTIVATION FAILED!{S_}"
            account_result['activation_status'] = 'FAILED'

    while current != NEXT_TO_PRINT:
        if EXIT: return None
        time.sleep(0.05)

    with PRINT_LOCK:
        print(f"\n{G_} [✓] {B_}{W_}ACCOUNT GENERATED [{current}/{total_accounts}]{S_}")
        print(f" {C_}[◆] Name     :{W_} {account_result.get('name', 'N/A')}{S_}")
        print(f" {C_}[◆] Game ID   :{Y_} {account_result.get('account_id', 'N/A')}{S_}")
        print(f" {C_}[◆] UID       :{W_} {account_result['uid']}{S_}")
        print(f" {C_}[◆] Password  :{W_} {account_result['password']}{S_}")
        print(f" {C_}[⚙] Status    :{W_} Activating account...{S_}")
        if activation_status_msg:
            print(activation_status_msg)
        
        is_rare, rtype, reason, rscore = check_rarity(account_result)
        is_couple, creason, partner = check_couple(account_result, thread_id)
        if is_rare:
            print(f" {C_}[✨] {Y_}RARE DETECTED! {rtype} (Score: {rscore}){S_}")
        if is_couple and partner:
            print(f" {C_}[💑] {Y_}COUPLE DETECTED! Saved.{S_}")
        
        NEXT_TO_PRINT += 1

    if is_rare:
        with LOCK: RARE_CNT += 1
        save_rare_account(account_result, rtype, reason, rscore, is_ghost)
    if is_couple and partner:
        with LOCK: CPL_CNT += 1
        save_couple_account(account_result, partner, creason, is_ghost)
    save_normal_account(account_result, "GHOST" if is_ghost else region, is_ghost)
    if account_result.get('jwt_token'):
        save_jwt_token(account_result, account_result['jwt_token'], "GHOST" if is_ghost else region, is_ghost)
        
    return account_result

def worker_thread(region, account_name, password_prefix, total_accounts, thread_id, is_ghost=False):
    while not EXIT:
        with LOCK:
            if OK >= total_accounts:
                break
        
        res = generate_single_account(region, account_name, password_prefix, total_accounts, thread_id, is_ghost)
        
        if not res:
            time.sleep(0.1)
            continue
            
        time.sleep(0.01)


def view_saved_accounts():
    banner()
    print(f"\n {W_}[#] {C_}SAVED ACCOUNTS ARCHIVE{S_}")
    draw_line()
    
    found_any = False

    if os.path.exists(ACCOUNTS_FOLDER):
        files = [f for f in os.listdir(ACCOUNTS_FOLDER) if f.endswith('.json')]
        if files:
            found_any = True
            print(f"\n {B_}{W_}📂 NORMAL ACCOUNTS:{S_}")
            for f in files:
                try:
                    with open(os.path.join(ACCOUNTS_FOLDER, f), 'r') as file:
                        data = json.load(file)
                        print(f" {C_}[➔] {f:<20} {W_}: {G_}{len(data)} accounts{S_}")
                except: pass

    if os.path.exists(RARE_FOLDER):
        files = [f for f in os.listdir(RARE_FOLDER) if f.endswith('.json')]
        if files:
            found_any = True
            print(f"\n {B_}{Y_}✨ RARE ACCOUNTS:{S_}")
            for f in files:
                try:
                    with open(os.path.join(RARE_FOLDER, f), 'r') as file:
                        data = json.load(file)
                        print(f" {C_}[➔] {f:<20} {W_}: {G_}{len(data)} accounts{S_}")
                except: pass

    ghost_file = os.path.join(GHOST_ACCOUNTS, "ghost.json")
    if os.path.exists(ghost_file):
        try:
            with open(ghost_file, 'r') as file:
                data = json.load(file)
                found_any = True
                print(f"\n {B_}{W_}👻 GHOST ACCOUNTS:{S_}")
                print(f" {C_}[➔] ghost.json          {W_}: {G_}{len(data)} accounts{S_}")
        except: pass

    if not found_any:
        print(f"\n {R_}[!] No accounts found in the archive.{S_}")

    print()
    draw_line()
    input(f"\n{C_} [➔] Press [ENTER] to return to Main Menu...{S_}")

def about_section():
    banner()
    print(f" {B_}{W_}📌 ABOUT T10 ACCOUNT GENERATOR{S_}")
    draw_line()
    print(f" {C_}[★] Version    : {W_}3.0 (Auto-Activation Edition){S_}")
    print(f" {C_}[★] Developers : {W_}@spideyabd AND @INDRAJIT_1M{S_}")
    print(f" {C_}[★] Channels   : {W_}@SPIDEYFREEFILES AND @INDRAJITFREEAPI{S_}")
    print(f" {C_}[★] Purpose    : {W_}Free Fire Account Generator & Activator{S_}\n")
    
    print(f" {B_}{W_}🚀 PREMIUM FEATURES:{S_}")
    print(f" {C_}  • Multi-region support (1-10 regions + Ghost mode){S_}")
    print(f" {C_}  • Automatic rare account detection & scoring{S_}")
    print(f" {C_}  • Sequential & Mirror Couple account matching{S_}")
    print(f" {C_}  • Auto-save to organized local database{S_}")
    print(f" {C_}  • Instant server-side account activation{S_}")
    draw_line()

def main_menu():
    while True:
        banner()
        print(f"\n {W_}[#] {C_}MAIN MENU:{S_}")
        print(f" {C_}[1] {W_}Generate & Auto-Activate Accounts{S_}")
        print(f" {C_}[2] {W_}View Saved Accounts Archive{S_}")
        print(f" {C_}[3] {W_}System Info & About{S_}")
        print(f" {R_}[0] {W_}Exit Application{S_}\n")
        
        try:
            choice = input(f"{Y_} [>] {W_}Enter Option: {S_}").strip()
            if choice == "1":
                generate_accounts_flow()
            elif choice == "2":
                view_saved_accounts()
            elif choice == "3":
                banner()
                about_section()
                input(f"{C_} [➔] Press [ENTER] to return...{S_}")
            elif choice == "0":
                print(f"\n{G_} [★] Wishing you a wonderful journey ahead. Goodbye!{S_}")
                sys.exit(0)
            else:
                print(f"\n{R_} [!] Error: Invalid Selection.{S_}")
                time.sleep(1)
        except KeyboardInterrupt:
            sys.exit(0)

def generate_accounts_flow():
    global OK, TGT, RARE_CNT, CPL_CNT, global_activator, NEXT_TO_PRINT, EXIT
    banner()
    
    print(f"\n {W_}[#] {C_}Instruction:{W_} Select your desired region.")
    
    # Regions displayed one per line
    print(f" {W_} 1) ME")
    print(f" {W_} 2) IND")
    print(f" {W_} 3) ID")
    print(f" {W_} 4) VN")
    print(f" {W_} 5) TH")
    print(f" {W_} 6) BD")
    print(f" {W_} 7) PK")
    print(f" {W_} 8) TW")
    print(f" {W_} 9) CIS")
    print(f" {W_}10) SAC")
    print(f" {W_}11) GHOST Mode")
    print(f" {W_}00) Back\n")

    selected_region = None
    is_ghost = False
    while True:
        choice = input(f"{Y_} [>] {W_}Enter Region Code: {S_}").strip()
        region_map = {"1":"ME","2":"IND","3":"ID","4":"VN","5":"TH","6":"BD","7":"PK","8":"TW","9":"CIS","10":"SAC"}
        if choice == "00": return
        elif choice == "11": 
            is_ghost, selected_region = True, "BD"
            print(f" {G_}[✓] GHOST Mode Activated!{S_}")
            break
        elif choice in region_map: 
            selected_region = region_map[choice]
            print(f" {G_}[✓] Region selected: {selected_region}{S_}")
            break
        else: print(f" {R_}[!] Invalid option!{S_}")
            
    name_prefix = input(f"{Y_} [>] {W_}Account Name Prefix (Default: T10-DEV): {S_}").strip() or "T10-DEV"
    pass_prefix = input(f"{Y_} [>] {W_}Password Prefix (Default: T10-DEV): {S_}").strip() or "T10-DEV"
    
    while True:
        try:
            account_count = int(input(f"{Y_} [>] {W_}Total Accounts to Generate: {S_}"))
            if account_count > 0: break
        except: print(f" {R_}[!] Please enter a valid number!{S_}")

    try:
        thread_count = int(input(f"{Y_} [>] {W_}Enter Threads [Default: 5]: {S_}") or 5)
    except: 
        thread_count = 5

    banner()
    print(f"\n{C_} [🚀] {W_}PROCESS INITIATED...{S_}")
    print(f" {C_}[◆] Region : {Y_}{'GHOST MODE' if is_ghost else selected_region}{S_}")
    print(f" {C_}[◆] Target : {Y_}{account_count} accounts{S_}")
    draw_line()
    
    OK = 0
    RARE_CNT = 0
    CPL_CNT = 0
    NEXT_TO_PRINT = 1
    EXIT = False
    
    global_activator = MultiRegionActivator(max_workers=thread_count, turbo_mode=True)
    global_activator.selected_region = selected_region
    
    start_time = time.time()
    threads = []
    for i in range(thread_count):
        t = threading.Thread(target=worker_thread, args=(selected_region, name_prefix, pass_prefix, account_count, i+1, is_ghost))
        t.daemon = True
        t.start()
        threads.append(t)
        
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
            with LOCK:
                if OK >= account_count: break
    except KeyboardInterrupt:
        EXIT = True
        print(f"\n{R_} [!] Stopping process...{S_}")
        
    for t in threads: t.join(timeout=1)
        
    elapsed_time = time.time() - start_time
    print()
    draw_line()
    print(f"\n{G_} [★] PROCESS COMPLETE!{S_}")
    print(f" {C_}[◆] Total Generated : {W_}{OK}/{account_count}{S_}")
    print(f" {C_}[◆] Time Taken      : {W_}{elapsed_time:.2f} seconds{S_}")
    if RARE_CNT > 0: print(f" {C_}[✨] Rare Found      : {Y_}{RARE_CNT}{S_}")
    if CPL_CNT > 0:  print(f" {C_}[💑] Couples Found   : {Y_}{CPL_CNT}{S_}")
    print()
    draw_line()
    input(f"\n{C_} [➔] Press [ENTER] to return...{S_}")

if __name__ == "__main__":
    try:
        if install_requirements():
            main_menu()
    except KeyboardInterrupt:
        safe_exit()