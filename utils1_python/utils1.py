import logging, json5, importlib, zoneinfo, jwt, ast, inspect, random, string, os, tzlocal, re, unicodedata, psycopg2, bcrypt, psutil, socket, time #type:ignore
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, List, Union, Optional
from psycopg2 import pool  # type: ignore
from contextlib import contextmanager
from dotenv import load_dotenv #type:ignore
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path
load_dotenv()
class FindFileError(Exception):
    def __init__(self, message="Ocurrió un error al buscar un archivo:", e=""):
        frame = inspect.currentframe().f_back
        caller_function = frame.f_code.co_name if frame else "<unknown>"
        super().__init__(f"{message} {e}. Surgido desde: {caller_function}.")
class ConfigFileNotFoundError(FindFileError):pass
class ConfigParseError(FindFileError):pass
class MapApplicationsError(Exception):
    def __init__(self, message="Ocurrió un error al incorporar una aplicación:", e=""):
        frame = inspect.currentframe().f_back
        caller_function = frame.f_code.co_name if frame else "<unknown>"
        super().__init__(f"{message} {e}. Surgido desde: {caller_function}.")
class InvalidBlueprintError(MapApplicationsError):pass
class BlueprintImportError(MapApplicationsError):pass
@dataclass 
class Issue: 
    path: str 
    problem: str 
    char: str = '' 
    codepoint: str = '' 
    category: str = '' 
    count: int = 0 
    snippet: str = '' 
    extra: dict = field(default_factory=dict)
class SqlError(Exception):
    def __init__(self, message="Ocurrió un error durante la instrucción sql:", e=""):
        frame = inspect.currentframe().f_back
        caller_function = frame.f_code.co_name if frame else "<unknown>"
        super().__init__(f"{message} {e}. Surgido desde: {caller_function}.")
class PayloadError(Exception):
    def __init__(self, message="", path="$", issue: Issue = None):
        frame = inspect.currentframe().f_back
        caller = frame.f_code.co_name if frame else "<unknown>"
        super().__init__(f"{message} (path={path}, caller={caller})")
        self.issue = issue
class SQLInjectionDetectedError(PayloadError): pass
class XSSDetectedError(PayloadError): pass
class InvalidCharactersError(PayloadError): pass
class LengthExceededError(PayloadError): pass
class UnicodeNormalizationChangedError(PayloadError): pass
class InvalidBytesError(PayloadError): pass
class TimeManagerError(Exception):
    def __init__(self, message="Error ocurrido en TimeManager: ", caller=None):
        frame = inspect.currentframe().f_back
        caller = caller or (frame.f_code.co_name if frame else "<unknown>")
        super().__init__(f"{message} (caller={caller})")
class SecurityError(Exception):
    def __init__(self, message: str = "", caller: Optional[str] = None):
        frame = inspect.currentframe().f_back
        caller_fn = caller or (frame.f_code.co_name if frame else "<unknown>")
        super().__init__(f"{message} (caller={caller_fn})")
class JWTError(SecurityError): pass
class JWTEncodeError(JWTError): pass
class JWTDecodeError(JWTError): pass
class RequestValidationError(SecurityError): pass
class MissingHeaderError(RequestValidationError): pass
class InvalidContentTypeError(RequestValidationError): pass
class BadRequestPayloadError(RequestValidationError): pass
class ObfuscationError(SecurityError): pass
class PasswordHashError(SecurityError): pass
db_pool = psycopg2.pool.SimpleConnectionPool(1, 10,dbname=os.getenv("DB_NAME"),user=os.getenv("DB_USER"),password=os.getenv("DB_PASSWORD"),host=os.getenv("DB_HOST"),port=os.getenv("DB_PORT"))
@contextmanager
def get_conn():
    conn = db_pool.getconn()
    try:yield conn
    finally:db_pool.putconn(conn)
logger = logging.getLogger(str(os.path.splitext(os.path.basename(__file__))[0]))
if not logger.hasHandlers():logging.basicConfig(level=logging.INFO)
def find_file(nombre: str, base_path: str = ".") -> str:
    try:
        base = Path(base_path)
        nombre_sin_ext = Path(nombre).stem
        ext = Path(nombre).suffix
        resultados = []
        for archivo in base.rglob("*"):
            if archivo.is_file() and archivo.stem == nombre_sin_ext:
                if ext == "" or archivo.suffix == ext:resultados.append(str(archivo))
        if not resultados:raise ConfigFileNotFoundError(f"Archivo '{nombre}' no encontrado en '{base_path}'")
        return resultados[0]
    except Exception as e:raise FindFileError(e)
custom = 500
REQUIRED_GET_HEADERS = ("Accept-Language", "User-Agent")
FORBIDDEN_CHARS = set("#<>[]$%*()'`;?¿:\"=~{}@&/|·¬\\")
SQL_KEYWORDS = {'select', 'union', 'insert', 'update', 'delete','drop', 'alter', 'where', 'from', 'into', 'values','or', 'and', 'create', 'table', 'database', 'exec','exists', 'sleep', 'benchmark'}
WEIRD_UNICODE_RANGES = [
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
    (0xFEFF, 0xFEFF),
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x2060, 0x2060),
    (0x00A0, 0x00A0),
    (0x180E, 0x180E),
]
MAX_LEN_PER_FIELD = custom
ALLOW_CONTROL_WHITESPACE = {'\t', '\n', '\r'}
SQL_COMMENT_PATTERNS = [
    re.compile(r"--[^\n]*"),
    re.compile(r"/\*.*?\*/", re.DOTALL),
    re.compile(r"#.*"),
]
XSS_PATTERNS = [
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"<img\s+[^>]*src\s*=\s*['\"]?javascript:", re.IGNORECASE),
    re.compile(r"<iframe\b", re.IGNORECASE),
    re.compile(r"<svg\b", re.IGNORECASE),
    re.compile(r"<meta\s+[^>]*http-equiv", re.IGNORECASE),
    re.compile(r"document\s*\.", re.IGNORECASE),
    re.compile(r"window\s*\.", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"settimeout\s*\(", re.IGNORECASE),
    re.compile(r"setinterval\s*\(", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE),
    re.compile(r"<body\s+onload", re.IGNORECASE),
]
def is_weird_unicode(ch: str) -> bool:
    cp = ord(ch)
    for a, b in WEIRD_UNICODE_RANGES:
        if a <= cp <= b:return True
    return False
def is_forbidden_category(ch: str) -> bool:
    cat = unicodedata.category(ch)
    if cat in {'Cc', 'Cf', 'Cs', 'Co', 'Cn'}:
        if ch in ALLOW_CONTROL_WHITESPACE:return False
        return True
    return False
def remove_invisibles(text: str) -> str:return ''.join(c for c in text if not is_weird_unicode(c))
def normalize_and_clean(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = remove_invisibles(text)
    return text
def tokenize(text: str) -> list:return re.findall(r"[a-zA-Z_]+|\d+|[^\w\s]", text.lower())
def detect_sql_payload(text: str) -> dict:
    cleaned = normalize_and_clean(text)
    tokens = tokenize(cleaned)
    sql_hits = [tok for tok in tokens if tok in SQL_KEYWORDS]
    suspicious = len(sql_hits) >= 2 or ("or" in tokens and "=" in tokens)
    comment_matches = []
    for pattern in SQL_COMMENT_PATTERNS:
        match = pattern.search(cleaned)
        if match:comment_matches.append(match.group())
    if comment_matches:suspicious = True
    return {
        'suspicious': suspicious,
        'tokens': tokens,
        'sql_hits': sql_hits,
        'sql_comments': comment_matches
    }
def safe_str(x: Any) -> Union[str, None]:
    if isinstance(x, bytes):
        try:return x.decode('utf-8', 'strict')
        except UnicodeDecodeError:return None
    elif isinstance(x, str):return x
    else:return str(x)
def shorten(s: str, pos: int, radius: int = 15) -> str:
    start = max(0, pos - radius)
    end = min(len(s), pos + radius)
    return s[start:end].replace('\n', '\\n').replace('\r', '\\r')
def detect_xss_payload(text: str) -> dict:
    cleaned = normalize_and_clean(text)
    matches = []
    for pattern in XSS_PATTERNS:
        if pattern.search(cleaned):
            matches.append(pattern.pattern)
    return {
        'suspicious': bool(matches),
        'matched_patterns': matches
    }
def scan_string(path: str, s: str) -> List[Issue]:
    issues: List[Issue] = []
    if len(s) > MAX_LEN_PER_FIELD:
        issue = Issue(path, 'length_exceeded', count=len(s), extra={'max': MAX_LEN_PER_FIELD})
        issues.append(issue)
    n = unicodedata.normalize('NFC', s)
    if n != s:
        issue = Issue(path, 'unicode_normalization_changed', extra={'original_len': len(s), 'normalized_len': len(n)})
        issues.append(issue)
        raise UnicodeNormalizationChangedError("Texto Unicode normalizado", path=path, issue=issue)
    s = n
    sql_check = detect_sql_payload(s)
    if sql_check['suspicious']:
        issue = Issue(path, 'sql_injection_like_payload', snippet=shorten(s, 0), extra={'sql_tokens_detected': sql_check['sql_hits'],'sql_comment_patterns': sql_check['sql_comments'],'tokens': sql_check['tokens']})
        raise SQLInjectionDetectedError("Posible payload SQL detectado", path=path, issue=issue)
    xss_check = detect_xss_payload(s)
    if xss_check['suspicious']:
        issue = Issue(path, 'xss_like_payload', snippet=shorten(s, 0), extra={'matched_patterns': xss_check['matched_patterns']})
        raise XSSDetectedError("Posible payload XSS detectado", path=path, issue=issue)
    counter = Counter(s)
    for ch, cnt in counter.items():
        cp = f"U+{ord(ch):04X}"
        cat = unicodedata.category(ch)
        if ch in FORBIDDEN_CHARS or is_weird_unicode(ch) or is_forbidden_category(ch):
            issue = Issue(path, 'invalid_char_detected', char=repr(ch), codepoint=cp, category=cat, count=cnt)
            issues.append(issue)
            raise InvalidCharactersError("Caracter inválido detectado", path=path, issue=issue)
    return issues
def walk(obj: Any, path: str = '$') -> List[Issue]:
    issues: List[Issue] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            k_s = safe_str(k)
            if k_s is None:
                issue = Issue(f'{path}.<key>', 'invalid_bytes_key')
                issues.append(issue)
                raise InvalidBytesError("Clave no válida (bytes)", path=f'{path}.<key>', issue=issue)
            else:
                issues.extend(scan_string(f'{path}["{k_s}"]<key>', k_s))
            issues.extend(walk(v, f'{path}["{k}"]'))
    elif isinstance(obj, (list, tuple, set)):
        for idx, item in enumerate(obj):
            issues.extend(walk(item, f'{path}[{idx}]'))
    else:
        s = safe_str(obj)
        if s is None:
            issue = Issue(path, 'invalid_bytes_value')
            issues.append(issue)
            raise InvalidBytesError("Valor no válido (bytes)", path=path, issue=issue)
        issues.extend(scan_string(path, s))
    return issues
def validate_extended_payload(dato: Any) -> dict:
    issues = walk(dato)
    return {
        "valido": len(issues) == 0,
        "errores": [i.problem for i in issues],
        "detalles": issues
    }
def load_jconfig() -> dict:
    try:
        config_filename = os.getenv("JCONFIG_FILENAME")
        if not config_filename:raise ConfigFileNotFoundError("La variable de entorno JCONFIG_FILENAME no está definida.")
        config_path = find_file(config_filename)
        with open(config_path, 'r') as f:
            try:return json5.load(f)
            except Exception as e:raise ConfigParseError(f"Error al parsear JSON: {e}")
    except FindFileError as e:raise
    except Exception as e:raise ConfigParseError(e)
def mapApplications(app, jconfig: dict):
    try:
        endpoint_map = jconfig.get('endpoints-map', {})
        for url_prefix, import_entry in endpoint_map.items():
            import_path = import_entry[0] if isinstance(import_entry, list) else import_entry
            if '.' not in import_path:
                logger.warning(f"Ruta malformada: {import_path}")
                continue
            *module_parts, bp_var = import_path.split('.')
            module_str = '.'.join(module_parts)
            try:module = importlib.import_module(module_str)
            except Exception as e:raise BlueprintImportError(f"Error importando módulo {module_str}: {e}")
            try:blueprint = getattr(module, bp_var)
            except AttributeError:raise InvalidBlueprintError(f"Blueprint '{bp_var}' no existe en módulo {module_str}")
            if not hasattr(blueprint, 'register'):raise InvalidBlueprintError(f"{bp_var} no parece un Blueprint válido.")
            app.register_blueprint(blueprint, url_prefix=f'/{url_prefix}')
            logger.info(f"Registrado: {url_prefix} ← {import_path}")
    except Exception as e:raise MapApplicationsError(e)
class TimeManager:
    def __init__(self):
        try:
            self.localzone = ZoneInfo(tzlocal.get_localzone_name())
            self.utczone = ZoneInfo("UTC")
            self.jwt_exp_days = int(os.getenv("JWT_EXP_DAYS", "30"))
        except Exception as e:raise TimeManagerError(f"Error inicializando zonas horarias o JWT_EXP_DAYS: {e}")
    def get_timestamp(self, tz: ZoneInfo = None, fmt: str = "%a, %B %-d, %Y, %H:%M:%S") -> str:
        tz = tz or self.localzone
        try:return datetime.now(tz=tz).strftime(fmt)
        except Exception as e:raise TimeManagerError(f"No se pudo obtener timestamp: {e}")
    def get_timestamp_epoch(self, tz: ZoneInfo = None) -> int:
        tz = tz or self.utczone
        try:return int(datetime.now(tz=tz).timestamp())
        except Exception as e:raise TimeManagerError(f"No se pudo obtener timestamp epoch: {e}")
    def get_timestamp_iso(self, tz: ZoneInfo = None) -> str:
        tz = tz or self.localzone
        try:return datetime.now(tz=tz).isoformat()
        except Exception as e:raise TimeManagerError(f"No se pudo obtener timestamp ISO: {e}")
    def get_jwt_expiration_date(
        self,
        days: int | None = None,
        hours: int = 0,
        minutes: int = 0,
        seconds: int = 0
    ) -> datetime:
        try:
            if days is None and hours == 0 and minutes == 0 and seconds == 0:days = self.jwt_exp_days
            for val, name in zip([days, hours, minutes, seconds], ["days","hours","minutes","seconds"]):
                if val is not None and not isinstance(val, int):raise TimeManagerError(f"{name} debe ser int o None")
            return datetime.now(tz=self.utczone) + timedelta(days=days or 0, hours=hours, minutes=minutes, seconds=seconds)
        except Exception as e:raise TimeManagerError(f"No se pudo calcular expiración JWT: {e}")
    def get_jwt_expiration_timestamp(
        self,
        days: int | None = None,
        hours: int = 0,
        minutes: int = 0,
        seconds: int = 0
    ) -> int:
        try:
            exp_date = self.get_jwt_expiration_date(days=days, hours=hours, minutes=minutes, seconds=seconds)
            return int(exp_date.timestamp())
        except Exception as e:
            raise TimeManagerError(f"No se pudo calcular timestamp de expiración JWT: {e}")
class JWTManager:
    def __init__(self, secret: Optional[str] = None, algorithm: str = "HS256"):
        self.secret = secret or os.getenv("JWT_SECRET") or os.getenv("JWK_SECRET")
        if not self.secret:raise JWTError("No se encontró secreto JWT en entorno (JWT_SECRET/JWK_SECRET).")
        self.algorithm = algorithm
    def encode(self, payload: dict, expires_delta: Optional[timedelta] = None) -> str:
        try:
            data = payload.copy()
            if expires_delta is not None:data["exp"] = int((datetime.utcnow() + expires_delta).timestamp())
            token = jwt.encode(data, self.secret, algorithm=self.algorithm)
            if isinstance(token, bytes):token = token.decode('utf-8')
            return token
        except Exception as e:raise JWTEncodeError(f"Error al codificar JWT: {e}")
    def decode(self, token: str, verify_exp: bool = True) -> dict:
        try:
            options = {"verify_exp": verify_exp}
            payload = jwt.decode(token, self.secret, algorithms=[self.algorithm], options=options)
            return payload
        except jwt.ExpiredSignatureError as e:raise JWTDecodeError(f"Token expirado: {e}")
        except jwt.InvalidTokenError as e:raise JWTDecodeError(f"Token inválido: {e}")
        except Exception as e:raise JWTDecodeError(f"Error al decodificar JWT: {e}")
class Obfuscator:
    def __init__(self):pass
    def caesar_cipher(self, text: str, shift: int = 2) -> str:
        try:
            result_chars = []
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    result_chars.append(chr((ord(c) - base + shift) % 26 + base))
                else:result_chars.append(c)
            return ''.join(result_chars)
        except Exception as e:raise ObfuscationError(f"Error en caesar_cipher: {e}")
    def caesar_decipher(self, text: str, shift: int = 2) -> str:return self.caesar_cipher(text, -shift)
    def obfuscate_jwt(self, token: str, shift: int = 2) -> str:
        try:return self.caesar_cipher(token, shift)
        except Exception as e:raise ObfuscationError(f"Error obfuscating JWT: {e}")
    def deobfuscate_jwt(self, obfuscated: str, shift: int = 2) -> str:
        try:return self.caesar_decipher(obfuscated, shift)
        except Exception as e:raise ObfuscationError(f"Error deobfuscating JWT: {e}")
class PasswordManager:
    def __init__(self):pass
    def hash_password(self, password: str) -> str:
        try:
            if not isinstance(password, str):raise PasswordHashError("Password debe ser str")
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            return hashed.decode('utf-8')
        except PasswordHashError:raise
        except Exception as e:raise PasswordHashError(f"Error al hashear password: {e}")
    def verify_password(self, password: str, hashed: str) -> bool:
        try:
            if not isinstance(password, str) or not isinstance(hashed, str):raise PasswordHashError("Tipos inválidos para verify_password")
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:raise PasswordHashError(f"Error verificando password: {e}")
class RequestValidator:
    def __init__(self):pass
    def is_get_request_valid(self, request: Any) -> bool:
        try:
            headers = getattr(request, "headers", {}) or {}
            for h in REQUIRED_GET_HEADERS:
                if not headers.get(h):
                    logger.debug("Falta header GET: %s", h)
                    return False
            return True
        except Exception as e:raise RequestValidationError(f"Error validando GET request: {e}")
    def is_post_request_valid(self, request: Any, require_json: bool = True) -> bool:
        try:
            headers = getattr(request, "headers", {}) or {}
            content_type = headers.get("Content-Type")
            if not content_type:raise MissingHeaderError("Content-Type faltante en POST request")
            if require_json:
                if not hasattr(request, "get_json"):raise BadRequestPayloadError("Objeto request no soporta get_json()")
                payload = request.get_json(silent=True) if callable(getattr(request, "get_json", None)) else None
                if not payload:
                    logger.debug("POST request sin JSON válido")
                    return False
            return True
        except RequestValidationError:raise
        except Exception as e:raise RequestValidationError(f"Error validando POST request: {e}")
class SecurityManager:
    def __init__(self, jwt_secret: Optional[str] = None):
        try:
            self.jwt = JWTManager(secret=jwt_secret)
            self.obfuscator = Obfuscator()
            self.pw = PasswordManager()
            self.validator = RequestValidator()
        except Exception as e:raise SecurityError(f"Error inicializando SecurityManager: {e}")
    def firmar_renderizado(self, payload: dict, expires_delta: Optional[timedelta] = None, obfuscate: bool = True, shift: int = 2) -> str:
        token = self.jwt.encode(payload, expires_delta=expires_delta)
        return self.obfuscator.obfuscate_jwt(token, shift) if obfuscate else token
    def comprobar_renderizado(self, token_or_obf: str, obfuscated: bool = True, shift: int = 2) -> dict:
        try:
            token = self.obfuscator.deobfuscate_jwt(token_or_obf, shift) if obfuscated else token_or_obf
            payload = self.jwt.decode(token)
            return payload
        except JWTError:raise
        except ObfuscationError:raise
        except Exception as e:raise SecurityError(f"Error comprobando renderizado: {e}")
    def encriptar_password(self, password: str) -> str:return self.pw.hash_password(password)
    def verificar_password(self, password: str, hashed: str) -> bool:return self.pw.verify_password(password, hashed)
    def is_get_request_valid(self, request: Any) -> bool:return self.validator.is_get_request_valid(request)
    def is_post_request_valid(self, request: Any, require_json: bool = True) -> bool:return self.validator.is_post_request_valid(request, require_json=require_json)
    def gen_cadena(self, length: int = 12) -> str:return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    def gen_segundos(self, min_secs: int = 3, max_secs: int = 5) -> int:return random.randint(min_secs, max_secs)
class SqlManager:
    def __init__(self):
        pass
    def query(self, sql, params=None, fetch=False):
        params = params or ()
        with get_conn() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    result = cur.fetchall() if fetch else None
                    conn.commit()
                    return result
            except Exception as e:
                conn.rollback()
                raise SqlError(e)
class Centinela:
    def __init__(self):
        self.check_interval_seconds = int(os.getenv('CENTINELA_CHECK_INTERVAL_SECONDS'))
        self.disk_path = str(os.getenv("CENTINELA_DISK_PATH"))
        self.disk_free_warning_pct = float(os.getenv("CENTINELA_DISK_FREE_WARNING_PCT"))
        self.cpu_warning_pct = float(os.getenv("CENTINELA_CPU_WARNING_PCT"))
        self.ram_warning_pct = float(os.getenv("CENTINELA_RAM_WARNING_PCT"))
        self.fd_warning_threshold = int(os.getenv("CENTINELA_FD_WARNING_THRESHOLD"))
        self.worker_names = ["myworker", "celery", "gunicorn"]
        self.worker_min_count = int(os.getenv("CENTINELA_WORKER_MIN_COUNT"))
        self.internet_check_host = ("1.1.1.1", 53)
        self.internet_timeout = int(os.getenv("CENTINELA_INTERNET_TIMEOUT"))
    def now_iso(self):return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    def check_internet(self):
        try:
            sock = socket.create_connection(self.internet_check_host, self.internet_timeout)
            sock.close()
            return True
        except OSError:return False
    def check_disk(self):
        try:
            du = psutil.disk_usage(self.disk_path)
            free_pct = (du.free / du.total) * 100.0
            return {"total": du.total, "used": du.used, "free": du.free, "free_pct": free_pct}
        except Exception as e:return {"error": str(e)}
    def check_cpu(self):
        try:
            pct = psutil.cpu_percent(interval=0.5)
            return {"cpu_pct": pct}
        except Exception as e:return {"error": str(e)}
    def check_ram(self):
        try:
            vm = psutil.virtual_memory()
            return {"ram_pct": vm.percent, "total": vm.total, "available": vm.available}
        except Exception as e:return {"error": str(e)}
    def check_fds_unix(self):        
        try:
            if os.path.exists("/proc/sys/fs/file-nr"):
                with open("/proc/sys/fs/file-nr", "r") as f:
                    parts = f.read().strip().split()
                    if len(parts) >= 3:
                        allocated = int(parts[0])
                        unused = int(parts[1])
                        max_fds = int(parts[2])
                        used = allocated - unused
                        free = max_fds - used
                        return {"max": max_fds, "used": used, "free": free}
        except Exception:pass
        try:
            total_open = 0
            for p in psutil.process_iter(["pid"]):
                try:total_open += p.num_fds()
                except Exception:pass
            return {"approx_open_fds": total_open}
        except Exception as e:return {"error": str(e)}
    def count_workers(self):
        lower_names = [n.lower() for n in self.worker_names]
        count = 0
        matches = []
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pname = (p.info.get("name") or "").lower()
                cmd = " ".join(p.info.get("cmdline") or []).lower()
                for name in lower_names:
                    if name in pname or name in cmd:
                        count += 1
                        matches.append({"pid": p.info["pid"], "name": p.info.get("name"), "cmdline": p.info.get("cmdline")})
                        break
            except Exception:continue
        return {"count": count, "matches": matches}
    def classify_and_log(self, check_name, data):
        timestamp = self.now_iso()
        level = "INFO"
        msg = ""
        if check_name == "internet":
            ok = data is True
            if not ok:
                level = "WARNING"
                msg = "No internet (connection failed)"
            else:msg = "Internet OK"
        elif check_name == "disk":
            if "error" in data:
                level = "ERROR"
                msg = f"Disk check error: {data['error']}"
            else:
                free_pct = data["free_pct"]
                msg = f"Disk free {free_pct:.1f}% ({data['free']//1024//1024} MB free)"
                if free_pct < self.disk_free_warning_pct:level = "WARNING"
        elif check_name == "cpu":
            if "error" in data:
                level = "ERROR"
                msg = f"CPU check error: {data['error']}"
            else:
                cpu_pct = data["cpu_pct"]
                msg = f"CPU usage {cpu_pct:.1f}%"
                if cpu_pct > self.cpu_warning_pct:level = "WARNING"
        elif check_name == "ram":
            if "error" in data:
                level = "ERROR"
                msg = f"RAM check error: {data['error']}"
            else:
                ram_pct = data["ram_pct"]
                msg = f"RAM usage {ram_pct:.1f}% ({data['available']//1024//1024} MB available)"
                if ram_pct > self.ram_warning_pct:level = "WARNING"
        elif check_name == "fds":
            if "error" in data:
                level = "ERROR"
                msg = f"FDs check error: {data['error']}"
            else:
                if data.get("free") is not None:
                    free = data["free"]
                    msg = f"FDs free: {free}"
                    if isinstance(free, int) and free < self.fd_warning_threshold:level = "WARNING"
                else:msg = f"FDs approx open: {data.get('approx_open_fds')}"
        elif check_name == "workers":
            cnt = data.get("count", 0)
            msg = f"Workers found: {cnt}"
            if cnt < self.worker_min_count:
                level = "WARNING"
                msg += " (below expected)"
        print(f"[{timestamp}] {level:7} {check_name:10} - {msg}")
    def run_cycle(self):
        internet_ok = self.check_internet()
        self.classify_and_log("internet", internet_ok)
        disk = self.check_disk()
        self.classify_and_log("disk", disk)
        cpu = self.check_cpu()
        self.classify_and_log("cpu", cpu)
        ram = self.check_ram()
        self.classify_and_log("ram", ram)
        fds = self.check_fds_unix()
        self.classify_and_log("fds", fds)
        workers = self.count_workers()
        self.classify_and_log("workers", workers)
    
    def main(self):
        print(f"[{self.now_iso()}] Centinela arrancando. Intervalo {self.check_interval_seconds}s")
        try:
            while True:
                self.run_cycle()
                time.sleep(self.check_interval_seconds)
        except KeyboardInterrupt:print(f"[{self.now_iso()}] Centinela detenido por usuario.")