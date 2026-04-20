"""TriageOne — Auto-detect IOC type from raw input."""

from __future__ import annotations
import re
from backend.models.ioc import IOCType

_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
_IPV6 = re.compile(
    r"^("
    r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}|"
    r":((:[0-9a-fA-F]{1,4}){1,7}|:)"
    r")$"
)
_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")
_URL = re.compile(r"^https?://", re.IGNORECASE)
_FILENAME = re.compile(r"^[\w\-. ]+\.\w{1,10}$")
_FILE_EXTENSIONS = {
    "exe","dll","bat","cmd","ps1","msi","scr","vbs","js",
    "doc","docx","xls","xlsx","ppt","pptx","pdf","rtf",
    "zip","rar","7z","tar","gz","iso","img",
    "jpg","jpeg","png","gif","bmp","svg",
    "py","rb","php","sh","pl","java","class","jar",
    "csv","json","xml","yaml","yml","toml","ini","cfg",
    "log","txt","md","html","htm","css",
    "bin","dat","tmp","bak","swp","apk","ipa","deb","rpm","eml","msg",
}


def detect_ioc_type(value: str) -> IOCType:
    v = value.strip()
    if not v:
        return IOCType.UNKNOWN
    v = v.replace("[.]", ".").replace("hxxp", "http").replace("hxxps", "https")
    if _URL.match(v): return IOCType.URL
    if _SHA256.match(v): return IOCType.HASH_SHA256
    if _SHA1.match(v): return IOCType.HASH_SHA1
    if _MD5.match(v): return IOCType.HASH_MD5
    if _IPV4.match(v): return IOCType.IP
    if _IPV6.match(v): return IOCType.IP
    if "." in v:
        ext = v.rsplit(".", 1)[-1].lower()
        if ext in _FILE_EXTENSIONS and _FILENAME.match(v):
            return IOCType.FILENAME
    if _DOMAIN.match(v) and "." in v: return IOCType.DOMAIN
    if _FILENAME.match(v): return IOCType.FILENAME
    return IOCType.UNKNOWN


def defang(value: str) -> str:
    return (value.strip().replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://"))
