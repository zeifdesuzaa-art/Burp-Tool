# -*- coding: utf-8 -*-
# SourceMap Hunter Pro v2.2 - Jython 2.7 | Burp Community | Passive-Only
# CRITICAL FIXES:
# 1. Added missing SwingUtilities & JFileChooser imports
# 2. Fixed sourceMappingURL regex to handle //#, /*#, //@, and bare attributes
# 3. Fixed base64 inline map regex to handle charset parameter
# 4. Relaxed _isComplex from 3/4 to 2/4 character classes (was killing real secrets)
# 5. Added sources[] array analysis when sourcesContent is absent
# 6. Added debug output so you can see map detection in the Extender output

from __future__ import print_function
from burp import IBurpExtender, IHttpListener, ITab

from java.awt import Color
from java.awt import Font
from java.awt import BorderLayout
from java.awt import FlowLayout
from java.awt import Toolkit
from java.awt.event import MouseAdapter
from java.awt.datatransfer import StringSelection

from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JCheckBox
from javax.swing import JTextField
from javax.swing import JButton
from javax.swing import JTable
from javax.swing import JScrollPane
from javax.swing import JTextArea
from javax.swing import JSplitPane
from javax.swing import JPopupMenu
from javax.swing import JMenuItem
from javax.swing import BoxLayout
from javax.swing import ListSelectionModel
from javax.swing import SwingUtilities
from javax.swing import JFileChooser
from javax.swing import RowFilter
from javax.swing.border import TitledBorder
from javax.swing.border import EmptyBorder
from javax.swing.border import CompoundBorder
from javax.swing.border import LineBorder
from javax.swing.table import DefaultTableModel
from javax.swing.table import DefaultTableCellRenderer
from javax.swing.table import TableRowSorter
from javax.swing.event import ListSelectionListener

from java.lang import Runnable
from java.lang import Object
from java.util import ArrayList

import re
import json
import hashlib
import math
import base64
import codecs

# ==================== CONFIG & CONSTANTS ====================
MAX_RESPONSE_SIZE = 5 * 1024 * 1024
ENTROPY_THRESHOLD = 3.5      # Lowered slightly for real-world keys
CONTEXT_WINDOW = 50
CDN_SKIP_LIST = frozenset([
    'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'googleapis.com',
    'ajax.googleapis.com', 'fonts.googleapis.com', 'amazonaws.com', 'cloudfront.net',
    'fastly.net', 'akamai.net', 'akamaiedge.net', 'facebook.com', 'google-analytics.com',
    'googletagmanager.com', 'doubleclick.net', 'hotjar.com', 'mixpanel.com',
    'segment.io', 'sentry.io', 'bugsnag.com', 'intercomcdn.com', 'hs-scripts.com',
    'zdassets.com', 'mktossl.com', 'salesforceliveagent.com', 'datadoghq.com',
    'launchdarkly.com', 'stripe.com', 'paypal.com', 'recaptcha.net'
])

TYPE_COLORS = {
    "AWS Key": Color(255, 100, 100),
    "Secret": Color(255, 80, 80),
    "Cloud Bucket": Color(150, 200, 255),
    "Endpoint": Color(200, 255, 200),
    "Config Token": Color(255, 230, 150),
    "SourceMap Ref": Color(220, 220, 220),
    "JWT": Color(255, 180, 255),
    "Private Key": Color(255, 50, 50),
    "GitHub Token": Color(150, 255, 150),
    "Slack Token": Color(100, 200, 255),
    "Firebase Key": Color(255, 200, 100),
    "Google API Key": Color(200, 150, 255),
    "Basic Auth": Color(255, 100, 150),
    "IP/Host": Color(200, 200, 200),
    "Bearer Token": Color(255, 220, 180)
}

# ==================== HELPER FUNCTIONS ====================
def calculate_entropy(s):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p, 2) for p in prob if p > 0)

def normalize_url(map_ref, protocol, host, request_url):
    if not map_ref:
        return None
    if map_ref.startswith("http"):
        return map_ref
    if map_ref.startswith("//"):
        return protocol + ":" + map_ref
    if map_ref.startswith("/"):
        return protocol + "://" + host + map_ref
    base = request_url.rsplit("/", 1)[0]
    return base + "/" + map_ref

def sha256_hash(val):
    return hashlib.sha256(val.encode('utf-8', 'ignore')).hexdigest()

# ==================== CUSTOM TABLE RENDERER ====================
class ColoredRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            ftype = table.getValueAt(row, 1)
            color = TYPE_COLORS.get(str(ftype), None)
            if color:
                comp.setBackground(color)
            else:
                comp.setBackground(Color.WHITE)
        return comp

# ==================== RUNNABLE HELPERS (Jython-safe EDT) ====================
class TableAdder(Runnable):
    def __init__(self, model, row):
        self.model = model
        self.row = row
    def run(self):
        self.model.addRow(self.row)

class RowRemover(Runnable):
    def __init__(self, model, row):
        self.model = model
        self.row = row
    def run(self):
        self.model.removeRow(self.row)

class ClearTableRunner(Runnable):
    def __init__(self, model):
        self.model = model
    def run(self):
        self.model.setRowCount(0)

class StatsUpdater(Runnable):
    def __init__(self, label, text):
        self.label = label
        self.text = text
    def run(self):
        self.label.setText(self.text)

class DetailUpdater(Runnable):
    def __init__(self, area, text):
        self.area = area
        self.text = text
    def run(self):
        self.area.setText(self.text)

# ==================== MAIN EXTENDER ====================
class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SourceMap Hunter Pro v2.2")
        callbacks.registerHttpListener(self)

        # Precompile Patterns (Jython 2.7 / ASCII-safe)
        # FIX: Made comment prefix optional and added [#@]? to catch //#, /*#, //@
        self._map_ref_re = re.compile(
            r'(?:/\*+|//|/\*\*)?[#@]?\s*sourceMappingURL\s*=\s*(?:url\()?["\']?([^"\'\s?#>]+)["\']?[\)]?',
            re.I
        )
        # FIX: Handles charset parameter between MIME type and base64
        self._base64_map_re = re.compile(
            r'sourceMappingURL=data:[^;]+(?:;[^;]+)*;base64,([A-Za-z0-9+/=]+)',
            re.I
        )
        self._endpoint_re = re.compile(
            r'(https?://[^\s"\'<>]{5,120}|/(?:api|graphql|rest|webhook|auth|token|login|register|admin|dashboard|user|account|payment|billing|subscription|oauth|callback|hook|v1|v2|v3|internal|private)[a-zA-Z0-9_\-/]{0,80}(?:\.[a-zA-Z0-9]{1,10})?)',
            re.I
        )
        self._secret_context_re = re.compile(
            r'(?:secret|key|token|password|api_key|apikey|access_key|client_secret|jwt_secret|private_key|auth_token|session|csrf)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.+/=]{16,80})',
            re.I
        )
        self._bearer_re = re.compile(r'(?i)bearer\s+([a-zA-Z0-9_\-\.=]{20,})')
        self._aws_key_re = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
        self._aws_secret_re = re.compile(
            r'(?:aws_secret_access_key|secret_access_key|aws_secret)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
            re.I
        )
        self._s3_re = re.compile(
            r'\b([a-z0-9][a-z0-9._-]*\.s3[\.-][a-z0-9-]+\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9._-]+)\b',
            re.I
        )
        self._gcp_re = re.compile(
            r'\b([a-z0-9][-a-z0-9._]*\.storage\.googleapis\.com|storage\.cloud\.google\.com/[a-z0-9._-]+)\b',
            re.I
        )
        self._jwt_re = re.compile(r'\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b')
        self._private_key_re = re.compile(
            r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{100,5000}-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            re.I
        )
        self._github_re = re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b')
        self._slack_re = re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}(?:-[a-zA-Z0-9]{24})?\b')
        self._firebase_re = re.compile(r'\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b')
        self._google_api_re = re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')
        self._basic_auth_re = re.compile(r'\bhttps?://[^:]+:[^@]+@[^\s"\'<>]+\b')
        self._ip_re = re.compile(
            r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|localhost|[a-z0-9_-]+\.local(?:domain)?)(?::\d{1,5})?\b',
            re.I
        )
        self._generic_token_re = re.compile(r'\b[A-Za-z0-9_\-\.+/=]{32,64}\b')

        # State
        self._seen_hashes = set()
        self._false_positives = set()

        self._initUI()
        callbacks.addSuiteTab(self)
        callbacks.printOutput("[*] SourceMap Hunter Pro v2.2 loaded. Passive analysis active. Authorized targets only.")

    def _initUI(self):
        self._mainPanel = JPanel(BorderLayout(10, 10))
        self._mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))

        banner = JLabel("  [!] AUTHORIZED USE ONLY: Passive analysis on scoped targets. Zero active requests. WAF-safe.", JLabel.LEFT)
        banner.setForeground(Color(150, 0, 0))
        banner.setFont(Font("SansSerif", Font.BOLD, 12))
        banner.setBorder(CompoundBorder(EmptyBorder(2,5,2,5), LineBorder(Color(200, 200, 200), 1)))

        topPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._scopeCheck = JCheckBox("Strict Scope Only", True)
        self._filterField = JTextField("", 18)
        self._filterField.setToolTipText("Live filter by URL, Type, Value, or Context")
        self._searchBtn = JButton("Filter")

        typePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        typePanel.setBorder(TitledBorder("Show Types"))
        self._typeFilters = {}
        typeList = [
            "SourceMap Ref", "Endpoint", "Secret", "AWS Key", "Cloud Bucket",
            "Config Token", "JWT", "Private Key", "GitHub Token", "Slack Token",
            "Firebase Key", "Google API Key", "Basic Auth", "IP/Host", "Bearer Token"
        ]
        for t in typeList:
            cb = JCheckBox(t, True)
            cb.setFont(Font("SansSerif", Font.PLAIN, 10))
            self._typeFilters[t] = cb
            typePanel.add(cb)

        topPanel.add(self._scopeCheck)
        topPanel.add(JLabel("Search:"))
        topPanel.add(self._filterField)
        topPanel.add(self._searchBtn)

        self._columns = ["URL", "Type", "Value", "Confidence", "Source", "Context", "Hash"]
        self._tableModel = DefaultTableModel(self._columns, 0)
        self._table = JTable(self._tableModel)
        self._table.setDefaultRenderer(Object, ColoredRenderer())
        self._table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._table.getColumnModel().getColumn(0).setPreferredWidth(250)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(100)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(180)
        self._table.getColumnModel().getColumn(3).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(4).setPreferredWidth(120)
        self._table.getColumnModel().getColumn(5).setPreferredWidth(300)
        self._table.getColumnModel().getColumn(6).setPreferredWidth(80)
        scroll = JScrollPane(self._table)

        self._detailsArea = JTextArea(4, 80)
        self._detailsArea.setEditable(False)
        self._detailsArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._detailsArea.setLineWrap(True)
        detailsScroll = JScrollPane(self._detailsArea)
        detailsScroll.setBorder(TitledBorder("Match Context"))

        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll, detailsScroll)
        splitPane.setResizeWeight(0.75)

        self._popup = JPopupMenu()
        copyUrlItem = JMenuItem("Copy URL")
        copyValItem = JMenuItem("Copy Value")
        copyRowItem = JMenuItem("Copy Row")
        markFPItem = JMenuItem("Mark as False Positive")
        self._popup.add(copyUrlItem)
        self._popup.add(copyValItem)
        self._popup.add(copyRowItem)
        self._popup.addSeparator()
        self._popup.add(markFPItem)
        self._table.addMouseListener(self._PopupMouseListener(self))
        copyUrlItem.addActionListener(self._onCopyUrl)
        copyValItem.addActionListener(self._onCopyVal)
        copyRowItem.addActionListener(self._onCopyRow)
        markFPItem.addActionListener(self._onMarkFP)

        bottomPanel = JPanel(BorderLayout())
        statsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._statsLabel = JLabel("Matches: 0 | Secrets: 0 | Endpoints: 0 | Maps: 0 | Deduped: 0 | FPs: 0")
        statsPanel.add(self._statsLabel)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self._exportCSV = JButton("Export CSV")
        self._exportJSON = JButton("Export JSON")
        self._clearBtn = JButton("Clear Table")
        self._resetDedupBtn = JButton("Reset Dedup")
        btnPanel.add(self._clearBtn)
        btnPanel.add(self._resetDedupBtn)
        btnPanel.add(self._exportCSV)
        btnPanel.add(self._exportJSON)

        bottomPanel.add(statsPanel, BorderLayout.WEST)
        bottomPanel.add(btnPanel, BorderLayout.EAST)

        self._searchBtn.addActionListener(self._onFilter)
        self._filterField.addActionListener(self._onFilter)
        self._exportCSV.addActionListener(self._onExportCSV)
        self._exportJSON.addActionListener(self._onExportJSON)
        self._clearBtn.addActionListener(self._onClear)
        self._resetDedupBtn.addActionListener(self._onResetDedup)

        class RowListener(ListSelectionListener):
            def __init__(self, extender):
                self.extender = extender
            def valueChanged(self, e):
                if e.getValueIsAdjusting():
                    return
                self.extender._onRowSelect()
        self._table.getSelectionModel().addListSelectionListener(RowListener(self))

        northBox = JPanel()
        northBox.setLayout(BoxLayout(northBox, BoxLayout.Y_AXIS))
        northBox.add(topPanel)
        northBox.add(typePanel)

        self._mainPanel.add(banner, BorderLayout.NORTH)
        self._mainPanel.add(northBox, BorderLayout.PAGE_START)
        self._mainPanel.add(splitPane, BorderLayout.CENTER)
        self._mainPanel.add(bottomPanel, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "SourceMap Hunter Pro"

    def getUiComponent(self):
        return self._mainPanel

    # ==================== PASSIVE ANALYSIS ====================
    def processHttpMessage(self, toolFlag, messageIsRequest, requestResponse):
        if messageIsRequest:
            return

        req_info = self._helpers.analyzeRequest(requestResponse)
        url_obj = req_info.getUrl()
        host = requestResponse.getHttpService().getHost()

        if self._scopeCheck.isSelected() and not self._callbacks.isInScope(url_obj):
            return
        if any(host.endswith(cdn) or host == cdn for cdn in CDN_SKIP_LIST):
            return

        response = requestResponse.getResponse()
        if response is None or len(response) > MAX_RESPONSE_SIZE:
            return

        try:
            resp_str = self._helpers.bytesToString(response)
        except:
            return

        resp_info = self._helpers.analyzeResponse(response)
        headers = resp_info.getHeaders()
        req_url = url_obj.toString()
        protocol = requestResponse.getHttpService().getProtocol()

        found_something = False

        # Check X-SourceMap / Source-Map headers
        for header in headers:
            hlower = header.lower()
            if hlower.startswith("x-sourcemap:") or hlower.startswith("source-map:"):
                map_ref = header.split(":", 1)[1].strip()
                norm_url = normalize_url(map_ref, protocol, host, req_url)
                if norm_url:
                    self._addFinding(req_url, "SourceMap Ref", norm_url, "Medium", "HTTP Header", "")
                    found_something = True

        # Check body for source map references
        has_map_ref = "sourceMappingURL" in resp_str or "sourceMapping" in resp_str
        is_map_ext = req_url.split("?")[0].endswith(".map")

        if not has_map_ref and not is_map_ext and not found_something:
            return

        if has_map_ref or is_map_ext:
            self._callbacks.printOutput("[*] SourceMap signal detected: " + req_url)

        # Parse inline base64 source maps
        for b64data in self._base64_map_re.findall(resp_str):
            try:
                decoded = base64.b64decode(b64data)
                map_json = json.loads(decoded)
                self._callbacks.printOutput("[+] Parsed inline base64 map from: " + req_url)
                self._parseMapJson(map_json, req_url, "inline_base64")
            except Exception as ex:
                self._callbacks.printOutput("[!] Inline base64 parse error: " + str(ex))

        # Parse external sourceMappingURL references
        for mref in self._map_ref_re.findall(resp_str):
            if isinstance(mref, tuple):
                mref = mref[0] or mref[1]
            if not mref:
                continue
            norm_url = normalize_url(mref, protocol, host, req_url)
            if not norm_url:
                continue
            self._addFinding(req_url, "SourceMap Ref", norm_url, "Medium", "JS/HTML", "")
            found_something = True

        # If current response is a map file, parse it
        is_map = is_map_ext
        if not is_map:
            for header in headers:
                if header.lower().startswith("content-type:"):
                    if "json" in header.lower():
                        is_map = True
                    break

        if is_map:
            self._callbacks.printOutput("[+] Processing .map file: " + req_url)
            try:
                map_json = json.loads(resp_str)
                self._parseMapJson(map_json, req_url, "map_file")
            except Exception as ex:
                self._callbacks.printOutput("[!] Map JSON parse error: " + str(ex))
            self._extractArtifacts(resp_str, req_url, "map_raw")

    def _parseMapJson(self, map_json, source_url, origin):
        sources = map_json.get("sources", [])
        sources_content = map_json.get("sourcesContent", [])

        # NEW: Analyze sources[] array even when sourcesContent is absent
        for src in sources:
            if not src:
                continue
            low = src.lower()
            if any(k in low for k in ['api','graphql','auth','token','webhook','admin','internal','private','svc','service','gateway','rest','endpoint']):
                h = sha256_hash("Endpoint" + src + "sources_array")
                if h not in self._seen_hashes and h not in self._false_positives:
                    self._seen_hashes.add(h)
                    self._addFinding(source_url, "Endpoint", src, "Medium", "sources_array", "")
            if any(k in low for k in ['config','secret','key','env','password','credential','jwt','aws','s3','token']):
                h = sha256_hash("Secret" + src + "sources_array")
                if h not in self._seen_hashes and h not in self._false_positives:
                    self._seen_hashes.add(h)
                    self._addFinding(source_url, "Secret", src, "Low", "sources_array", "")

        for idx, src in enumerate(sources_content or []):
            if not src:
                continue
            fname = sources[idx] if idx < len(sources) else "unknown"
            self._extractArtifacts(src, source_url, fname)

    def _getContext(self, text, start, end):
        ctx_start = max(0, start - CONTEXT_WINDOW)
        ctx_end = min(len(text), end + CONTEXT_WINDOW)
        snippet = text[ctx_start:ctx_end]
        snippet = snippet.replace("\n", " ").replace("\r", " ").replace("\t", " ")
        if len(snippet) > 200:
            snippet = snippet[:200] + "..."
        return snippet

    def _isComplex(self, s):
        """FIX: Relaxed to 2 of 4 classes. Was 3/4 which killed most real secrets."""
        has_lower = bool(re.search(r'[a-z]', s))
        has_upper = bool(re.search(r'[A-Z]', s))
        has_digit = bool(re.search(r'[0-9]', s))
        has_sym = bool(re.search(r'[^a-zA-Z0-9]', s))
        return sum([has_lower, has_upper, has_digit, has_sym]) >= 2

    def _isFalsePositivePattern(self, val):
        if re.match(r'^[a-z][a-z0-9]{0,2}$', val):
            return True
        if re.match(r'^#[0-9a-fA-F]{3,8}$', val):
            return True
        low = val.lower()
        common = ('true', 'false', 'null', 'undefined', 'function', 'var', 'return',
                  'if', 'else', 'for', 'while', 'class', 'const', 'let', 'new', 'this',
                  'window', 'document', 'console', 'log', 'error', 'length', 'prototype',
                  'constructor', 'toString', 'valueOf', 'name', 'index', 'module', 'exports',
                  'require', 'define', 'jquery', 'angular', 'react', 'vue', 'lodash', 'axios',
                  'fetch', 'promise', 'async', 'await', 'try', 'catch', 'finally', 'throw',
                  'break', 'continue', 'switch', 'case', 'default', 'do', 'typeof', 'instanceof',
                  'in', 'of', 'yield', 'void', 'delete', 'debugger', 'with')
        if low in common:
            return True
        if len(val) < 20 and val.isalpha() and val.islower():
            return True
        if len(set(val)) == 1:
            return True
        if re.match(r'^([a-z][0-9]?[,;]){3,}', val):
            return True
        return False

    def _extractArtifacts(self, text, source_url, file_name):
        if not text:
            return

        findings = []

        # Endpoints
        for m in self._endpoint_re.finditer(text):
            val = m.group(0).strip().rstrip('.')
            if val.startswith(("<", ">", "{", "}", ";", ",", ")", "(", "[", "]", "'", '"')):
                continue
            conf = "High" if any(k in val.lower() for k in ['api','graphql','auth','token','webhook','v1/','v2/','admin','internal']) else "Medium"
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("Endpoint", val, conf, file_name, ctx))

        # Secrets with context & entropy
        for m in self._secret_context_re.finditer(text):
            val = m.group(1).strip()
            if len(val) < 16:
                continue
            if not self._isComplex(val):
                continue
            if calculate_entropy(val) >= ENTROPY_THRESHOLD:
                ctx = self._getContext(text, m.start(), m.end())
                findings.append(("Secret", val, "High", file_name, ctx))

        # Bearer tokens
        for m in self._bearer_re.finditer(text):
            val = m.group(1).strip()
            if len(val) >= 20 and calculate_entropy(val) >= ENTROPY_THRESHOLD:
                ctx = self._getContext(text, m.start(), m.end())
                findings.append(("Bearer Token", val, "High", file_name, ctx))

        # AWS Keys
        for m in self._aws_key_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("AWS Key", val, "High", file_name, ctx))

        # AWS Secret Access Key
        for m in self._aws_secret_re.finditer(text):
            val = m.group(1)
            if calculate_entropy(val) >= ENTROPY_THRESHOLD:
                ctx = self._getContext(text, m.start(), m.end())
                findings.append(("Secret", val, "High", file_name, ctx))

        # S3 Buckets
        for m in self._s3_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("Cloud Bucket", val, "High", file_name, ctx))

        # GCP Buckets
        for m in self._gcp_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("Cloud Bucket", val, "High", file_name, ctx))

        # JWT
        for m in self._jwt_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("JWT", val, "High", file_name, ctx))

        # Private Keys
        for m in self._private_key_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("Private Key", val, "Critical", file_name, ctx))

        # GitHub Tokens
        for m in self._github_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("GitHub Token", val, "High", file_name, ctx))

        # Slack Tokens
        for m in self._slack_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("Slack Token", val, "High", file_name, ctx))

        # Firebase
        for m in self._firebase_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("Firebase Key", val, "High", file_name, ctx))

        # Google API
        for m in self._google_api_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("Google API Key", val, "High", file_name, ctx))

        # Basic Auth URLs
        for m in self._basic_auth_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("Basic Auth", val, "High", file_name, ctx))

        # Private IPs / localhost
        for m in self._ip_re.finditer(text):
            val = m.group(0)
            ctx = self._getContext(text, m.start(), m.end())
            findings.append(("IP/Host", val, "Medium", file_name, ctx))

        # Generic high-entropy tokens near config keywords
        for m in self._generic_token_re.finditer(text):
            val = m.group(0)
            if len(val) < 32:
                continue
            if not self._isComplex(val):
                continue
            ent = calculate_entropy(val)
            if ent < ENTROPY_THRESHOLD + 0.5:
                continue
            start = max(0, m.start() - CONTEXT_WINDOW)
            context = text[start:m.start()].lower()
            if any(k in context for k in ['config','env','secret','key','token','setting','jwt','aws','s3','auth','credential','password','api']):
                ctx = self._getContext(text, m.start(), m.end())
                findings.append(("Config Token", val, "Medium", file_name, ctx))

        # Deduplicate & add
        for ftype, fval, conf, src, ctx in findings:
            if self._isFalsePositivePattern(fval):
                continue
            h = sha256_hash(ftype + fval + src)
            if h not in self._seen_hashes and h not in self._false_positives:
                self._seen_hashes.add(h)
                self._addFinding(source_url, ftype, fval, conf, src, ctx)

    def _addFinding(self, url, ftype, value, confidence, source, context):
        h = sha256_hash(url + ftype + value + source)
        if h in self._seen_hashes or h in self._false_positives:
            return
        self._seen_hashes.add(h)
        SwingUtilities.invokeLater(TableAdder(self._tableModel, [url, ftype, value, confidence, source, context, h]))
        self._updateStats()

    def _updateStats(self):
        count = self._tableModel.getRowCount()
        secrets = 0
        endpoints = 0
        maps = 0
        for i in range(count):
            t = str(self._tableModel.getValueAt(i, 1))
            if t in ("Secret", "AWS Key", "Config Token", "JWT", "Private Key", "GitHub Token", "Slack Token", "Firebase Key", "Google API Key", "Basic Auth", "Bearer Token"):
                secrets += 1
            elif t == "Endpoint":
                endpoints += 1
            elif t == "SourceMap Ref":
                maps += 1
        dedup = len(self._seen_hashes)
        fp = len(self._false_positives)
        text = "Matches: %d | Secrets: %d | Endpoints: %d | Maps: %d | Deduped: %d | FPs: %d" % (count, secrets, endpoints, maps, dedup, fp)
        SwingUtilities.invokeLater(StatsUpdater(self._statsLabel, text))

    # ==================== UI HANDLERS ====================
    class _PopupMouseListener(MouseAdapter):
        def __init__(self, extender):
            self.extender = extender

        def mousePressed(self, e):
            if e.isPopupTrigger():
                self.extender._popup.show(e.getComponent(), e.getX(), e.getY())

        def mouseReleased(self, e):
            if e.isPopupTrigger():
                self.extender._popup.show(e.getComponent(), e.getX(), e.getY())

    def _popupMouseListener(self):
        return self._PopupMouseListener(self)

    def _onCopyUrl(self, e):
        rows = self._table.getSelectedRows()
        if not rows:
            return
        vals = [str(self._tableModel.getValueAt(self._table.convertRowIndexToModel(r), 0)) for r in rows]
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection("\n".join(vals)), None)
        self._callbacks.printOutput("[+] Copied %d URLs" % len(vals))

    def _onCopyVal(self, e):
        rows = self._table.getSelectedRows()
        if not rows:
            return
        vals = [str(self._tableModel.getValueAt(self._table.convertRowIndexToModel(r), 2)) for r in rows]
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection("\n".join(vals)), None)
        self._callbacks.printOutput("[+] Copied %d values" % len(vals))

    def _onCopyRow(self, e):
        rows = self._table.getSelectedRows()
        if not rows:
            return
        lines = []
        for r in rows:
            mr = self._table.convertRowIndexToModel(r)
            row_data = [str(self._tableModel.getValueAt(mr, c)) for c in range(len(self._columns))]
            lines.append(" | ".join(row_data))
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection("\n".join(lines)), None)
        self._callbacks.printOutput("[+] Copied %d rows" % len(rows))

    def _onMarkFP(self, e):
        rows = self._table.getSelectedRows()
        if not rows:
            return
        model_rows = []
        for r in rows:
            model_rows.append(self._table.convertRowIndexToModel(r))
        model_rows.sort(reverse=True)
        for mr in model_rows:
            h = str(self._tableModel.getValueAt(mr, 6))
            self._false_positives.add(h)
            SwingUtilities.invokeLater(RowRemover(self._tableModel, mr))
        self._updateStats()
        self._callbacks.printOutput("[+] Marked %d findings as False Positive" % len(rows))

    def _onFilter(self, e):
        q = self._filterField.getText().strip()
        allowed_types = [t for t, cb in self._typeFilters.items() if cb.isSelected()]
        all_types = list(self._typeFilters.keys())

        if not q and len(allowed_types) == len(all_types):
            self._table.setRowSorter(None)
            return

        sorter = TableRowSorter(self._tableModel)
        filters = []

        if q:
            filters.append(RowFilter.regexFilter("(?i)" + q))

        if len(allowed_types) < len(all_types):
            type_pattern = "|".join(re.escape(t) for t in allowed_types)
            filters.append(RowFilter.regexFilter("(?i)^(" + type_pattern + ")$", 1))

        if len(filters) > 1:
            flist = ArrayList()
            for f in filters:
                flist.add(f)
            sorter.setRowFilter(RowFilter.andFilter(flist))
        elif filters:
            sorter.setRowFilter(filters[0])

        self._table.setRowSorter(sorter)

    def _onRowSelect(self):
        row = self._table.getSelectedRow()
        if row < 0:
            return
        try:
            mr = self._table.convertRowIndexToModel(row)
            url = str(self._tableModel.getValueAt(mr, 0))
            ftype = str(self._tableModel.getValueAt(mr, 1))
            val = str(self._tableModel.getValueAt(mr, 2))
            conf = str(self._tableModel.getValueAt(mr, 3))
            src = str(self._tableModel.getValueAt(mr, 4))
            ctx = str(self._tableModel.getValueAt(mr, 5))
            details = "URL: %s\nType: %s | Confidence: %s | Source: %s\nValue: %s\n\nContext:\n%s" % (url, ftype, conf, src, val, ctx)
            SwingUtilities.invokeLater(DetailUpdater(self._detailsArea, details))
        except:
            pass

    def _onExportCSV(self, e):
        self._exportFile("csv")

    def _onExportJSON(self, e):
        self._exportFile("json")

    def _exportFile(self, fmt):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._mainPanel) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getPath()
        rows = []
        for i in range(self._tableModel.getRowCount()):
            row_dict = {}
            for j in range(len(self._columns)):
                val = self._tableModel.getValueAt(i, j)
                row_dict[self._columns[j]] = str(val) if val is not None else ""
            rows.append(row_dict)

        try:
            with codecs.open(path, 'w', 'utf-8') as f:
                if fmt == "csv":
                    f.write(u",".join(self._columns) + u"\n")
                    for r in rows:
                        vals = [str(r.get(c, "")) for c in self._columns]
                        escaped = []
                        for v in vals:
                            if ',' in v or '"' in v or '\n' in v or '\r' in v:
                                v = '"%s"' % v.replace('"', '""')
                            escaped.append(v)
                        f.write(u",".join(escaped) + u"\n")
                else:
                    f.write(u"[\n")
                    for idx, r in enumerate(rows):
                        f.write(u"  {\n")
                        items = []
                        for k, v in r.items():
                            safe_v = str(v).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '')
                            items.append(u'    "%s": "%s"' % (k, safe_v))
                        f.write(u",\n".join(items))
                        f.write(u"\n  }")
                        if idx < len(rows) - 1:
                            f.write(u",")
                        f.write(u"\n")
                    f.write(u"]\n")
            self._callbacks.printOutput("[+] Exported %s to %s" % (fmt.upper(), path))
        except Exception as ex:
            self._callbacks.printOutput("[!] Export failed: " + str(ex))

    def _onClear(self, e):
        SwingUtilities.invokeLater(ClearTableRunner(self._tableModel))
        self._updateStats()

    def _onResetDedup(self, e):
        self._seen_hashes.clear()
        self._false_positives.clear()
        self._callbacks.printOutput("[+] Dedup and False Positive caches cleared. New findings will be collected.")
