'''
A Burp extension to extract various data from the sitemap.
This data can later be used in personalized wordlists.

Features:
- UI tab with extraction options
- Select output directory
- Extract from full sitemap or in-scope only
(Jython-compatible)
'''

import threading
import os
import sys
import re
from urlparse import urlparse

from burp import IBurpExtender, ITab
from burp.IParameter import (
    PARAM_URL, PARAM_BODY, PARAM_JSON, PARAM_XML
)

from java.util import ArrayList
from javax.swing import (
    JPanel, JCheckBox, JButton, JTextField, JLabel,
    JFileChooser, BoxLayout
)
from java.awt import BorderLayout, Frame


# =========================
# Regexes
# =========================

NUM_RE = re.compile(r'^\d+$')
UUID_RE = re.compile(
    r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',
    re.I
)


# =========================
# Helper Classes
# =========================

class Wordlists(object):
    def __init__(self):
        self.paths = set()
        self.param_keys = set()
        self.param_values = set()
        self.param_queries = set()
        self.subdomains = set()

    def clear(self):
        self.paths.clear()
        self.param_keys.clear()
        self.param_values.clear()
        self.param_queries.clear()
        self.subdomains.clear()


# =========================
# Burp Extension
# =========================

class BurpExtender(IBurpExtender, ITab):

    # -------------------------
    # Burp registration
    # -------------------------

    def registerExtenderCallbacks(self, callbacks):
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Wordlist Generator")

        self.wordlists = Wordlists()
        self.wordlistDir = self._init_output_dir()

        # Default options
        self.opt_paths = True
        self.opt_keys = True
        self.opt_values = True
        self.opt_queries = True
        self.opt_subdomains = True

        self._build_ui()
        callbacks.addSuiteTab(self)

        print("Wordlist Generator initialized")

    # -------------------------
    # ITab implementation
    # -------------------------

    def getTabCaption(self):
        return "Wordlist Generator"

    def getUiComponent(self):
        return self._mainPanel

    # -------------------------
    # UI
    # -------------------------

    def _build_ui(self):
        self._mainPanel = JPanel(BorderLayout())

        # === Options panel ===
        optionsPanel = JPanel()
        optionsPanel.setLayout(BoxLayout(optionsPanel, BoxLayout.Y_AXIS))

        optionsPanel.add(JLabel("Extraction options"))

        self.chk_paths = JCheckBox("Extract paths", True)
        self.chk_keys = JCheckBox("Extract parameter keys", True)
        self.chk_values = JCheckBox("Extract parameter values", True)
        self.chk_queries = JCheckBox("Extract parameter queries", True)
        self.chk_subdomains = JCheckBox("Extract subdomains", True)

        optionsPanel.add(self.chk_paths)
        optionsPanel.add(self.chk_keys)
        optionsPanel.add(self.chk_values)
        optionsPanel.add(self.chk_queries)
        optionsPanel.add(self.chk_subdomains)

        # === Output directory panel ===
        outputPanel = JPanel()
        outputPanel.setLayout(BoxLayout(outputPanel, BoxLayout.X_AXIS))

        self.txt_output = JTextField(self.wordlistDir, 30)
        browseBtn = JButton("Browse", actionPerformed=self._browse_dir)

        outputPanel.add(JLabel("Output directory: "))
        outputPanel.add(self.txt_output)
        outputPanel.add(browseBtn)

        # === Buttons panel ===
        buttonsPanel = JPanel()

        allBtn = JButton(
            "Extract from entire sitemap",
            actionPerformed=self._extract_all
        )
        scopeBtn = JButton(
            "Extract from in-scope only",
            actionPerformed=self._extract_scope
        )

        buttonsPanel.add(allBtn)
        buttonsPanel.add(scopeBtn)

        # === Assemble ===
        self._mainPanel.add(optionsPanel, BorderLayout.NORTH)
        self._mainPanel.add(outputPanel, BorderLayout.CENTER)
        self._mainPanel.add(buttonsPanel, BorderLayout.SOUTH)

    def _browse_dir(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

        if chooser.showOpenDialog(self._mainPanel) == JFileChooser.APPROVE_OPTION:
            self.txt_output.setText(
                chooser.getSelectedFile().getAbsolutePath()
            )

    # -------------------------
    # Button handlers
    # -------------------------

    def _extract_all(self, event):
        self._apply_ui_settings()
        sitemap = self._callbacks.getSiteMap(None)
        self._run_async(self.generate, sitemap)

    def _extract_scope(self, event):
        self._apply_ui_settings()
        sitemap = self._callbacks.getSiteMap(None)

        scoped = []
        for rr in sitemap:
            try:
                reqInfo = self._helpers.analyzeRequest(rr)
                if self._callbacks.isInScope(reqInfo.getUrl()):
                    scoped.append(rr)
            except:
                pass

        self._run_async(self.generate, scoped)

    def _apply_ui_settings(self):
        self.wordlistDir = self.txt_output.getText()

        self.opt_paths = self.chk_paths.isSelected()
        self.opt_keys = self.chk_keys.isSelected()
        self.opt_values = self.chk_values.isSelected()
        self.opt_queries = self.chk_queries.isSelected()
        self.opt_subdomains = self.chk_subdomains.isSelected()

    # -------------------------
    # Async helper
    # -------------------------

    def _run_async(self, target, *args):
        t = threading.Thread(target=target, args=args)
        t.daemon = True
        t.start()

    # -------------------------
    # Core logic
    # -------------------------

    def generate(self, requestResponses):
        self.wordlists.clear()
        total = len(requestResponses)

        print("Generating wordlists (%d items)" % total)

        for idx, rr in enumerate(requestResponses, 1):
            try:
                self._process_request(rr)
            except Exception as e:
                sys.stderr.write(
                    "Error (%d/%d): %s\n" % (idx, total, str(e))
                )

        self._store_all()
        print("Done")

    def _process_request(self, rr):
        if rr.getResponse() is None:
            return

        responseInfo = self._helpers.analyzeResponse(rr.getResponse())
        if responseInfo.getStatusCode() != 200:
            return

        requestInfo = self._helpers.analyzeRequest(rr)
        url_obj = requestInfo.getUrl()

        if not self._callbacks.isInScope(url_obj):
            return

        url = self._to_str(url_obj.toString())

        if self.opt_paths:
            self._extract_path(url)
        if self.opt_subdomains:
            self._extract_subdomain(url)

        for param in requestInfo.getParameters():
            self._extract_param(param)

    # -------------------------
    # Path extraction
    # -------------------------

    def _normalize_path(self, path):
        if not path:
            return "/"
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        return path

    def _is_unique_segment(self, segment):
        return NUM_RE.match(segment) or UUID_RE.match(segment)

    def _generalize_segment(self, segment):
        if NUM_RE.match(segment):
            return "{id}"
        if UUID_RE.match(segment):
            return "{uuid}"
        return segment

    def _extract_path(self, url):
        parsed = urlparse(url)
        path = self._normalize_path(parsed.path)

        parts = [p for p in path.split("/") if p]
        current = []

        for part in parts:
            if self._is_unique_segment(part):
                generalized = [
                    self._generalize_segment(p)
                    for p in current + [part]
                ]
                self.wordlists.paths.add("/" + "/".join(generalized))
                return

            current.append(part)
            self.wordlists.paths.add("/" + "/".join(current))

    # -------------------------
    # Other extractors
    # -------------------------

    def _extract_subdomain(self, url):
        parsed = urlparse(url)
        host = parsed.netloc

        if not host:
            return

        parts = host.split(".")
        if len(parts) > 2:
            self.wordlists.subdomains.add(".".join(parts[:-2]))

    def _extract_param(self, param):
        if int(param.getType()) not in (
            PARAM_URL, PARAM_BODY, PARAM_JSON, PARAM_XML
        ):
            return

        key = self._to_str(
            self._helpers.bytesToString(param.getName())
        )
        value = self._to_str(
            self._helpers.bytesToString(param.getValue())
        )

        if self.opt_keys:
            self.wordlists.param_keys.add(key)
        if self.opt_values:
            self.wordlists.param_values.add(value)
        if self.opt_queries:
            self.wordlists.param_queries.add("%s=%s" % (key, value))

    # -------------------------
    # Storage
    # -------------------------

    def _store_all(self):
        if self.opt_paths:
            self._store("paths.txt", self.wordlists.paths)
        if self.opt_keys:
            self._store("keys.txt", self.wordlists.param_keys)
        if self.opt_values:
            self._store("values.txt", self.wordlists.param_values)
        if self.opt_queries:
            self._store("queries.txt", self.wordlists.param_queries)
        if self.opt_subdomains:
            self._store("subdomains.txt", self.wordlists.subdomains)

    def _store(self, filename, items):
        if not items:
            return

        if not os.path.exists(self.wordlistDir):
            os.makedirs(self.wordlistDir)

        path = os.path.join(self.wordlistDir, filename)
        with open(path, "w") as f:
            for item in sorted(items):
                f.write(item + "\n")

    # -------------------------
    # Utilities
    # -------------------------

    def _to_str(self, value):
        if value is None:
            return ""
        if isinstance(value, unicode):
            return value
        try:
            return value.decode("utf-8")
        except:
            return str(value)

    def _init_output_dir(self):
        base = os.path.abspath(os.getcwd())
        path = os.path.join(base, "wordlists", self.getProjectTitle())
        if not os.path.exists(path):
            os.makedirs(path)
        return path

    def getProjectTitle(self):
        for frame in Frame.getFrames():
            if frame.isVisible() and frame.getTitle().startswith("Burp Suite"):
                return frame.getTitle().split("-", 1)[1].strip()
        return "default"
