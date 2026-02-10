# -*- coding: utf-8 -*-

'''
Wordlist Generator – Stable Jython Burp Extension

Features:
- UI tab with extraction options
- Max path depth (0 = unlimited)
- Filenames extracted separately (segments with extensions)
- Filenames excluded from paths
- Append-only output
- Buttons: entire sitemap / in-scope only
- Context menu obeys UI settings
'''

import os
import sys
import re
import threading
from urlparse import urlparse

from burp import IBurpExtender, ITab, IContextMenuFactory
from burp.IContextMenuInvocation import CONTEXT_TARGET_SITE_MAP_TREE
from burp.IParameter import PARAM_URL, PARAM_BODY, PARAM_JSON, PARAM_XML

from java.util import ArrayList
from javax.swing import (
    JPanel, JCheckBox, JButton, JTextField, JLabel,
    JFileChooser, BoxLayout, JMenuItem, JSpinner, SpinnerNumberModel
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
EXT_RE = re.compile(r'.+\.[A-Za-z0-9]{1,10}$')


# =========================
# Data container
# =========================

class Wordlists(object):
    def __init__(self):
        self.paths = set()
        self.filenames = set()
        self.param_keys = set()
        self.param_values = set()
        self.param_queries = set()
        self.subdomains = set()

    def clear(self):
        self.paths.clear()
        self.filenames.clear()
        self.param_keys.clear()
        self.param_values.clear()
        self.param_queries.clear()
        self.subdomains.clear()


# =========================
# Burp Extension
# =========================

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    # -------------------------
    # Registration
    # -------------------------

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        callbacks.setExtensionName("Wordlist Generator")
        callbacks.registerContextMenuFactory(self)

        self.wordlists = Wordlists()

        # Defaults
        self.wordlistDir = self._init_output_dir()
        self.opt_paths = True
        self.opt_filenames = True
        self.opt_keys = True
        self.opt_values = True
        self.opt_queries = True
        self.opt_subdomains = True
        self.max_path_depth = 0  # 0 = unlimited

        self._build_ui()
        callbacks.addSuiteTab(self)

        print("[+] Wordlist Generator loaded")

    # -------------------------
    # ITab
    # -------------------------

    def getTabCaption(self):
        return "Wordlist Generator"

    def getUiComponent(self):
        return self.mainPanel

    # -------------------------
    # UI
    # -------------------------

    def _build_ui(self):
        self.mainPanel = JPanel(BorderLayout())

        options = JPanel()
        options.setLayout(BoxLayout(options, BoxLayout.Y_AXIS))

        self.chk_paths = JCheckBox("Extract paths", True)
        self.chk_filenames = JCheckBox("Extract filenames", True)
        self.chk_keys = JCheckBox("Extract parameter keys", True)
        self.chk_values = JCheckBox("Extract parameter values", True)
        self.chk_queries = JCheckBox("Extract parameter queries", True)
        self.chk_subdomains = JCheckBox("Extract subdomains", True)

        options.add(self.chk_paths)
        options.add(self.chk_filenames)
        options.add(self.chk_keys)
        options.add(self.chk_values)
        options.add(self.chk_queries)
        options.add(self.chk_subdomains)

        depthPanel = JPanel()
        depthPanel.add(JLabel("Max path depth (0 = unlimited): "))
        self.spinner_depth = JSpinner(SpinnerNumberModel(0, 0, 20, 1))
        depthPanel.add(self.spinner_depth)
        options.add(depthPanel)

        outputPanel = JPanel()
        outputPanel.add(JLabel("Output directory:"))
        self.txt_output = JTextField(self.wordlistDir, 20)
        outputPanel.add(self.txt_output)
        outputPanel.add(JButton("Browse", actionPerformed=self._browse))

        buttons = JPanel()
        buttons.add(JButton("Extract entire sitemap", actionPerformed=self._extract_all))
        buttons.add(JButton("Extract in-scope only", actionPerformed=self._extract_scope))

        self.mainPanel.add(options, BorderLayout.NORTH)
        self.mainPanel.add(outputPanel, BorderLayout.CENTER)
        self.mainPanel.add(buttons, BorderLayout.SOUTH)

    def _browse(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        if chooser.showOpenDialog(self.mainPanel) == JFileChooser.APPROVE_OPTION:
            self.txt_output.setText(chooser.getSelectedFile().getAbsolutePath())

    # -------------------------
    # Context menu
    # -------------------------

    def createMenuItems(self, invocation):
        if invocation.getInvocationContext() != CONTEXT_TARGET_SITE_MAP_TREE:
            return None

        menu = ArrayList()

        menu.add(JMenuItem(
            "Generate wordlist (selection)",
            actionPerformed=lambda e: self._run(invocation.getSelectedMessages())
        ))

        menu.add(JMenuItem(
            "Generate wordlist (entire sitemap)",
            actionPerformed=lambda e: self._run(self._callbacks.getSiteMap(None))
        ))

        return menu

    # -------------------------
    # Execution
    # -------------------------

    def _apply_settings(self):
        self.wordlistDir = self.txt_output.getText()
        self.opt_paths = self.chk_paths.isSelected()
        self.opt_filenames = self.chk_filenames.isSelected()
        self.opt_keys = self.chk_keys.isSelected()
        self.opt_values = self.chk_values.isSelected()
        self.opt_queries = self.chk_queries.isSelected()
        self.opt_subdomains = self.chk_subdomains.isSelected()
        self.max_path_depth = int(self.spinner_depth.getValue())

    def _extract_all(self, event):
        print("extract all")
        self._run(self._callbacks.getSiteMap(None))

    def _is_rr_in_scope(self, rr):
        try:
            req = rr.getRequest()
            if req is None:
                return False

            req_info = self._helpers.analyzeRequest(req)
            url = req_info.getUrl()

            return self._callbacks.isInScope(url)

        except:
            return False


    def _extract_scope(self, event):
        print("extract in scope")

        sitemap = self._callbacks.getSiteMap(None)
        scoped = [
            rr for rr in sitemap
            if rr.getRequest() and
            self._callbacks.isInScope(
                self._helpers.analyzeRequest(rr).getUrl()
            )
        ]

        print(len(scoped))
        self._run(scoped)

    def _run(self, items):
        self._apply_settings()
        t = threading.Thread(target=self.generate, args=(items,))
        t.daemon = True
        t.start()

    # -------------------------
    # Core logic
    # -------------------------

    def generate(self, items):
        self.wordlists.clear()
        print("[*] Processing %d items" % len(items))

        for rr in items:
            try:
                self._process(rr)
            except Exception as e:
                sys.stderr.write("Error: %s\n" % e)

        self._store_all()
        print("[+] Done")

    def _process(self, rr):
        if rr.getResponse() is None:
            return

        if self._helpers.analyzeResponse(rr.getResponse()).getStatusCode() != 200:
            return

        req = self._helpers.analyzeRequest(rr)
        url = req.getUrl().toString()

        if self.opt_paths or self.opt_filenames:
            self._extract_path(url)

        if self.opt_subdomains:
            self._extract_subdomain(url)

        for p in req.getParameters():
            self._extract_param(p)

    # -------------------------
    # Path / filename logic
    # -------------------------

    def _extract_path(self, url):
        parts = [p for p in urlparse(url).path.split("/") if p]
        current = []

        for part in parts:

            if self.max_path_depth > 0 and len(current) >= self.max_path_depth:
                return

            if EXT_RE.match(part):
                if self.opt_filenames:
                    self.wordlists.filenames.add(part)
                return

            if NUM_RE.match(part) or UUID_RE.match(part):
                if self.opt_paths:
                    self.wordlists.paths.add("/" + "/".join(current + ["{id}"]))
                return

            current.append(part)
            if self.opt_paths:
                self.wordlists.paths.add("/" + "/".join(current))

    # -------------------------
    # Other extractors
    # -------------------------

    def _extract_subdomain(self, url):
        host = urlparse(url).netloc
        parts = host.split(".")
        if len(parts) > 2:
            self.wordlists.subdomains.add(".".join(parts[:-2]))

    def _extract_param(self, param):
        if int(param.getType()) not in (PARAM_URL, PARAM_BODY, PARAM_JSON, PARAM_XML):
            return

        key = self._helpers.bytesToString(param.getName())
        val = self._helpers.bytesToString(param.getValue())

        if self.opt_keys:
            self.wordlists.param_keys.add(key)
        if self.opt_values:
            self.wordlists.param_values.add(val)
        if self.opt_queries:
            self.wordlists.param_queries.add("%s=%s" % (key, val))

    # -------------------------
    # Storage (append-only)
    # -------------------------

    def _store_all(self):
        if not os.path.exists(self.wordlistDir):
            os.makedirs(self.wordlistDir)

        if self.opt_paths:
            self._store("paths.txt", self.wordlists.paths)
        if self.opt_filenames:
            self._store("filenames.txt", self.wordlists.filenames)
        if self.opt_keys:
            self._store("keys.txt", self.wordlists.param_keys)
        if self.opt_values:
            self._store("values.txt", self.wordlists.param_values)
        if self.opt_queries:
            self._store("queries.txt", self.wordlists.param_queries)
        if self.opt_subdomains:
            self._store("subdomains.txt", self.wordlists.subdomains)

    def _store(self, name, items):
        path = os.path.join(self.wordlistDir, name)
        with open(path, "a") as f:
            for i in sorted(items):
                f.write(i + "\n")

    # -------------------------
    # Utilities
    # -------------------------

    def _init_output_dir(self):
        base = os.getcwd()
        path = os.path.join(base, "wordlists")
        if not os.path.exists(path):
            os.makedirs(path)
        return path
