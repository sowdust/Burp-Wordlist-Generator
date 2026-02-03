'''
A Burp extension to extract various data from the sitemap.
This data can later be used in personalized wordlists.

Refactored version (Jython-compatible).
'''

import threading
import os
import sys
from urlparse import urlparse

from burp import IBurpExtender, IContextMenuFactory
from burp.IParameter import (
    PARAM_URL, PARAM_BODY, PARAM_JSON, PARAM_XML
)
from burp.IContextMenuInvocation import CONTEXT_TARGET_SITE_MAP_TREE

from java.util import ArrayList
from javax.swing import JMenuItem
from java.awt import Frame


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

class BurpExtender(IBurpExtender, IContextMenuFactory):

    # -------------------------
    # Initialization
    # -------------------------

    def registerExtenderCallbacks(self, callbacks):
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Wordlist Generator")
        callbacks.registerContextMenuFactory(self)

        self.wordlists = Wordlists()
        self.wordlistDir = self._init_output_dir()

        print("Wordlist Generator initialized")
        print("Writing to: %s" % self.wordlistDir)

    def _init_output_dir(self):
        base = os.path.abspath(os.getcwd())
        path = os.path.join(base, "wordlists", self.getProjectTitle())
        if not os.path.exists(path):
            os.makedirs(path)
        return path

    # -------------------------
    # Context Menu
    # -------------------------

    def createMenuItems(self, invocation):
        if invocation.getInvocationContext() != CONTEXT_TARGET_SITE_MAP_TREE:
            return None

        menu = ArrayList()

        full = JMenuItem(
            "Generate wordlist from entire sitemap",
            actionPerformed=self._menu_full
        )
        menu.add(full)

        selection = invocation.getSelectedMessages()
        if selection:
            self._selection = selection
            selected = JMenuItem(
                "Generate wordlist from selection",
                actionPerformed=self._menu_selection
            )
            menu.add(selected)

        return menu

    def _menu_full(self, event):
        sitemap = self._callbacks.getSiteMap(None)
        self._run_async(self.generate, sitemap)

    def _menu_selection(self, event):
        self._run_async(self.generate, self._selection)

    def _run_async(self, target, *args):
        t = threading.Thread(target=target, args=args)
        t.daemon = True
        t.start()

    # -------------------------
    # Core Logic
    # -------------------------

    def generate(self, requestResponses):
        self.wordlists.clear()

        total = len(requestResponses)
        count = 0

        print("Generating wordlists (%d items)" % total)

        for rr in requestResponses:
            count += 1
            try:
                self._process_request(rr, count, total)
            except Exception as e:
                sys.stderr.write(
                    "Error processing request (%d/%d): %s\n"
                    % (count, total, str(e))
                )

        self._store_all()
        print("Done!")

    def _process_request(self, requestResponse, count, total):
        requestInfo = self._helpers.analyzeRequest(requestResponse)
        url_obj = requestInfo.getUrl()

        if not self._callbacks.isInScope(url_obj):
            print("[%d/%d] %s (out of scope)" % (count, total, url_obj))
            return

        url = self._to_str(url_obj.toString())
        method = self._to_str(requestInfo.getMethod())

        print("[%d/%d] %s %s" % (count, total, method, url))

        self._extract_path(url)
        self._extract_subdomain(url)

        for param in requestInfo.getParameters():
            self._extract_param(param)

    # -------------------------
    # Extractors
    # -------------------------

    def _extract_path(self, url):
        parsed = urlparse(url)
        self.wordlists.paths.add(parsed.path)

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

        self.wordlists.param_keys.add(key)
        self.wordlists.param_values.add(value)
        self.wordlists.param_queries.add("%s=%s" % (key, value))

    # -------------------------
    # Storage
    # -------------------------

    def _store_all(self):
        self._store("paths.txt", self.wordlists.paths)
        self._store("keys.txt", self.wordlists.param_keys)
        self._store("values.txt", self.wordlists.param_values)
        self._store("queries.txt", self.wordlists.param_queries)
        self._store("subdomains.txt", self.wordlists.subdomains)

    def _store(self, filename, items):
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

    def getProjectTitle(self):
        for frame in Frame.getFrames():
            if frame.isVisible() and frame.getTitle().startswith("Burp Suite"):
                return frame.getTitle().split("-", 1)[1].strip()
        return "default"
