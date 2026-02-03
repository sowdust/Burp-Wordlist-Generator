'''
A Burp extension to extract various data from the sitemap.
This data can later be used in personalized wordlists.

Path extraction:
- Only from responses with HTTP 200
- Discards paths with unique segments
- Keeps generalized paths only
(Jython-compatible)
'''

import threading
import os
import sys
import re
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

class BurpExtender(IBurpExtender, IContextMenuFactory):

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
        # Must have a response
        if rr.getResponse() is None:
            return

        responseInfo = self._helpers.analyzeResponse(rr.getResponse())
        status = responseInfo.getStatusCode()

        # Only HTTP 200
        if status != 200:
            return

        requestInfo = self._helpers.analyzeRequest(rr)
        url_obj = requestInfo.getUrl()

        if not self._callbacks.isInScope(url_obj):
            return

        url = self._to_str(url_obj.toString())

        self._extract_path(url)
        self._extract_subdomain(url)

        for param in requestInfo.getParameters():
            self._extract_param(param)

    # -------------------------
    # Path Extraction (Strict)
    # -------------------------

    def _normalize_path(self, path):
        if not path:
            return "/"
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        return path

    def _is_unique_segment(self, segment):
        return (
            NUM_RE.match(segment) or
            UUID_RE.match(segment)
        )

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
            # If unique segment found, store ONLY generalized path and stop
            if self._is_unique_segment(part):
                generalized = [
                    self._generalize_segment(p)
                    for p in current + [part]
                ]
                self.wordlists.paths.add("/" + "/".join(generalized))
                return

            # Safe, non-unique segment
            current.append(part)
            self.wordlists.paths.add("/" + "/".join(current))


    # -------------------------
    # Other Extractors
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
