"""Public-release checks: example config, installer profile selection, and a tree sweep.

Owner-specific terms come from the environment so this file does not contain them.
"""
import os, re, subprocess, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


# Distinctive names and addresses that must not appear in a public tree. Keep your own
# list out of the repository: set OC_RELEASE_DENYLIST to comma-separated terms before running.
NEEDLES = [t.strip() for t in os.environ.get("OC_RELEASE_DENYLIST", "").split(",") if t.strip()]
# Short tokens matched on word boundaries (OC_RELEASE_DENY_WORDS, comma-separated).
WORDS = [t.strip() for t in os.environ.get("OC_RELEASE_DENY_WORDS", "").split(",") if t.strip()]

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".pytest_cache"}


def tree_files():
    for path in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def allowed_ip(ip):
    """Loopback, link-local, private, and documentation ranges, plus synthetic test clients."""
    if ip in {"0.0.0.0", "1.1.1.1", "1.2.3.4", "5.6.7.8", "9.9.9.9"}:
        return True
    a, b, c, _d = (int(x) for x in ip.split("."))
    if a == 127 or (a == 169 and b == 254):
        return True
    if a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return True
    if (a, b, c) in {(203, 0, 113), (198, 51, 100), (192, 0, 2)}:  # RFC 5737
        return True
    return False


def parse_env(text):
    out = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        key, value = s.split("=", 1)
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


class ExampleEnv(unittest.TestCase):
    def test_placeholders_and_empty_allowlists(self):
        vals = parse_env((ROOT / ".env.example").read_text())
        self.assertEqual(vals["OC_ROOT"], "/srv/opencloud")
        self.assertEqual(vals["OC_CONSOLE_HOST"], "console.example.com")
        self.assertEqual(vals["OC_APPS_DOMAIN"], "apps.example.com")
        self.assertEqual(vals["OC_S3_HOST"], "s3.apps.example.com")
        self.assertEqual(vals["OC_ACME_EMAIL"], "admin@example.com")
        self.assertEqual(vals["OC_TLS"], "acme")
        self.assertEqual(vals["OC_EDGE_MODE"], "internal")
        self.assertEqual(vals["OC_GENERIC_GATEWAY"], "0")
        self.assertEqual(vals["OC_TRUSTED_PROXY_HOSTS"], "oc-edge")
        self.assertEqual(vals["OC_PUBLIC_IP"], "")
        for key in ("OC_LOCAL_SOURCES", "OC_ALLOWED_EXTERNAL_NETWORKS", "OC_ALLOWED_DATA_ROOTS",
                    "OC_ALLOWED_SECRET_PATHS", "OC_LLM_PROVIDER_KEY", "OC_SMTP_PASSWORD",
                    "OC_LLM_UPSTREAM_URL", "OC_PROXY_NETWORK"):
            self.assertEqual(vals[key], "", key)

    def test_builtin_fallbacks_are_generic(self):
        agent = (ROOT / "agent" / "agent.py").read_text()
        console = (ROOT / "console" / "console.py").read_text()
        self.assertIn('os.environ.get("OC_ROOT", "/srv/opencloud")', agent)
        self.assertIn('os.environ.get("OC_APPS_DOMAIN", "localhost")', agent)
        self.assertIn('os.environ.get("OC_CONSOLE_HOST", "console.localhost")', agent)
        self.assertIn("app_runtime", console)
        self.assertNotIn("postgresql://app:", console)


class AllowlistFromEnv(unittest.TestCase):
    def test_secret_paths_come_only_from_the_environment(self):
        import sys
        sys.path.insert(0, str(ROOT / "agent"))
        import agent
        key = "OC_ALLOWED_SECRET_PATHS"
        old = os.environ.get(key)
        try:
            os.environ[key] = ""
            self.assertEqual(agent.allow(key), [])
            os.environ[key] = "/tmp/oc-a /tmp/oc-b"
            self.assertEqual([str(p) for p in agent.allow(key)], ["/tmp/oc-a", "/tmp/oc-b"])
            os.environ[key] = "relative ../etc"
            self.assertEqual(agent.allow(key), [])
        finally:
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


class ComposeProfiles(unittest.TestCase):
    def profiles(self, mode, gateway, builder="0"):
        script = f"""
set -eu
OC_EDGE_MODE={mode}
OC_GENERIC_GATEWAY={gateway}
OC_BUILDER={builder}
OC_OBSERVE=0
OC_ROOT=/tmp/oc-release-missing
. ./compose-env.sh
printf '%s\\n' "$COMPOSE_FILE"
printf '%s\\n' "$COMPOSE_PROFILES"
"""
        got = subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(got.returncode, 0, got.stderr)
        lines = got.stdout.splitlines()
        self.assertEqual(len(lines), 2, got.stdout)
        return lines[0], lines[1]

    def test_internal_edge_and_optional_gateway(self):
        files, profiles = self.profiles("internal", "0")
        self.assertEqual(files, "compose.yaml")
        self.assertEqual(profiles, "edge,build")
        files, profiles = self.profiles("internal", "1")
        self.assertEqual(profiles, "edge,build,gateway")

    def test_external_edge_starts_builder_only_when_asked(self):
        files, profiles = self.profiles("external", "0", "0")
        self.assertEqual(files, "compose.yaml:compose.external.yaml")
        self.assertEqual(profiles, "")
        _files, profiles = self.profiles("external", "0", "1")
        self.assertEqual(profiles, "build")
        _files, profiles = self.profiles("external", "1", "0")
        self.assertEqual(profiles, "gateway")

    def test_shell_scripts_parse(self):
        for name in ("install.sh", "opencloud", "compose-env.sh", "tests/e2e.sh", "tests/e2e-external.sh"):
            got = subprocess.run(["bash", "-n", name], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(got.returncode, 0, f"{name}: {got.stderr}")


class TreeSweep(unittest.TestCase):
    def test_no_owner_terms_emails_or_unexpected_ips(self):
        words = [re.compile(r"\b" + re.escape(w) + r"\b", re.I) for w in WORDS]
        bad = []
        for path in tree_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            folded = text.casefold()
            rel = str(path.relative_to(ROOT))
            for needle in NEEDLES:
                if needle.casefold() in folded:
                    bad.append(f"{rel}: {needle}")
            for word in words:
                if word.search(text):
                    bad.append(f"{rel}: word {word.pattern}")
            for match in EMAIL.finditer(text):
                domain = match.group(1).casefold()
                if domain != "example.com" and not domain.endswith(".example.com"):
                    bad.append(f"{rel}: email {match.group(0)}")
            for ip in IPV4.findall(text):
                if not allowed_ip(ip):
                    bad.append(f"{rel}: ip {ip}")
        self.assertEqual(bad, [])

    def test_license_and_guides_exist(self):
        for name in ("LICENSE", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "README.md", ".env.example", ".gitignore"):
            self.assertTrue((ROOT / name).is_file(), name)
        for name in ("INSTALL.md", "LOGIN.md", "DNS.md", "DEPLOY.md", "APP-GUIDE.md", "DATABASES.md",
                     "STORAGE.md", "OPEN-BEDROCK.md", "OPEN-ELB.md", "RESTORE.md", "SECURITY.md",
                     "TROUBLESHOOTING.md", "UPGRADING.md", "ARCHITECTURE.md"):
            self.assertTrue((ROOT / "docs" / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
