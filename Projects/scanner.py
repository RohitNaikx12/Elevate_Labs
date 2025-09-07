#!/usr/bin/env python3
# scanner.py - CLI Web Vulnerability Scanner (educational)
import argparse, time, os
from collections import deque
from urllib.parse import urlsplit, urljoin, urlunsplit
import requests
from bs4 import BeautifulSoup

ALLOWLIST = {
    "localhost", "127.0.0.1", "::1",
    "testphp.vulnweb.com", "juice-shop.herokuapp.com",
    "demo.testfire.net", "zero.webappsecurity.com", "example.com"
}
USER_AGENT = "Educational-Scanner/1.0"
REQUEST_TIMEOUT = 6.0
CRAWL_DELAY = 0
MAX_PAGES_DEFAULT = 20
XSS_PAYLOAD = "<script>alert(1)</script>"
SQLI_PAYLOAD = "' OR '1'='1--"
SQL_ERRORS = ["you have an error in your sql syntax","warning: mysql","unclosed quotation mark","quoted string not properly terminated","pg_query","mysql_fetch","syntax error","ORA-01756","SQLSTATE"]

def assert_allowed(url):
    host = urlsplit(url).hostname or ""
    if host not in ALLOWLIST:
        raise ValueError(f"Host '{host}' is not in allowlist. Edit scanner.py to add permitted targets.")

def normalize_url(url):
    parts = list(urlsplit(url))
    if parts[2] == "": parts[2] = "/"
    return urlunsplit(parts)

def same_netloc(a,b):
    return urlsplit(a).netloc == urlsplit(b).netloc

def crawl(start_url, max_pages):
    assert_allowed(start_url)
    s = requests.Session(); s.headers["User-Agent"] = USER_AGENT
    seen=set(); q=deque([normalize_url(start_url)]); out=[]
    while q and len(out) < max_pages:
        url=q.popleft()
        if url in seen: continue
        seen.add(url)
        try:
            r = s.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            continue
        out.append((url, r))
        if "text/html" in (r.headers.get("Content-Type") or ""):
            soup = BeautifulSoup(r.text or "", "lxml")
            for a in soup.find_all("a", href=True):
                nxt = urljoin(r.url, a["href"])
                if same_netloc(nxt, start_url):
                    q.append(normalize_url(nxt))
        if CRAWL_DELAY: time.sleep(CRAWL_DELAY)
    return out

def passive_checks(pages):
    findings=[]
    for _u, resp in pages:
        url = resp.url
        h = resp.headers; scheme = urlsplit(url).scheme
        def header_present(name): return any(k.lower()==name.lower() for k in h.keys())
        if not header_present("Content-Security-Policy"):
            findings.append((url,"missing_csp","Medium","CSP header not set",""))
        if not header_present("X-Frame-Options"):
            findings.append((url,"missing_xfo","Medium","X-Frame-Options header not set",""))
        if not header_present("X-Content-Type-Options"):
            findings.append((url,"missing_xcto","Low","X-Content-Type-Options header not set",""))
        if not header_present("Referrer-Policy"):
            findings.append((url,"missing_refpol","Low","Referrer-Policy header not set",""))
        if not header_present("Permissions-Policy"):
            findings.append((url,"missing_perm_policy","Low","Permissions-Policy header not set",""))
        if scheme=="https" and not header_present("Strict-Transport-Security"):
            findings.append((url,"missing_hsts","Low","Strict-Transport-Security header not set",""))
        sc = h.get("Set-Cookie") or ""
        if sc and "httponly" not in sc.lower():
            findings.append((url,"cookie_no_httponly","Medium","Cookie missing HttpOnly flag",""))
        if scheme=="https" and sc and "secure" not in sc.lower():
            findings.append((url,"cookie_no_secure","Medium","Cookie missing Secure flag",""))
        # mixed content
        if scheme=="https" and "text/html" in (h.get("Content-Type") or ""):
            soup = BeautifulSoup(resp.text or "", "lxml")
            for tag, attr in [("img","src"),("script","src"),("link","href"),("iframe","src")]:
                for el in soup.find_all(tag):
                    val = (el.get(attr) or "").strip()
                    if val.startswith("http://"):
                        findings.append((url,"mixed_content","Medium","HTTPS page loads insecure resource", f"{tag}:{val}"))
                        break
        # CSRF heuristic: POST form without hidden token-like input
        if "text/html" in (h.get("Content-Type") or ""):
            soup = BeautifulSoup(resp.text or "", "lxml")
            for form in soup.find_all("form"):
                method = (form.get("method") or "get").lower()
                if method=="post":
                    tokens = form.find_all("input", {"type":"hidden"})
                    names = [t.get("name","").lower() for t in tokens]
                    if not any(any(k in (n or "") for k in ["csrf","xsrf","token","authenticity"]) for n in names):
                        findings.append((url,"csrf_token_missing","Medium","POST form without hidden CSRF-like token",""))
    return findings

def active_checks(pages):
    findings=[]
    s=requests.Session(); s.headers["User-Agent"]=USER_AGENT
    for _u, resp in pages:
        if "text/html" not in (resp.headers.get("Content-Type") or ""): continue
        page_url = resp.url
        soup = BeautifulSoup(resp.text or "", "lxml")
        forms = soup.find_all("form")
        for form in forms:
            method = (form.get("method") or "get").lower()
            action = form.get("action") or page_url
            target = urljoin(page_url, action)
            names = [inp.get("name") for inp in form.find_all(["input","textarea"]) if inp.get("name")]
            if not names: names=["q"]
            data = {n: XSS_PAYLOAD for n in names}
            try:
                r = s.post(target, data=data, timeout=REQUEST_TIMEOUT) if method=="post" else s.get(target, params=data, timeout=REQUEST_TIMEOUT)
                if XSS_PAYLOAD in (r.text or ""):
                    findings.append((r.url,"xss_reflection","High","Reflected XSS indicator",XSS_PAYLOAD))
            except requests.RequestException:
                pass
            # SQLi test
            inj = {n: SQLI_PAYLOAD for n in names}
            try:
                r2 = s.post(target, data=inj, timeout=REQUEST_TIMEOUT) if method=="post" else s.get(target, params=inj, timeout=REQUEST_TIMEOUT)
                lt = (r2.text or "").lower()
                if any(err in lt for err in SQL_ERRORS):
                    findings.append((r2.url,"sqli_error","High","SQL error message detected after input","sql-error-signature"))
            except requests.RequestException:
                pass
    return findings

def save_reports(scan_name, findings):
    os.makedirs("reports", exist_ok=True)
    md = ["# Scan Report - " + scan_name, ""]
    for (url, cid, sev, msg, evidence) in findings:
        md.append(f"## {sev} - {msg}")
        md.append(f"- Check ID: {cid}")
        md.append(f"- URL: {url}")
        if evidence: md.append(f"- Evidence: `{evidence}`")
        md.append("")
    out_md = os.path.join("reports", f"{scan_name}.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    # also write simple html
    out_html = os.path.join("reports", f"{scan_name}.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write("<html><body>\n")
        for line in md:
            f.write(f"<p>{line}</p>\n")
        f.write("</body></html>\n")
    print(f"Saved reports: {out_md}, {out_html}")

def main():
    p = argparse.ArgumentParser(description="Educational scanner CLI")
    p.add_argument("--url", required=True)
    p.add_argument("--max-pages", type=int, default=MAX_PAGES_DEFAULT)
    p.add_argument("--active", type=int, default=0, help="1 to enable active lab tests")
    args = p.parse_args()
    try:
        pages = crawl(args.url, args.max_pages)
    except ValueError as e:
        print("[ERROR]", e); return
    passive = passive_checks(pages)
    findings = list(passive)
    if args.active:
        findings += active_checks(pages)
    scan_name = "scan_" + time.strftime("%Y%m%d_%H%M%S")
    save_reports(scan_name, findings)
    if not findings:
        print("No findings.")
    else:
        for (url, cid, sev, msg, evidence) in findings:
            print(f"- [{sev}] {cid} @ {url} - {msg}")
            if evidence: print("   evidence:", evidence)

if __name__ == '__main__':
    main()
