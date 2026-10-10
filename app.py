from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urlparse
from datetime import datetime
import re, io, csv, socket, ssl, urllib.request, urllib.error

app = Flask(__name__)

def normalize_url(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("Enter a website URL.")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    # Only public hostnames/IPs are accepted by the demo checker.
    host = parsed.hostname.lower()
    if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Local/private targets are not supported by this public demo checker.")
    try:
        ip = socket.gethostbyname(host)
        if ip.startswith(("127.", "10.", "192.168.", "169.254.")) or (
            ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31
        ) or ip == "0.0.0.0":
            raise ValueError("Private/local network targets are not supported.")
    except socket.gaierror:
        raise ValueError("Could not resolve that hostname. Check the URL.")
    return value, parsed

def check_website(url):
    normalized, parsed = normalize_url(url)
    result = {
        "url": normalized,
        "host": parsed.hostname,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "checks": [],
        "score": 0,
        "summary": ""
    }
    score = 0
    # Perform one basic HTTP(S) request only; this is not a penetration test.
    req = urllib.request.Request(normalized, headers={"User-Agent": "HackGuardAI-Security-Checklist/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            status = response.status
            headers = {k.lower(): v for k, v in response.headers.items()}
            final_url = response.geturl()
        result["http_status"] = status
        result["final_url"] = final_url
        result["checks"].append({
            "name": "Website reachable",
            "status": "pass" if 200 <= status < 400 else "warn",
            "detail": f"Received HTTP status {status}."
        })
        if 200 <= status < 400: score += 20
        for header, title, detail in [
            ("strict-transport-security", "HTTP Strict Transport Security (HSTS)", "Helps browsers enforce HTTPS."),
            ("content-security-policy", "Content Security Policy (CSP)", "Can reduce some script-injection risks."),
            ("x-content-type-options", "X-Content-Type-Options", "Helps prevent MIME-type sniffing."),
            ("x-frame-options", "X-Frame-Options", "Can help reduce clickjacking risk.")
        ]:
            present = header in headers
            result["checks"].append({
                "name": title,
                "status": "pass" if present else "warn",
                "detail": ("Header detected." if present else "Header not detected in this response. Review whether it should be configured.")
            })
            if present: score += 20
        is_https = urlparse(final_url).scheme.lower() == "https"
        result["checks"].append({
            "name": "HTTPS",
            "status": "pass" if is_https else "fail",
            "detail": "Final page uses HTTPS." if is_https else "Final page is not using HTTPS."
        })
        if is_https: score += 20
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        result["checks"].append({
            "name": "Website reachable",
            "status": "fail",
            "detail": f"Could not fetch the page: {str(reason)[:180]}"
        })
        result["http_status"] = None
        result["final_url"] = normalized
        result["checks"].append({
            "name": "HTTP security headers",
            "status": "warn",
            "detail": "Headers could not be inspected because the request did not complete."
        })
        result["checks"].append({
            "name": "HTTPS",
            "status": "warn",
            "detail": "HTTPS status could not be confirmed."
        })
    result["score"] = min(100, score)
    result["summary"] = (
        "Good baseline: keep monitoring and verify configuration." if score >= 80
        else "Some improvements may be needed. Review the warnings below." if score >= 50
        else "Several checks need attention. Review the findings and retest."
    )
    result["disclaimer"] = "Basic HTTP/header checklist only—not a full vulnerability scan or penetration test."
    return result

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(check_website(data.get("url", "")))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/report.csv", methods=["POST"])
def report_csv():
    data = request.get_json(silent=True) or {}
    try:
        result = check_website(data.get("url", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Website", result["url"]])
    writer.writerow(["Checked at", result["checked_at"]])
    writer.writerow(["Score (heuristic)", result["score"]])
    writer.writerow(["Summary", result["summary"]])
    writer.writerow([])
    writer.writerow(["Check", "Status", "Details"])
    for item in result["checks"]:
        writer.writerow([item["name"], item["status"], item["detail"]])
    writer.writerow([])
    writer.writerow(["Disclaimer", result["disclaimer"]])
    memory = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    memory.seek(0)
    return send_file(memory, mimetype="text/csv", as_attachment=True,
                     download_name="hackguard-security-report.csv")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
