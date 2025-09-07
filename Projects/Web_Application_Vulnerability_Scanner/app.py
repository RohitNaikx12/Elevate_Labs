from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import os, time
from scanner import crawl, passive_checks, active_checks, save_reports

app = Flask(__name__)
app.secret_key = "dev-secret"

@app.route("/", methods=["GET","POST"])
def index():
    if request.method=="POST":
        target = request.form.get("target","").strip()
        max_pages = int(request.form.get("max_pages") or 20)
        active = request.form.get("active") == "on"
        try:
            pages = crawl(target, max_pages)
        except Exception as e:
            flash(str(e)); return redirect(url_for("index"))
        findings = passive_checks(pages)
        if active:
            findings += active_checks(pages)
        scan_name = "scan_"+time.strftime("%Y%m%d_%H%M%S")
        save_reports(scan_name, findings)
        return redirect(url_for("report_view", name=scan_name))
    return render_template("index.html")

@app.route("/report/<name>")
def report_view(name):
    md = os.path.join("reports", name + ".md")
    html = os.path.join("reports", name + ".html")
    if os.path.exists(html):
        return send_file(html)
    elif os.path.exists(md):
        return send_file(md)
    else:
        return "Report not found", 404

if __name__ == '__main__':
    app.run(debug=True)
