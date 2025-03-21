from flask import Flask, render_template, request, jsonify, send_file
import nmap
import sqlite3
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt
import io
import base64
import os

app = Flask(__name__)

DB_PATH = "scans.db"

def get_db_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            os TEXT,
            ports TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()

init_db()

def scan_target(target):
    nm = nmap.PortScanner()

    try:
        nm.scan(target, arguments="-T4 -F")

        open_ports = [
            str(port) for host in nm.all_hosts()
            for proto in nm[host].all_protocols()
            for port in nm[host][proto].keys()
            if nm[host][proto][port]['state'] == 'open'
        ]

        if not open_ports:
            return {"error": "No open ports found."}

        ports_str = ",".join(open_ports)
        nm.scan(target, arguments=f"-A -sV -O --script vuln -p {ports_str}")

        scan_result = {
            host: {
                "os": nm[host].get("osmatch", [{}])[0].get("name", "Unknown OS"),
                "ports": [
                    {
                        "port": port,
                        "state": nm[host][proto][port].get('state', 'Unknown'),
                        "service": nm[host][proto][port].get('name', 'Unknown'),
                        "version": nm[host][proto][port].get('version', 'N/A'),
                        "vulnerabilities": nm[host][proto][port].get('script', {}).get('vuln', 'No known vulnerabilities')
                    }
                    for proto in nm[host].all_protocols()
                    for port in nm[host][proto].keys()
                ]
            }
            for host in nm.all_hosts()
        }

        return scan_result
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}

def save_scan_to_db(target, scan_result):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        for host, data in scan_result.items():
            ports_info = ", ".join(f"{p['port']}/{p['service']}" for p in data["ports"])
            cursor.execute('''INSERT INTO scans (target, os, ports)
                              VALUES (?, ?, ?)''', (host, data["os"], ports_info))

        conn.commit()

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if target:
            result = scan_target(target)
            if "error" not in result:
                save_scan_to_db(target, result)
        else:
            result = {"error": "No target provided!"}

    return render_template("index.html", result=result)

@app.route("/history")
def history():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT target, os, ports, timestamp FROM scans ORDER BY timestamp DESC LIMIT 10")
            scans = cursor.fetchall()

        port_chart = generate_port_chart()

    except Exception as e:
        print(f"Error retrieving history: {e}")
        scans = []
        port_chart = None

    return render_template("history.html", scans=scans, port_chart=port_chart)

@app.route("/export/json")
def export_json():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT target, os, ports, timestamp FROM scans ORDER BY timestamp DESC LIMIT 10")
            scans = cursor.fetchall()

        scan_data = [{"target": s[0], "os": s[1], "ports": s[2], "timestamp": s[3]} for s in scans]
        return jsonify(scan_data)

    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/export/pdf")
def export_pdf():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT target, os, ports, timestamp FROM scans ORDER BY timestamp DESC LIMIT 10")
            scans = cursor.fetchall()

        pdf_filename = "scan_report.pdf"

        c = canvas.Canvas(pdf_filename, pagesize=letter)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(200, 770, "🔍 Scan Report")
        c.setFont("Helvetica", 12)

        y = 750
        for scan in scans:
            text = f"Target: {scan[0]}, OS: {scan[1]}, Ports: {scan[2]}, Time: {scan[3]}"
            c.drawString(50, y, text)
            y -= 20
            if y < 50:
                c.showPage()
                c.setFont("Helvetica", 12)
                y = 750

        c.save()

        return send_file(pdf_filename, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)})

def generate_port_chart():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT target, ports FROM scans ORDER BY timestamp DESC LIMIT 10")
            scans = cursor.fetchall()

        if not scans:
            return None

        targets = [scan[0] for scan in scans]
        port_counts = [len(scan[1].split(",")) if scan[1] else 0 for scan in scans]

        plt.figure(figsize=(10, 5))
        plt.bar(targets, port_counts, color="blue")
        plt.xlabel("Target")
        plt.ylabel("Open Ports")
        plt.title("Number of Open Ports per Scan")
        plt.xticks(rotation=45)

        img = io.BytesIO()
        plt.savefig(img, format="png")
        img.seek(0)
        graph_url = base64.b64encode(img.getvalue()).decode()
        plt.close()

        return f"data:image/png;base64,{graph_url}"

    except Exception as e:
        print(f"Error generating graph: {e}")
        return None

if __name__ == "__main__":
    app.run(debug=False)
