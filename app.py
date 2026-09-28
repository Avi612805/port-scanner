from flask import Flask, render_template, request, redirect, session, Response
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()
import nmap
from datetime import datetime

app = Flask(__name__)
app.secret_key = "portscan-secret-key"
import os

SENDER_EMAIL = os.getenv("SENDER_EMAIL")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")
APP_PASSWORD = os.getenv("APP_PASSWORD")

nm = nmap.PortScanner()

scan_history = []
last_results = None
last_scan_type = "tcp"
last_port_range = "1-100"


@app.route("/")
def home():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "1234":
            session["logged_in"] = True
            return redirect("/dashboard")

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    global last_results
    global last_scan_type
    global last_port_range

    if not session.get("logged_in"):
        return redirect("/login")

    results = last_results
    scan_type = last_scan_type
    port_range = last_port_range

    if request.method == "POST":

        target = "127.0.0.1"

        port_range = request.form.get(
            "port_range",
            "1-100"
        )

        scan_type = request.form.get(
            "scan_type",
            "tcp"
        ).lower()

        if scan_type == "tcp":
           arguments = "-sT"

        elif scan_type == "udp":
           arguments = "-sU"

        elif scan_type == "syn":
            arguments = "-sS"

        elif scan_type == "version":
            arguments = "-sV"

        elif scan_type == "os":
            arguments = "-O"

        elif scan_type == "aggressive":
            arguments = "-A"

    else:
        arguments = "-sT"

    try:

            nm.scan(
                hosts=target,
                ports=port_range,
                arguments=arguments
            )

            results = nm

            last_results = results
            last_scan_type = scan_type
            last_port_range = port_range
            open_ports = 0

            for host in results.all_hosts():

                if scan_type in results[host]:

                    for port in results[host][scan_type]:

                        state = results[host][scan_type][port]["state"]

                        if state == "open":
                            open_ports += 1

            scan_history.append({
                "target": target,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ports": open_ports,
                "port_range": port_range,
                "scan_type": scan_type.upper()
            })

    except Exception as e:

            return render_template(
                "index.html",
                error=str(e),
                results=None,
                scan_type=scan_type,
                port_range=port_range,
                scan_history=scan_history
            )

    return render_template(
        "index.html",
        results=results,
        scan_type=scan_type,
        port_range=port_range,
        scan_history=scan_history
    )
@app.route("/history")
def history():

    if not session.get("logged_in"):
        return redirect("/login")

    return render_template(
        "index.html",
        results=None,
        scan_type=last_scan_type,
        port_range=last_port_range,
        scan_history=scan_history
    )
@app.route("/report")
def report():

    if not session.get("logged_in"):
        return redirect("/login")

    if not scan_history:
        return "No scan has been performed yet."

    latest = scan_history[-1]

    return render_template(
        "report.html",
        scan=latest
    )
@app.route("/download_pdf")
def download_pdf():

    if not session.get("logged_in"):
        return redirect("/login")

    if not scan_history:
        return "No scan available."

    latest = scan_history[-1]

    from reportlab.pdfgen import canvas
    from io import BytesIO

    buffer = BytesIO()

    pdf = canvas.Canvas(buffer)

    pdf.setTitle("Port Scan Report")

    pdf.drawString(50, 800, "PORT SCAN REPORT")
    pdf.drawString(50, 760, "Target: " + latest["target"])
    pdf.drawString(50, 740, "Scan Type: " + latest["scan_type"])
    pdf.drawString(50, 720, "Port Range: " + latest["port_range"])
    pdf.drawString(50, 700, "Open Ports: " + str(latest["ports"]))
    pdf.drawString(50, 680, "Scan Time: " + latest["time"])

    pdf.save()

    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
            "attachment; filename=scan_report.pdf"
        }
    ) 
@app.route("/email_report")
def email_report():

    if not session.get("logged_in"):
        return redirect("/login")

    if not scan_history:
        return "No scan available."

    latest = scan_history[-1]

    msg = EmailMessage()
    msg["Subject"] = "Port Scan Report"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    msg.set_content(f"""Port Scan Report

Target: {latest["target"]}
Scan Type: {latest["scan_type"]}
Port Range: {latest["port_range"]}
Open Ports: {latest["ports"]}
Scan Time: {latest["time"]}
""")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)

        return "Email sent successfully."

    except Exception as e:
        return "Email failed: " + str(e)
 
@app.route("/download_xml")
def download_xml():

    if not session.get("logged_in"):
        return redirect("/login")

    if not scan_history:
        return "No scan available."

    latest = scan_history[-1]

    xml_data = f"""<?xml version="1.0" encoding="UTF-8"?>
<scan_report>
    <target>{latest["target"]}</target>
    <scan_type>{latest["scan_type"]}</scan_type>
    <port_range>{latest["port_range"]}</port_range>
    <open_ports>{latest["ports"]}</open_ports>
    <scan_time>{latest["time"]}</scan_time>
</scan_report>
"""

    return Response(
        xml_data,
        mimetype="application/xml",
        headers={
            "Content-Disposition":
            "attachment; filename=scan_report.xml"
        }
    )



if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )