"""Flask web server for the DPI Engine."""

from __future__ import annotations

import json
import shutil
import sys
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

# Project root on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dpi.rules import list_app_names
from dpi.service import analyze_pcap

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB

JOBS_DIR = ROOT / "web" / "jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_PCAP = ROOT / "test_dpi.pcap"


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/apps")
def api_apps():
    apps = [a for a in list_app_names() if a not in ("Unknown", "TLS", "QUIC", "HTTP", "HTTPS", "DNS")]
    return jsonify({"apps": sorted(set(apps))})


@app.post("/api/analyze")
def api_analyze():
    if "pcap" not in request.files:
        return jsonify({"success": False, "error": "No PCAP file uploaded"}), 400

    upload = request.files["pcap"]
    if not upload.filename:
        return jsonify({"success": False, "error": "Empty filename"}), 400

    job_id = uuid.uuid4().hex[:12]
    job_dir = JOBS_DIR / job_id
    job_dir.mkdir(parents=True)

    input_path = job_dir / "input.pcap"
    output_path = job_dir / "filtered.pcap"
    upload.save(input_path)

    options_raw = request.form.get("options", "{}")
    try:
        options = json.loads(options_raw)
    except json.JSONDecodeError:
        shutil.rmtree(job_dir, ignore_errors=True)
        return jsonify({"success": False, "error": "Invalid options JSON"}), 400

    mode = options.get("mode", "multithreaded")
    if mode not in ("multithreaded", "simple"):
        mode = "multithreaded"

    report = analyze_pcap(
        input_path,
        output_path,
        mode=mode,
        block_ips=options.get("block_ips", []),
        block_apps=options.get("block_apps", []),
        block_domains=options.get("block_domains", []),
        lbs=int(options.get("lbs", 2)),
        fps=int(options.get("fps", 2)),
        quiet=True,
    )

    result = report.to_dict()
    result["job_id"] = job_id

    if report.success and output_path.is_file():
        result["download_url"] = f"/api/download/{job_id}"
    else:
        shutil.rmtree(job_dir, ignore_errors=True)

    status = 200 if report.success else 422
    return jsonify(result), status


@app.get("/api/download/<job_id>")
def api_download(job_id: str):
    if not job_id.isalnum() or len(job_id) > 32:
        return jsonify({"error": "Invalid job id"}), 400

    output_path = JOBS_DIR / job_id / "filtered.pcap"
    if not output_path.is_file():
        return jsonify({"error": "File not found or expired"}), 404

    return send_file(
        output_path,
        as_attachment=True,
        download_name="filtered.pcap",
        mimetype="application/vnd.tcpdump.pcap",
    )


@app.post("/api/sample")
def api_sample():
    """Return path to bundled or generated sample PCAP for the UI."""
    if not SAMPLE_PCAP.is_file():
        try:
            import generate_test_pcap

            generate_test_pcap.main()
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 500

    if not SAMPLE_PCAP.is_file():
        return jsonify({"success": False, "error": "Sample PCAP not available"}), 404

    return jsonify(
        {
            "success": True,
            "filename": "test_dpi.pcap",
            "size": SAMPLE_PCAP.stat().st_size,
            "download_url": "/api/sample/file",
        }
    )


@app.get("/api/sample/file")
def api_sample_file():
    if not SAMPLE_PCAP.is_file():
        return jsonify({"error": "Sample not found"}), 404
    return send_file(
        SAMPLE_PCAP,
        as_attachment=False,
        download_name="test_dpi.pcap",
        mimetype="application/vnd.tcpdump.pcap",
    )


def main() -> None:
    print("DPI Web UI: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
