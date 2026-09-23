from flask import Flask, request, jsonify
from securevalidator.core import (
    validate_email, validate_url, validate_filename,
    sanitize_sql_input, sanitize_html_input
)
from securelogger.logger import secure_logger

app = Flask(__name__)

@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(force=True)
    try:
        results = {
            "email": validate_email(data.get("email", "")),
            "url": validate_url(data.get("url", "")),
            "filename": validate_filename(data.get("filename", "")),
            "sql": sanitize_sql_input(data.get("sql", "")),
            "html": sanitize_html_input(data.get("html", "")),
        }
        secure_logger.info("Validation check performed", extra={"data": data, "results": results})
        return jsonify(results)
    except Exception as e:
        secure_logger.warning("Invalid JSON received", extra={"data": str(request.data)})
        return jsonify({"error": "Invalid JSON format"}), 400

if __name__ == "__main__":
    app.run(debug=True)
