from flask import Flask, request, jsonify, render_template
from analyzer import analyze_password

app = Flask(__name__)


@app.route("/")
def index():
    """Serve the frontend HTML page."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Accepts a JSON body: { "password": "somepassword" }
    Returns the full analysis result as JSON.
    """
    data     = request.get_json()
    password = data.get("password", "")
    result   = analyze_password(password)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)