from flask import Flask, request, Response
import requests as req_lib

app = Flask(__name__)

UPSTREAM = "https://teams.microsoft.com/api/mt"

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path):
    url = f"{UPSTREAM}/{path}" if path else UPSTREAM
    headers = {k: v for k, v in request.headers if k.lower() not in ("host", "content-length")}
    try:
        resp = req_lib.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request.get_data(),
            timeout=30,
        )
    except req_lib.RequestException as e:
        return Response(str(e), status=502)
    excluded = {"transfer-encoding", "content-encoding", "content-length"}
    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
    return Response(resp.content, status=resp.status_code, headers=resp_headers)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
