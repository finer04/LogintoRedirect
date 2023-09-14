from flask import Flask, request, Response
import requests

PROXY_URL = ''

def download_file(streamable):
    with streamable as stream:
        stream.raise_for_status()
        for chunk in stream.iter_content(chunk_size=8192):
            yield chunk

def _proxy(*args, **kwargs):
    resp = requests.request(
        method=request.method,
        url=request.url.replace(request.host_url, PROXY_URL),
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        stream=True)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    return Response(download_file(resp), resp.status_code, headers)


app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def download(path):
    return _proxy()

with app.app_context():
    PROXY_URL = requests.get(url='http://127.0.0.1:5000/settings/dest_url').content.decode('utf-8')
    print(PROXY_URL)


if __name__ == "__main__":
    app.run(port=5001,debug=True)