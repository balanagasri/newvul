from flask import Flask, render_template, request
import requests
import ssl
from urllib3.poolmanager import PoolManager
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup

app = Flask(__name__)

# Custom SSL Adapter to handle SSL handshake issues
class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        # Remove specific cipher setting and let the system handle it automatically
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# Create a session and mount the adapter to ensure SSL compatibility
session = requests.Session()
session.mount("https://", SSLAdapter())

# SQL Injection Test
def test_sql_injection(url):
    sqli_payloads = ["' OR 1=1 --", "' OR 'a'='a", '" OR "a"="a']
    for payload in sqli_payloads:
        try:
            response = session.get(url, params={"search": payload})
            if "error" in response.text or "syntax" in response.text:
                return f"Potential SQL Injection vulnerability detected in {url}.    NOTE:Please check SQL security!!!."
        except requests.exceptions.RequestException as e:
            return f"Error occurred while testing SQLi: {e}"
    return None

# XSS Test
def test_xss(url):
    xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    for payload in xss_payloads:
        try:
            response = session.get(url, params={"search": payload})
            if payload in response.text:
                return f"Potential XSS vulnerability detected in {url}.    NOTE : please check the JAVASCRIPT security!!!"
        except requests.exceptions.RequestException as e:
            return f"Error occurred while testing XSS: {e}"
    return None

# Main function to run the scanner
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        sql_injection_result = test_sql_injection(url)
        xss_result = test_xss(url)
        return render_template("index.html", url=url, sql_injection_result=sql_injection_result, xss_result=xss_result)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
