from flask import Flask, render_template, request
import requests
import socket
from urllib.parse import urlparse

app = Flask(__name__)

# دالة فحص هيدرز الأمان للموقع
def check_security_headers(url):
    results = {}
    try:
        # التأكد من أن الرابط يبدأ بـ http أو https
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
            
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        # قائمة بأهم هيدرز الأمان
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection'
        ]
        
        for header in security_headers:
            if header in headers:
                results[header] = {"status": "موجود (آمن)", "value": headers[header]}
            else:
                results[header] = {"status": "مفقود (غير محمي)", "value": None}
                
        return results, "نجح الفحص"
    except Exception as e:
        return None, f"خطأ في الاتصال بالموقع: {str(e)}"

@app.route('/', methods=['GET', 'POST'])
def home():
    scan_results = None
    error_message = None
    target_url = None
    
    if request.method == 'POST':
        target_url = request.form.get('url')
        if target_url:
            scan_results, error_message = check_security_headers(target_url)
            
    return render_template('index.html', results=scan_results, error=error_message, url=target_url)

if __name__ == '__main__':
    app.run(debug=True)