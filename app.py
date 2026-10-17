from flask import Flask, render_template_string, request
import requests

app = Flask(__name__)

# قالب HTML متكامل وجاهز جوا الكود نفسه عشان نخلص من مشاكل الملفات نهائياً
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>فاحص الأمان - Security Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f7f6; margin: 0; padding: 40px; color: #333; }
        .container { max-width: 700px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #2c3e50; }
        form { display: flex; gap: 10px; margin-bottom: 20px; }
        input[type="text"] { flex: 1; padding: 12px; border: 1px solid #ccc; border-radius: 5px; font-size: 16px; }
        button { padding: 12px 20px; background-color: #27ae60; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #219150; }
        .result { background: #eef9f1; padding: 15px; border-radius: 5px; border-right: 5px solid #27ae60; }
        .error { background: #fde8e8; padding: 15px; border-radius: 5px; border-right: 5px solid #e74c3c; color: #c0392b; }
        ul { list-style: none; padding: 0; }
        li { padding: 8px 0; border-bottom: 1px solid #ddd; }
        .badge { padding: 3px 8px; border-radius: 3px; font-weight: bold; }
        .missing { background: #f8d7da; color: #721c24; }
        .found { background: #d4edda; color: #155724; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 فاحص هيدرز الأمان للمواقع</h1>
        <form method="POST">
            <input type="text" name="url" placeholder="أدخل رابط الموقع (مثال: google.com)" value="{{ url or '' }}" required>
            <button type="submit">فحص الان</button>
        </form>

        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}

        {% if results %}
            <div class="result">
                <h3>نتائج الفحص للرابط: {{ url }}</h3>
                <p>حالة الاستجابة (Status Code): <strong>{{ results.status }}</strong></p>
                <h4>هيدرز الأمان (Security Headers):</h4>
                <ul>
                    {% for header, status in results.headers.items() %}
                        <li>
                            <strong>{{ header }}:</strong> 
                            {% if status == 'مفقود (Missing)' %}
                                <span class="badge missing">{{ status }}</span>
                            {% else %}
                                <span class="badge found">{{ status }}</span>
                            {% endif %}
                        </li>
                    {% endfor %}
                </ul>
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def home():
    scan_results = None
    error_message = None
    target_url = None

    if request.method == 'POST':
        target_url = request.form.get('url', '').strip()
        if target_url:
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
            try:
                res = requests.get(target_url, timeout=5)
                headers_to_check = [
                    'Strict-Transport-Security',
                    'Content-Security-Policy',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Referrer-Policy'
                ]
                
                header_status = {}
                for header in headers_to_check:
                    header_status[header] = res.headers.get(header, 'مفقود (Missing)')

                scan_results = {
                    'status': res.status_code,
                    'headers': header_status
                }
            except Exception as e:
                error_message = f"تعذر الاتصال بالموقع: {str(e)}"

    return render_template_string(HTML_TEMPLATE, results=scan_results, error=error_message, url=target_url)

if __name__ == '__main__':
    app.run(debug=True)