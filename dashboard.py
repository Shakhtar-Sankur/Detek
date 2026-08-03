from flask import Flask, render_template, request, jsonify
import requests
import os
import json
from datetime import datetime, timedelta

app = Flask(__name__, static_folder='static', template_folder='templates')

API_BASE_URL = os.environ.get('API_BASE_URL', 'http://localhost:5000/api')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    try:
        days = request.args.get('days', 7)
        stats_response = requests.get(f"{API_BASE_URL}/stats?days={days}")
        stats = stats_response.json()

        alerts_response = requests.get(f"{API_BASE_URL}/alerts?limit=10")
        alerts = alerts_response.json().get('alerts', [])

        return render_template(
            'dashboard.html',
            stats=stats,
            alerts=alerts
        )
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/alerts')
def alerts():
    try:
        severity = request.args.get('severity')
        source = request.args.get('source')
        days = int(request.args.get('days', 7))

        end_time = int(datetime.now().timestamp())
        start_time = int((datetime.now() - timedelta(days=days)).timestamp())

        api_url = f"{API_BASE_URL}/alerts?start_time={start_time}&end_time={end_time}"
        if severity:
            api_url += f"&severity={severity}"
        if source:
            api_url += f"&source={source}"

        response = requests.get(api_url)
        data = response.json()
        alerts = data.get('alerts', [])

        return render_template(
            'alerts.html',
            alerts=alerts,
            count=len(alerts),
            filters={
                'severity': severity,
                'source': source,
                'days': days
            }
        )
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/alert/<alert_id>')
def alert_detail(alert_id):
    try:
        response = requests.get(f"{API_BASE_URL}/alerts/{alert_id}")
        alert = response.json()

        return render_template('alert_detail.html', alert=alert)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/submit-scan', methods=['POST'])
def submit_scan():
    try:
        content = request.form.get('content')
        source = request.form.get('source', 'web_dashboard')
        content_type = request.form.get('content_type', 'text/plain')

        if not content:
            return render_template('scan.html', error='No content provided')

        response = requests.post(
            f"{API_BASE_URL}/submit-scan",
            json={
                'content': content,
                'source': source,
                'content_type': content_type
            }
        )

        data = response.json()

        if 'error' in data:
            return render_template('scan.html', error=data['error'])

        return render_template('scan.html', success=True, message=data.get('message'))
    except Exception as e:
        return render_template('scan.html', error=str(e))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))