from flask import Flask, jsonify, request
import boto3
import json
import os
from datetime import datetime, timedelta
import threading

app = Flask(__name__)

dynamodb = boto3.resource('dynamodb')
kinesis_client = boto3.client('kinesis')

alerts_table = dynamodb.Table(os.environ.get('DYNAMODB_ALERTS_TABLE', 'data-leak-detection-alerts'))
state_table = dynamodb.Table(os.environ.get('DYNAMODB_STATE_TABLE', 'data-leak-detection-state'))

data_stream = os.environ.get('KINESIS_STREAM', 'data-leak-detection-stream')

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    severity = request.args.get('severity')
    source = request.args.get('source')
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')
    limit = int(request.args.get('limit', 100))

    scan_params = {
        'Limit': limit
    }

    # "timestamp" and "source" are DynamoDB reserved words. Used directly in a
    # FilterExpression they raise ValidationException, so both go through
    # ExpressionAttributeNames placeholders.
    filter_expressions = []
    expression_attr_values = {}
    expression_attr_names = {}

    if severity:
        filter_expressions.append('severity = :severity')
        expression_attr_values[':severity'] = severity

    if source:
        filter_expressions.append('#src = :source')
        expression_attr_names['#src'] = 'source'
        expression_attr_values[':source'] = source

    if start_time:
        filter_expressions.append('#ts >= :start_time')
        expression_attr_names['#ts'] = 'timestamp'
        expression_attr_values[':start_time'] = int(start_time)

    if end_time:
        filter_expressions.append('#ts <= :end_time')
        expression_attr_names['#ts'] = 'timestamp'
        expression_attr_values[':end_time'] = int(end_time)

    if filter_expressions:
        scan_params['FilterExpression'] = ' AND '.join(filter_expressions)
        scan_params['ExpressionAttributeValues'] = expression_attr_values
        if expression_attr_names:
            scan_params['ExpressionAttributeNames'] = expression_attr_names

    try:
        response = alerts_table.scan(**scan_params)
        alerts = response.get('Items', [])

        for alert in alerts:
            if 'details' in alert and isinstance(alert['details'], str):
                alert['details'] = json.loads(alert['details'])

            if 'timestamp' in alert:
                alert['timestamp_str'] = datetime.fromtimestamp(int(alert['timestamp'])).strftime('%Y-%m-%d %H:%M:%S')

        return jsonify({
            'alerts': alerts,
            'count': len(alerts)
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert(alert_id):
    try:
        response = alerts_table.get_item(
            Key={
                'alert_id': alert_id
            }
        )

        alert = response.get('Item')

        if not alert:
            return jsonify({
                'error': 'Alert not found'
            }), 404

        if 'details' in alert and isinstance(alert['details'], str):
            alert['details'] = json.loads(alert['details'])

        if 'timestamp' in alert:
            alert['timestamp_str'] = datetime.fromtimestamp(int(alert['timestamp'])).strftime('%Y-%m-%d %H:%M:%S')

        return jsonify(alert)
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        days = int(request.args.get('days', 7))
        end_time = int(datetime.now().timestamp())
        start_time = int((datetime.now() - timedelta(days=days)).timestamp())

        scan_params = {
            'FilterExpression': '#ts BETWEEN :start_time AND :end_time',
            'ExpressionAttributeNames': {'#ts': 'timestamp'},
            'ExpressionAttributeValues': {
                ':start_time': start_time,
                ':end_time': end_time
            }
        }

        # A single scan returns at most 1 MB, so statistics over a busy window
        # were silently computed from a fraction of the table.
        alerts = []
        while True:
            response = alerts_table.scan(**scan_params)
            alerts.extend(response.get('Items', []))
            last_key = response.get('LastEvaluatedKey')
            if not last_key:
                break
            scan_params['ExclusiveStartKey'] = last_key

        total_alerts = len(alerts)
        alerts_by_severity = {}
        alerts_by_source = {}
        alerts_by_day = {}

        for alert in alerts:
            severity = alert.get('severity', 'unknown')
            alerts_by_severity[severity] = alerts_by_severity.get(severity, 0) + 1

            source = alert.get('source', 'unknown')
            alerts_by_source[source] = alerts_by_source.get(source, 0) + 1

            timestamp = alert.get('timestamp', 0)
            day = datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d')
            alerts_by_day[day] = alerts_by_day.get(day, 0) + 1

        sorted_days = sorted(alerts_by_day.keys())
        alerts_by_day = {day: alerts_by_day[day] for day in sorted_days}

        return jsonify({
            'total_alerts': total_alerts,
            'by_severity': alerts_by_severity,
            'by_source': alerts_by_source,
            'by_day': alerts_by_day,
            'time_range': {
                'start': datetime.fromtimestamp(start_time).strftime('%Y-%m-%d'),
                'end': datetime.fromtimestamp(end_time).strftime('%Y-%m-%d'),
                'days': days
            }
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/submit-scan', methods=['POST'])
def submit_scan():
    try:
        data = request.json

        if not data:
            return jsonify({
                'error': 'No data provided'
            }), 400

        content = data.get('content')
        source = data.get('source', 'api_submission')
        content_type = data.get('content_type', 'text/plain')

        if not content:
            return jsonify({
                'error': 'No content provided'
            }), 400

        record = {
            'source': 'content_scan',
            'data': {
                'source': source,
                'content_type': content_type,
                'content_sample': content
            },
            'timestamp': int(datetime.now().timestamp())
        }

        response = kinesis_client.put_record(
            StreamName=data_stream,
            Data=json.dumps(record),
            PartitionKey=f"api-scan-{source}"
        )

        return jsonify({
            'success': True,
            'message': 'Content submitted for scanning',
            'record_id': response.get('SequenceNumber')
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))