import boto3
import json
import os
import time
from datetime import datetime, timedelta
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AlertManager:
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.sns_client = boto3.client('sns')
        self.lambda_client = boto3.client('lambda')

        self.alerts_table = self.dynamodb.Table(os.environ.get('DYNAMODB_ALERTS_TABLE', 'data-leak-detection-alerts'))
        self.state_table = self.dynamodb.Table(os.environ.get('DYNAMODB_STATE_TABLE', 'data-leak-detection-state'))

        self.alert_topic_arn = os.environ.get('SNS_ALERT_TOPIC', '')

        self.smtp_server = os.environ.get('SMTP_SERVER', '')
        self.smtp_port = int(os.environ.get('SMTP_PORT', 587))
        self.smtp_username = os.environ.get('SMTP_USERNAME', '')
        self.smtp_password = os.environ.get('SMTP_PASSWORD', '')
        self.email_from = os.environ.get('EMAIL_FROM', '')

        self.webhook_url = os.environ.get('WEBHOOK_URL', '')

        self.escalation_thresholds = {
            'medium': {
                'count': 5,
                'window': 60 * 60
            },
            'high': {
                'count': 2,
                'window': 60 * 60
            }
        }

    def process_new_alert(self, alert):
        self._store_alert(alert)
        self._check_for_escalation(alert)
        self._send_notifications(alert)

    def _store_alert(self, alert):
        try:
            self.alerts_table.put_item(Item=alert)
        except Exception as e:
            print(f"Error storing alert: {str(e)}")

    def _check_for_escalation(self, alert):
        severity = alert.get('severity')
        if severity not in self.escalation_thresholds:
            return

        threshold = self.escalation_thresholds[severity]

        try:
            end_time = int(time.time())
            start_time = end_time - threshold['window']

            response = self.alerts_table.scan(
                FilterExpression='severity = :severity AND timestamp BETWEEN :start_time AND :end_time',
                ExpressionAttributeValues={
                    ':severity': severity,
                    ':start_time': start_time,
                    ':end_time': end_time
                }
            )

            recent_alerts = response.get('Items', [])

            if len(recent_alerts) >= threshold['count']:
                self._trigger_escalation(severity, recent_alerts)
        except Exception as e:
            print(f"Error checking for escalation: {str(e)}")

    def _trigger_escalation(self, severity, alerts):
        escalation_alert = {
            'alert_id': f"escalation_{int(time.time())}",
            'timestamp': int(time.time()),
            'source': 'alert_escalation',
            'severity': 'critical',
            'details': {
                'original_severity': severity,
                'alert_count': len(alerts),
                'alert_ids': [alert['alert_id'] for alert in alerts],
                'message': f"Multiple {severity} alerts detected within threshold window"
            }
        }

        self._store_alert(escalation_alert)
        self._send_critical_notification(escalation_alert)

    def _send_notifications(self, alert):
        severity = alert.get('severity')

        if severity == 'low':
            pass
        elif severity == 'medium':
            self._send_sns_notification(alert)
        elif severity == 'high':
            self._send_sns_notification(alert)
            self._send_email_notification(alert)
        elif severity == 'critical':
            self._send_critical_notification(alert)

    def _send_sns_notification(self, alert):
        if not self.alert_topic_arn:
            return

        try:
            self.sns_client.publish(
                TopicArn=self.alert_topic_arn,
                Subject=f"Data Leak Detection Alert: {alert['severity']} - {alert['source']}",
                Message=json.dumps(alert, indent=2)
            )
        except Exception as e:
            print(f"Error sending SNS notification: {str(e)}")

    def _send_email_notification(self, alert):
        if not all([self.smtp_server, self.smtp_username, self.smtp_password, self.email_from]):
            return

        try:
            response = self.state_table.get_item(
                Key={
                    'id': 'email_recipients'
                }
            )

            recipients = []
            if 'Item' in response:
                recipients = json.loads(response['Item'].get('recipients', '[]'))

            if not recipients:
                print("No email recipients configured")
                return

            msg = MIMEMultipart()
            msg['From'] = self.email_from
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"Data Leak Detection Alert: {alert['severity']} - {alert['source']}"

            body = f"""
            <html>
            <body>
                <h2>Data Leak Detection Alert</h2>
                <p><strong>Severity:</strong> {alert['severity']}</p>
                <p><strong>Source:</strong> {alert['source']}</p>
                <p><strong>Time:</strong> {datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
                <h3>Details:</h3>
                <pre>{json.dumps(alert['details'], indent=2)}</pre>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)

        except Exception as e:
            print(f"Error sending email notification: {str(e)}")

    def _send_webhook_notification(self, alert):
        if not self.webhook_url:
            return

        try:
            response = requests.post(
                self.webhook_url,
                json=alert,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code >= 400:
                print(f"Webhook error: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error sending webhook notification: {str(e)}")

    def _send_critical_notification(self, alert):
        self._send_sns_notification(alert)
        self._send_email_notification(alert)
        self._send_webhook_notification(alert)

        alert_lambda = os.environ.get('ALERT_LAMBDA_FUNCTION')
        if alert_lambda:
            try:
                self.lambda_client.invoke(
                    FunctionName=alert_lambda,
                    InvocationType='Event',
                    Payload=json.dumps(alert)
                )
            except Exception as e:
                print(f"Error invoking alert Lambda: {str(e)}")

    def process_alert_queue(self):
        while True:
            try:
                response = self.alerts_table.scan(
                    FilterExpression='notification_status <> :status',
                    ExpressionAttributeValues={
                        ':status': 'processed'
                    }
                )

                alerts = response.get('Items', [])

                for alert in alerts:
                    self._send_notifications(alert)

                    self.alerts_table.update_item(
                        Key={
                            'alert_id': alert['alert_id']
                        },
                        UpdateExpression='SET notification_status = :status',
                        ExpressionAttributeValues={
                            ':status': 'processed'
                        }
                    )

                time.sleep(30)
            except Exception as e:
                print(f"Error processing alert queue: {str(e)}")
                time.sleep(30)

if __name__ == "__main__":
    manager = AlertManager()
    manager.process_alert_queue()