import boto3
import json
import os
import time
from datetime import datetime

class VPCFlowCollector:
    def __init__(self, kinesis_stream_name):
        self.kinesis_client = boto3.client('kinesis')
        self.logs_client = boto3.client('logs')
        self.ec2_client = boto3.client('ec2')
        self.kinesis_stream_name = kinesis_stream_name

    def list_flow_logs(self):
        response = self.ec2_client.describe_flow_logs()
        return [
            {
                'id': flow_log['FlowLogId'],
                'log_group_name': flow_log['LogGroupName']
                    if 'LogGroupName' in flow_log else None
            }
            for flow_log in response['FlowLogs']
            if flow_log.get('LogDestinationType') == 'cloud-watch-logs'
        ]

    def get_log_events(self, log_group_name, start_time=None, end_time=None):
        paginator = self.logs_client.get_paginator('filter_log_events')

        if not start_time:
            start_time = int((datetime.now().timestamp() - 300) * 1000)
        if not end_time:
            end_time = int(datetime.now().timestamp() * 1000)

        params = {
            'logGroupName': log_group_name,
            'startTime': start_time,
            'endTime': end_time
        }

        for page in paginator.paginate(**params):
            if 'events' in page:
                yield page['events']

    def parse_flow_log(self, message):
        fields = message.split()
        if len(fields) < 14:
            return None

        try:
            return {
                'version': fields[0],
                'account_id': fields[1],
                'interface_id': fields[2],
                'src_ip': fields[3],
                'dst_ip': fields[4],
                'src_port': int(fields[5]),
                'dst_port': int(fields[6]),
                'protocol': int(fields[7]),
                'packets': int(fields[8]),
                'bytes': int(fields[9]),
                'start_time': int(fields[10]),
                'end_time': int(fields[11]),
                'action': fields[12],
                'log_status': fields[13],
                'collected_at': int(time.time())
            }
        except (ValueError, IndexError):
            return None

    def process_and_send(self, log_events):
        records = []

        for event in log_events:
            if 'message' not in event:
                continue

            parsed_log = self.parse_flow_log(event['message'])
            if not parsed_log:
                continue

            record = {
                'Data': json.dumps({
                    'source': 'vpc_flow_logs',
                    'data': parsed_log,
                    'timestamp': int(time.time())
                }),
                'PartitionKey': parsed_log['interface_id']
            }
            records.append(record)

            if len(records) >= 500:
                self._send_to_kinesis(records)
                records = []

        if records:
            return self._send_to_kinesis(records)
        return 0

    def _send_to_kinesis(self, records):
        try:
            response = self.kinesis_client.put_records(
                Records=records,
                StreamName=self.kinesis_stream_name
            )

            failed = response.get('FailedRecordCount', 0)
            if failed > 0:
                print(f"Failed to send {failed} records to Kinesis")

            return len(records) - failed
        except Exception as e:
            print(f"Error sending records to Kinesis: {str(e)}")
            return 0

    def collect_continuously(self, interval=60):
        while True:
            try:
                flow_logs = self.list_flow_logs()
                total_processed = 0

                for flow_log in flow_logs:
                    if not flow_log['log_group_name']:
                        continue

                    print(f"Processing flow log {flow_log['id']} from {flow_log['log_group_name']}")

                    for events_batch in self.get_log_events(flow_log['log_group_name']):
                        batch_processed = self.process_and_send(events_batch)
                        total_processed += batch_processed

                print(f"Processed {total_processed} flow log records")
                time.sleep(interval)
            except Exception as e:
                print(f"Error in collection loop: {str(e)}")
                time.sleep(interval)

if __name__ == "__main__":
    kinesis_stream = os.environ.get('KINESIS_STREAM_NAME')
    if not kinesis_stream:
        print("KINESIS_STREAM_NAME environment variable not set")
        exit(1)

    collector = VPCFlowCollector(kinesis_stream)
    collector.collect_continuously()