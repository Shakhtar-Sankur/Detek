import boto3
import json
import os
import time
from datetime import datetime, timedelta

class CloudTrailCollector:
    def __init__(self, kinesis_stream_name):
        self.kinesis_client = boto3.client('kinesis')
        self.cloudtrail_client = boto3.client('cloudtrail')
        self.s3_client = boto3.client('s3')
        self.athena_client = boto3.client('athena')
        self.kinesis_stream_name = kinesis_stream_name

    def list_trails(self):
        response = self.cloudtrail_client.describe_trails()
        return [trail['TrailARN'] for trail in response['trailList']]

    def get_trail_status(self, trail_arn):
        response = self.cloudtrail_client.get_trail_status(TrailARN=trail_arn)
        return response

    def query_cloudtrail_via_athena(self, start_time, end_time, database='default', table='cloudtrail_logs'):
        query = f"""
        SELECT *
        FROM {database}.{table}
        WHERE eventtime BETWEEN timestamp '{start_time.isoformat()}' AND timestamp '{end_time.isoformat()}'
        ORDER BY eventtime DESC
        """

        query_execution = self.athena_client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={
                'Database': database
            },
            ResultConfiguration={
                'OutputLocation': f's3://{os.environ.get("ATHENA_OUTPUT_BUCKET", "athena-results")}/cloudtrail-queries/'
            }
        )

        execution_id = query_execution['QueryExecutionId']
        state = 'RUNNING'

        while state in ['RUNNING', 'QUEUED']:
            time.sleep(1)
            response = self.athena_client.get_query_execution(QueryExecutionId=execution_id)
            state = response['QueryExecution']['Status']['State']

        if state == 'SUCCEEDED':
            paginator = self.athena_client.get_paginator('get_query_results')
            for page in paginator.paginate(QueryExecutionId=execution_id):
                yield page['ResultSet']['Rows'][1:]
        else:
            print(f"Query failed with state: {state}")
            yield []

    def process_and_send(self, events):
        records = []

        for event in events:
            record = {
                'Data': json.dumps({
                    'source': 'cloudtrail',
                    'data': event,
                    'timestamp': int(time.time())
                }),
                'PartitionKey': event.get('userIdentity', {}).get('arn', 'default')
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

    def collect_continuously(self, interval=300):
        while True:
            try:
                end_time = datetime.now()
                start_time = end_time - timedelta(seconds=interval)

                print(f"Collecting CloudTrail events from {start_time} to {end_time}")

                events = []
                for result_batch in self.query_cloudtrail_via_athena(start_time, end_time):
                    events.extend(result_batch)

                total_processed = self.process_and_send(events)
                print(f"Processed {total_processed} CloudTrail events")

                time.sleep(interval)
            except Exception as e:
                print(f"Error in collection loop: {str(e)}")
                time.sleep(interval)