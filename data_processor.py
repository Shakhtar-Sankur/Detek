import boto3
import json
import os
import time
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import hashlib

from behavioral_model import BehavioralModel

class DataProcessor:
    def __init__(self, content_classifier_endpoint, behavioral_model_path):
        self.kinesis_client = boto3.client('kinesis')
        self.dynamodb_client = boto3.client('dynamodb')
        self.sagemaker_runtime = boto3.client('sagemaker-runtime')
        self.s3_client = boto3.client('s3')
        self.sns_client = boto3.client('sns')

        self.content_classifier_endpoint = content_classifier_endpoint

        self.behavioral_model = BehavioralModel(model_path=behavioral_model_path)

        self.content_threshold = 0.85
        self.behavior_threshold = 0.75

        self.state_table = os.environ.get('DYNAMODB_STATE_TABLE', 'data-leak-detection-state')
        self.alerts_table = os.environ.get('DYNAMODB_ALERTS_TABLE', 'data-leak-detection-alerts')
        self.alert_topic_arn = os.environ.get('SNS_ALERT_TOPIC', '')

        self.activity_buffer = {}
        self.buffer_time_window = timedelta(hours=24)

    def process_record(self, record):
        try:
            data = json.loads(record['Data'].decode('utf-8'))
            source = data.get('source')
            timestamp = data.get('timestamp')

            if source == 'vpc_flow_logs':
                return self._process_network_flow(data)
            elif source == 'cloudtrail':
                return self._process_api_activity(data)
            elif source == 's3_object_access':
                return self._process_data_access(data)
            elif source == 'content_scan':
                return self._process_content_scan(data)
            else:
                print(f"Unknown source type: {source}")
                return None

        except Exception as e:
            print(f"Error processing record: {str(e)}")
            return None

    def _process_network_flow(self, data):
        flow_data = data.get('data', {})

        if flow_data.get('action') == 'ACCEPT':
            return None

        dst_ip = flow_data.get('dst_ip')
        dst_port = flow_data.get('dst_port')
        protocol = flow_data.get('protocol')
        bytes_transferred = flow_data.get('bytes')

        is_suspicious_destination = self._check_suspicious_destination(dst_ip)

        is_unusual_port = self._check_unusual_port(protocol, dst_port)

        # Flow records routinely omit fields; comparing None raises TypeError and
        # encoding None raises AttributeError, both of which killed the record.
        bytes_transferred = bytes_transferred or 0
        dst_ip = dst_ip or 'unknown'
        is_large_transfer = bytes_transferred > 10000000

        if is_suspicious_destination or is_unusual_port or is_large_transfer:
            alert = {
                'alert_id': f"network_{int(time.time())}_{hashlib.md5(dst_ip.encode()).hexdigest()[:8]}",
                'timestamp': int(time.time()),
                'source': 'network_flow',
                'severity': 'high' if is_suspicious_destination else 'medium',
                'details': {
                    'src_ip': flow_data.get('src_ip'),
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'bytes': bytes_transferred,
                    'reason': {
                        'suspicious_destination': is_suspicious_destination,
                        'unusual_port': is_unusual_port,
                        'large_transfer': is_large_transfer
                    }
                }
            }

            self._create_alert(alert)
            return alert

        return None

    def _process_api_activity(self, data):
        activity_data = data.get('data', {})

        event_name = activity_data.get('eventName')
        event_source = activity_data.get('eventSource')
        user_identity = activity_data.get('userIdentity', {})
        user_id = user_identity.get('principalId', user_identity.get('arn', 'unknown'))
        request_parameters = activity_data.get('requestParameters', {})

        if (event_source == 'dynamodb.amazonaws.com' and event_name.startswith('Get')) or \
           (event_source == 's3.amazonaws.com' and event_name.startswith('Get')) or \
           (event_source == 's3.amazonaws.com' and event_name == 'ListObjects'):
            self._add_to_activity_buffer(user_id, {
                'timestamp': int(time.time()),
                'user_id': user_id,
                'action': event_name,
                'resource_type': event_source.split('.')[0],
                'data_volume': 0,
                'duration': 0
            })
            return None

        is_sensitive_operation = self._check_sensitive_operation(event_source, event_name)

        is_unusual_service = self._check_unusual_service(user_id, event_source)

        self._add_to_activity_buffer(user_id, {
            'timestamp': int(time.time()),
            'user_id': user_id,
            'action': event_name,
            'resource_type': event_source.split('.')[0],
            'data_volume': len(json.dumps(request_parameters)),
            'duration': 0
        })

        behavior_result = None
        if len(self.activity_buffer.get(user_id, [])) >= 10:
            behavior_result = self._perform_behavioral_analysis(user_id)

        if is_sensitive_operation or is_unusual_service or (behavior_result and behavior_result.get('is_anomalous')):
            alert = {
                'alert_id': f"api_{int(time.time())}_{hashlib.md5(user_id.encode()).hexdigest()[:8]}",
                'timestamp': int(time.time()),
                'source': 'api_activity',
                'severity': 'high' if is_sensitive_operation else 'medium',
                'details': {
                    'user_id': user_id,
                    'event_name': event_name,
                    'event_source': event_source,
                    'request_parameters': request_parameters,
                    'reason': {
                        'sensitive_operation': is_sensitive_operation,
                        'unusual_service': is_unusual_service,
                        'behavioral_anomaly': behavior_result.get('is_anomalous') if behavior_result else False,
                        'behavioral_score': behavior_result.get('score') if behavior_result else 0
                    }
                }
            }

            self._create_alert(alert)
            return alert

        return None

    def _process_data_access(self, data):
        access_data = data.get('data', {})

        user_id = access_data.get('user_id', 'unknown')
        object_key = access_data.get('object_key', '')
        bucket_name = access_data.get('bucket_name', '')
        operation = access_data.get('operation', '')
        bytes_processed = access_data.get('bytes_processed', 0)

        content_classification = None
        if operation in ['GetObject', 'DownloadObject', 'ReadObject']:
            content_sample = self._get_object_content_sample(bucket_name, object_key)
            if content_sample:
                content_classification = self._classify_content(content_sample)

        self._add_to_activity_buffer(user_id, {
            'timestamp': int(time.time()),
            'user_id': user_id,
            'action': operation,
            'resource_type': 's3',
            'data_volume': bytes_processed,
            'duration': 0
        })

        is_large_access = bytes_processed > 50000000

        behavior_result = None
        if len(self.activity_buffer.get(user_id, [])) >= 10:
            behavior_result = self._perform_behavioral_analysis(user_id)

        is_sensitive_content = content_classification and content_classification.get('is_sensitive', False) and \
                              content_classification.get('confidence', 0) > self.content_threshold

        is_behavioral_anomaly = behavior_result and behavior_result.get('is_anomalous')

        if is_sensitive_content or is_large_access or is_behavioral_anomaly:
            alert = {
                'alert_id': f"data_{int(time.time())}_{hashlib.md5((bucket_name + object_key).encode()).hexdigest()[:8]}",
                'timestamp': int(time.time()),
                'source': 'data_access',
                'severity': 'high' if is_sensitive_content else 'medium',
                'details': {
                    'user_id': user_id,
                    'bucket_name': bucket_name,
                    'object_key': object_key,
                    'operation': operation,
                    'bytes_processed': bytes_processed,
                    'reason': {
                        'sensitive_content': is_sensitive_content,
                        'content_category': content_classification.get('category') if content_classification else None,
                        'content_confidence': content_classification.get('confidence') if content_classification else 0,
                        'large_access': is_large_access,
                        'behavioral_anomaly': is_behavioral_anomaly,
                        'behavioral_score': behavior_result.get('score') if behavior_result else 0
                    }
                }
            }

            self._create_alert(alert)
            return alert

        return None

    def _process_content_scan(self, data):
        scan_data = data.get('data', {})

        content_source = scan_data.get('source', {})
        content_type = scan_data.get('content_type', '')
        content_sample = scan_data.get('content_sample', '')

        classification = self._classify_content(content_sample)

        if classification and classification.get('is_sensitive', False) and \
           classification.get('confidence', 0) > self.content_threshold:
            alert = {
                'alert_id': f"content_{int(time.time())}_{hashlib.md5(str(content_source).encode()).hexdigest()[:8]}",
                'timestamp': int(time.time()),
                'source': 'content_scan',
                'severity': 'high',
                'details': {
                    'content_source': content_source,
                    'content_type': content_type,
                    'classification': {
                        'category': classification.get('category'),
                        'confidence': classification.get('confidence'),
                    }
                }
            }

            self._create_alert(alert)
            return alert

        return None

    def _add_to_activity_buffer(self, user_id, activity):
        if user_id not in self.activity_buffer:
            self.activity_buffer[user_id] = []

        self.activity_buffer[user_id].append(activity)

        current_time = datetime.now()
        self.activity_buffer[user_id] = [
            act for act in self.activity_buffer[user_id]
            if current_time - datetime.fromtimestamp(act['timestamp']) <= self.buffer_time_window
        ]

    def _perform_behavioral_analysis(self, user_id):
        activities = self.activity_buffer.get(user_id, [])
        if not activities:
            return None

        results = self.behavioral_model.detect_anomalies(
            activities,
            threshold=self.behavior_threshold
        )

        return results.get(user_id)

    def _classify_content(self, content):
        try:
            response = self.sagemaker_runtime.invoke_endpoint(
                EndpointName=self.content_classifier_endpoint,
                ContentType='application/json',
                Body=json.dumps({'text': content})
            )

            result = json.loads(response['Body'].read().decode())
            return result
        except Exception as e:
            print(f"Error classifying content: {str(e)}")
            return None

    def _check_suspicious_destination(self, ip_address):
        suspicious_ips = [
            '185.159.128.0/22',
            '91.243.91.0/24',
            '103.102.166.0/24'
        ]

        for suspicious_ip in suspicious_ips:
            if suspicious_ip.endswith('/32') and ip_address == suspicious_ip[:-3]:
                return True
            elif '/' in suspicious_ip:
                prefix = suspicious_ip.split('/')[0]
                if ip_address.startswith(prefix.rsplit('.', 1)[0]):
                    return True

        return False

    def _check_unusual_port(self, protocol, port):
        if protocol == 6:
            unusual_tcp_ports = [4444, 31337, 8081, 8082, 6666, 1337]
            return port in unusual_tcp_ports
        elif protocol == 17:
            unusual_udp_ports = [53, 123, 161, 389]
            return port in unusual_udp_ports

        return False

    def _check_sensitive_operation(self, service, operation):
        sensitive_operations = {
            'dynamodb.amazonaws.com': ['DeleteTable', 'BatchWriteItem', 'DeleteItem'],
            's3.amazonaws.com': ['DeleteBucket', 'DeleteObject', 'DeleteObjects', 'PutBucketPolicy'],
            'ec2.amazonaws.com': ['TerminateInstances', 'ModifyInstanceAttribute'],
            'iam.amazonaws.com': ['CreateUser', 'CreateAccessKey', 'PutUserPolicy', 'AttachUserPolicy'],
            'kms.amazonaws.com': ['Decrypt', 'GenerateDataKey', 'Encrypt'],
            'secretsmanager.amazonaws.com': ['GetSecretValue']
        }

        return service in sensitive_operations and operation in sensitive_operations[service]

    def _check_unusual_service(self, user_id, service):
        try:
            response = self.dynamodb_client.get_item(
                TableName=self.state_table,
                Key={
                    'id': {'S': f"user_services_{user_id}"}
                }
            )

            if 'Item' in response:
                services = json.loads(response['Item'].get('services', {}).get('S', '[]'))
                return service not in services
            else:
                return True
        except Exception as e:
            print(f"Error checking user service history: {str(e)}")
            return False

    def _get_object_content_sample(self, bucket, key, max_size=4096):
        try:
            head_response = self.s3_client.head_object(Bucket=bucket, Key=key)
            content_type = head_response.get('ContentType', '')

            if not content_type.startswith('text/') and not content_type.endswith('/json') and \
               not content_type.endswith('/xml') and not content_type.endswith('/csv'):
                return None

            response = self.s3_client.get_object(
                Bucket=bucket,
                Key=key,
                Range=f'bytes=0-{max_size-1}'
            )

            return response['Body'].read().decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"Error getting object content: {str(e)}")
            return None

    def _create_alert(self, alert):
        try:
            self.dynamodb_client.put_item(
                TableName=self.alerts_table,
                Item={
                    'alert_id': {'S': alert['alert_id']},
                    'timestamp': {'N': str(alert['timestamp'])},
                    'source': {'S': alert['source']},
                    'severity': {'S': alert['severity']},
                    'details': {'S': json.dumps(alert['details'])}
                }
            )

            if self.alert_topic_arn:
                self.sns_client.publish(
                    TopicArn=self.alert_topic_arn,
                    Subject=f"Data Leak Detection Alert: {alert['severity']} - {alert['source']}",
                    Message=json.dumps(alert, indent=2)
                )

            print(f"Created alert: {alert['alert_id']} - {alert['severity']} - {alert['source']}")

        except Exception as e:
            print(f"Error creating alert: {str(e)}")

    def process_stream(self, stream_name, batch_size=100):
        response = self.kinesis_client.describe_stream(StreamName=stream_name)
        shards = response['StreamDescription']['Shards']

        shard_iterators = []
        for shard in shards:
            shard_id = shard['ShardId']
            iterator = self.kinesis_client.get_shard_iterator(
                StreamName=stream_name,
                ShardId=shard_id,
                ShardIteratorType='LATEST'
            )['ShardIterator']

            shard_iterators.append({
                'shard_id': shard_id,
                'iterator': iterator
            })

        while True:
            for i, shard_info in enumerate(shard_iterators):
                try:
                    response = self.kinesis_client.get_records(
                        ShardIterator=shard_info['iterator'],
                        Limit=batch_size
                    )

                    records = response['Records']
                    next_iterator = response['NextShardIterator']

                    shard_iterators[i]['iterator'] = next_iterator

                    if records:
                        print(f"Processing {len(records)} records from shard {shard_info['shard_id']}")

                        with ThreadPoolExecutor(max_workers=10) as executor:
                            executor.map(self.process_record, records)

                except Exception as e:
                    print(f"Error processing shard {shard_info['shard_id']}: {str(e)}")

                    try:
                        new_iterator = self.kinesis_client.get_shard_iterator(
                            StreamName=stream_name,
                            ShardId=shard_info['shard_id'],
                            ShardIteratorType='LATEST'
                        )['ShardIterator']

                        shard_iterators[i]['iterator'] = new_iterator
                    except Exception as iterator_error:
                        print(f"Error getting new iterator: {str(iterator_error)}")

            time.sleep(1)