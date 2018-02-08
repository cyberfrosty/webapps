#!/usr/bin python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost. All rights reserved.

AWS Utility classes for DynamoDB, S3, SES, SNS and Route 53
"""

from __future__ import print_function

import base64
from datetime import datetime
import hashlib
import hmac
import pytz
import simplejson as json
import boto3
from botocore.exceptions import ClientError
from utils import load_config, preset_password

CONFIG_DNS_TTL = 60 # TTL (Time To Live) in seconds tells DNS servers how long to cache
CONFIG_DNS_TYPE = 'A' # A record


class DynamoDB(object):
    """ Utility class for access to AWS DynamoDB.
    """
    def __init__(self, config, table_name):
        """ Constructor, get AWS resource and table.
        Args:
            config: dict of config info
            table_name: name of the database table
        """
        self.dynamodb = boto3.resource('dynamodb')
        self.config = config
        self.table_name = table_name
        self.table = self.dynamodb.Table(table_name)

    def generate_user_id(self, user):
        """ Use an HMAC to generate a user id to keep DB more secure. This prevents someone from
            looking up users by name or even hash of user name, without using the official API.
        Args:
            user name
        Returns:
            base32 userid
        """
        digest = hmac.new(
            self.config.get('user_id_hmac').encode('utf-8'),
            user.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        return base64.b32encode(digest[0:30])

    def create_table(self, primary_key):
        """ Create a table.
        Args:
            primary_key: table primary key, e.g. 'username'
        """
        active = False
        try:
            active = self.table.table_status == 'ACTIVE'
        except ClientError:
            pass

        if active:
            pass
        else:
            self.table = self.dynamodb.create_table(
                TableName=self.table_name,
                KeySchema=[
                    {
                        'AttributeName': primary_key,
                        'KeyType': 'HASH'  #Partition key
                    },
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': primary_key,
                        'AttributeType': 'S'
                    },
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )

    def delete_item(self, key, value):
        """ Delete an item from the table.
        Args:
            key: table primary key, e.g. 'username'
            value: primary key value to match
        """
        try:
            self.table.delete_item(Key={key : value})
            return {'message': 'Item deleted'}
        except (ClientError, KeyError) as err:
            return {'error': err.message}

    def get_item(self, key, value):
        """ Get an item from the table.
        Args:
            key: table primary key, e.g. 'username'
            value: primary key value to match
        Return:
            dict
        """
        try:
            response = self.table.get_item(Key={key : value})
            return response['Item']
        except (ClientError, KeyError) as err:
            return {'error': err.message}

    def put_item(self, value):
        """ Create or replace an item in the table.
        Args:
            value: json item data, which includes table primary key
        Return:
            dict
        """
        try:
            self.table.put_item(Item=value)
            return {'message': 'Item added/updated'}
        except (ClientError, KeyError) as err:
            return {'error': err.message}

    def update_item(self, id, key, value):
        """ Add or replace an item field in the table.
        Args:
            value: json item data, which includes table primary key
        Return:
            dict
        """
        try:
            self.table.update_item(Key={'id': id},
                                   UpdateExpression="SET " + key + " = :k",
                                   ExpressionAttributeValues={':k': value},
                                   ReturnValues="UPDATED_NEW")
            return {'message': 'Item updated'}
        except (ClientError, KeyError) as err:
            return {'error': err.message}

    def load_table(self, infile):
        """ Load json data from a file into table.
        {
          "Users": [
            {
              "user": "yuki",
              "email": "yuki@samialert.com",
              "phone": "+1-720-534-4871",
              "devices": [
                {"mac":"02:42:92:03:fa:ba","name":"room","ip":"2.3.4.5","port":8437,"internet":True}
                {"mac":"10:bf:4e:4d:32:6","name":"livingroom","internet":False}
              ]
              "shared_secret": "SHARED_SECRET_1"
            },
            ...
          ]
        }

        Args:
            file: json file to load
        """
        try:
            with open(infile) as json_file:
                users = json.load(json_file)
                loaded = 0
                if 'Users' in users:
                    users = users['Users']
                for user in users:
                    if 'email' in user and 'shared_secret' in user:
                        if 'id' not in user:
                            user['id'] = self.generate_user_id(user['email'])
                        if 'password' in user:
                            user['mcf'] = preset_password(user['email'], user['password'])
                            del user['password']
                        response = self.put_item(user)
                        if response:
                            loaded = loaded + 1
                        else:
                            print('Load of user failed: ' + user['id'])
                return {'message': 'Loaded ' + str(loaded) + ' items from ' + infile}
        except (IOError, ValueError) as err:
            return {'error': err.message}

class SES(object):
    """ Utility class for access to AWS SES.
    """
    def __init__(self, email_address):
        """ Constructor, get AWS resource
        Args:
            email_address: senders email address
        """
        self.ses = boto3.client('ses')
        self.email_address = email_address

    def send_email(self, to_list, subject, html, text):
        """ Send an email
        Args:
            to: recipient or list of recipients
            subject: subject line
            html: HTML formatted message
            text: Plain text message
        """
        if not isinstance(to_list, list):
            to_list = [to_list]
        response = self.ses.send_email(
            Destination={
                'BccAddresses': [],
                'CcAddresses': [],
                'ToAddresses': to_list,
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': 'UTF-8',
                        'Data': html,
                    },
                    'Text': {
                        'Charset': 'UTF-8',
                        'Data': text,
                    },
                },
                'Subject': {
                    'Charset': 'UTF-8',
                    'Data': subject,
                },
            },
            Source=self.email_address,
        )
        print(response)


class SNS(object):
    """ Utility class for access to AWS SNS.
    """
    def __init__(self, topic_name):
        """ Constructor, get AWS resource
        Args:
            topic_name: name of the topic
        """
        self.sns = boto3.resource('sns')
        self.topic = None
        if topic_name is not None:
            try:
                self.topic = self.sns.create_topic(Name=topic_name)
            except ClientError as err:
                print (err.message)

    def publish(self, message):
        """ Publish a message to our topic.
        Args:
            message: text or json
        """
        if self.topic is not None:
            resp = self.topic.publish(Message=message)
            return resp['MessageId']

    def subscribe(self, protocol, end_point):
        """ Subscribe to our topic.
        Args:
            protocol:  http,https, email, email-json, sms, sqs, application
            end_point: url, email, phone, arn
        """
        if self.topic is not None:
            response = self.topic.subscribe(Protocol=protocol, Endpoint=end_point)
            return response

    def send_sms(self, number, message):
        """ Send an SMS message to the phone number
        Args:
            number: phone number (e.g. '+17702233322')
            message: text
        """
        try:
            response = self.sns.publish(PhoneNumber=number, Message=message)
            return response
        except ClientError as err:
            return {'error': err.message}

class Route53(object):
    """ Utility class for access to AWS Route53.
    """
    def __init__(self, aws_region, domain, user_id=None):
        """ Constructor, get AWS Route53 client
        Args:
            aws region
            domain
            user id for subdomain
        """
        self.route53 = boto3.client('route53', region_name=aws_region)
        self.user_id = user_id
        if user_id:
            self.hostname = user_id + '.' + domain + '.'
        else:
            self.hostname = domain + '.'

    def get_dns_records(self, route_53_zone_id):
        """ Get DNS record for specified name from Route53
        Args:
            route_53_zone_id: defines the id for the DNS zone
        """
        try:
            current_route53_record_set = self.route53.list_resource_record_sets(
                HostedZoneId=route_53_zone_id,
                StartRecordName=self.hostname,
                StartRecordType=CONFIG_DNS_TYPE,
                MaxItems='4'
            )
        except ClientError as err:
            return {'error': err.message}

        # boto3 returns a dictionary with a nested list of dictionaries
        # see: http://boto3.readthedocs.org/en/latest/reference/services/
        # route53.html#Route53.Client.list_resource_record_sets
        # Parse the dict to find the current IP for the hostname, if it exists.
        # If it doesn't exist, the function returns False.
        for record in current_route53_record_set['ResourceRecordSets']:
            if record['Name'] == self.hostname:
                # If there's a single record, pass it along.
                if len(record['ResourceRecords']) == 1:
                    for sub_record in record['ResourceRecords']:
                        currentroute53_ip = sub_record['Value']
                        return {'message': currentroute53_ip}
                # Error out if there is more than one value for the record set.
                elif len(record['ResourceRecords']) > 1:
                    return_message = 'You should only have a single value for'\
                    ' your dynamic record.  You currently have more than one.'
                    return {'error': return_message}

    def set_dns_records(self, route_53_zone_id, public_ip):
        """ Set DNS record for specified name using Route53
        Args:
            route_53_zone_id: defines the id for the DNS zone
            public_ip: defines the current public ip of the client
        """
        # Set the DNS record to the current IP.
        try:
            self.route53.change_resource_record_sets(
                HostedZoneId=route_53_zone_id,
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'UPSERT',
                            'ResourceRecordSet': {
                                'Name': self.hostname,
                                'Type': CONFIG_DNS_TYPE,
                                'TTL': CONFIG_DNS_TTL,
                                'ResourceRecords': [
                                    {
                                        'Value': public_ip
                                    }
                                ]
                            }
                        }
                    ]
                }
            )
        except ClientError as err:
            return {'error': err.message}

        return {'message': 'DNS record updated'}

    def delete_dns_records(self, public_ip, route_53_zone_id):
        """ Delete DNS record for specified name using Route53
        Args:
            public_ip: current public ip of the client
            route_53_zone_id: id for the DNS zone
        """
        # Remove the DNS record from Route 53
        try:
            self.route53.change_resource_record_sets(
                HostedZoneId=route_53_zone_id,
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'DELETE',
                            'ResourceRecordSet': {
                                'Name': self.hostname,
                                'Type': CONFIG_DNS_TYPE,
                                'TTL': CONFIG_DNS_TTL,
                                'ResourceRecords': [
                                    {
                                        'Value': public_ip
                                    }
                                ]
                            }
                        }
                    ]
                }
            )
        except ClientError as err:
            return {'error': err.message}
        return {'message': 'DNS record deleted'}

    def update_dns_records(self, public_ip, route_53_zone_id):
        """ Check if existing DNS record matches client IP and update if needed
        Args:
            public_ip: current public ip of the client
            route_53_zone_id: id for the DNS zone
        """
        route53_get_response = self.get_dns_records(route_53_zone_id)
        # If no records were found, route53_client returns None
        # Set route53_ip and stop evaluating the null response.
        if not route53_get_response:
            route53_ip = '0'
        # Pass the error message up to the main function.
        elif 'error' in route53_get_response:
            return route53_get_response
        else:
            route53_ip = route53_get_response['message']
        # If the client's current IP matches the current DNS record
        # in Route 53 there is nothing left to do.
        if route53_ip == public_ip:
            return {'message': 'IP address matches current Route53 DNS record'}
        # If the IP addresses do not match or if the record does not exist,
        # Tell Route 53 to set the DNS record.
        else:
            return self.set_dns_records(route_53_zone_id, public_ip)

class S3(object):
    """ Base class for access to AWS S3.
    """
    def __init__(self):
        """ Constructor, get AWS resource.
        """
        self.sss = boto3.resource('s3')

    def exists(self, bucket):
        """ Checks to see if the bucket exists
        Returns:
            True if bucket exists
        """
        exists = True
        try:
            self.sss.meta.client.head_bucket(Bucket=bucket)
        except ClientError as err:
            # If a client error is thrown, then check that it was a 404 error.
            # If it was a 404 error, then the bucket does not exist.
            error_code = int(err.response['Error']['Code'])
            if error_code == 404:
                exists = False
        return exists

    def create_bucket(self, bucket, location='us-west-2'):
        """ Create a new bucket.
        Args:
            bucket: name of the bucket
            location: region to create bucket
                ACL='authenticated-read',
        """
        if not self.exists(bucket):
            try:
                self.sss.create_bucket(
                    Bucket=bucket,
                    CreateBucketConfiguration={'LocationConstraint': location},
                )
                return dict(status='ok')
            except ClientError as err:
                return dict(error=err.message)
        else:
            return dict(error='Bucket exists: ' + bucket)

    def delete_bucket(self, bucket):
        """ Delete a bucket.
        Args:
            bucket: name of the bucket
        """
        if self.exists(bucket):
            try:
                for key in self.sss.Bucket(bucket).objects.all():
                    key.delete()
                self.sss.Bucket(bucket).delete()
                return dict(status='ok')
            except ClientError as err:
                return dict(error=err.message)

    def upload_data(self, data, bucket, key, metadata=None):
        """ Upload a data to bucket.
        Args:
            data: textual content
            bucket: name of the bucket
            key: name of the file in S3
            metadata: dict of metadata to store with the object in S3
        """
        if self.exists(bucket):
            try:
                if metadata:
                    self.sss.Object(bucket, key).put(Body=data, Metadata=metadata)
                else:
                    self.sss.Object(bucket, key).put(Body=data)
                return dict(status='ok')
            except ClientError as err:
                return dict(error=err.message)
        else:
            return dict(error='Bucket does not exist')

    def upload_file(self, filename, bucket, key, metadata=None):
        """ Upload a file to bucket.
        Args:
            filename: local filename
            bucket: name of the bucket
            key: name of the file in S3
            metadata: dict of metadata to store with the object in S3
        """
        if self.exists(bucket):
            try:
                if metadata:
                    self.sss.Object(bucket, key).put(Body=open(filename, 'rb'), Metadata=metadata)
                else:
                    self.sss.Object(bucket, key).put(Body=open(filename, 'rb'))
                return dict(status='ok')
            except ClientError as err:
                return dict(error=err.message)
        else:
            return dict(error='Bucket does not exist')

    def download_data(self, bucket, key):
        """ Download a file from bucket and return contents in memory
        Args:
            bucket: name of the bucket
            key: name of the file in S3
        Return:
            tuple (status as dictionary, file contents or None for error)
        """
        if self.exists(bucket):
            try:
                response = self.sss.Object(bucket, key).get()
                return dict(status='ok'), response['Body'].read(), response.get('Metadata')
            except ClientError as err:
                return dict(error=err.message), None
        else:
            return dict(error='Bucket does not exist'), None

    def download_file(self, filename, bucket, key):
        """ Download a file from bucket and store locally
        Args:
            filename: local filename
            bucket: name of the bucket
            key: name of the file in S3
        """
        if self.exists(bucket):
            try:
                self.sss.Object(bucket, key).download_file(filename)
                return dict(status='ok')
            except ClientError as err:
                return dict(error=err.message)
        else:
            return dict(error='Bucket does not exist')

    def add_notification(self, bucket, arn):
        """ Add notification to bucket.
        Args:
            bucket: name of the bucket
            arn: SNS topic, SQS queue or Lambda function arn
            arn:aws:sqs
        """
        bucket_notification = self.sss.BucketNotification(bucket)
        fields = arn.split(':')
        if fields[2] == 'sqs':
            bucket_notification.put(
                NotificationConfiguration={
                    'QueueConfigurations': [
                        {
                            'QueueArn': arn,
                            'Events': ['s3:ObjectCreated:*', 's3:ObjectRemoved:*'],
                        }
                    ]
                }
            )
        elif fields[2] == 'sns':
            bucket_notification.put(
                NotificationConfiguration={
                    'TopicConfigurations': [
                        {
                            'TopicArn': arn,
                            'Events': ['s3:ObjectCreated:*', 's3:ObjectRemoved:*']
                        }
                    ],
                }
            )
        else:
            return dict(error='Unsupported notification: ' + arn)
        bucket_notification.load()

    def disable_notification(self, bucket):
        """ Disables all notifications on a bucket.
        Args:
            bucket: name of the bucket
        """
        bucket_notification = self.sss.BucketNotification(bucket)
        bucket_notification.put(NotificationConfiguration={})
        bucket_notification.load()

    def list_buckets(self):
        """ List all of the buckets for current user.
        """
        objects = []
        for bucket in self.sss.buckets.all():
            objects.append(bucket.name)
        return objects

    def get_matching_s3_objects(self, bucket, prefix, suffix, after, before):
        """ Generate objects in a bucket matching the requested criteria
        Args:
            bucket: name of the bucket
            after: return only entries modified on or after specified timestamp
            before: return only entries modified on or before specified timestamp
            prefix: return only entries with specifed prefix
            suffix: return only entries with specifed suffix
        """
        if not self.exists(bucket):
            print('Bucket does not exist')
            return

        s3client = boto3.client('s3')
        kwargs = {'Bucket': bucket}

        # If the prefix is a single string (not a tuple of strings), we can
        # do the filtering directly in the S3 API.
        if isinstance(prefix, str):
            kwargs['Prefix'] = prefix

        while True:

            # The S3 API response is a large blob of metadata.
            # 'Contents' contains information about the listed objects.
            try:
                resp = s3client.list_objects_v2(**kwargs)
            except ClientError as err:
                print(err.message)
                return

            try:
                contents = resp['Contents']
            except KeyError:
                return

            for obj in contents:
                key = obj['Key']
                last_modified = obj['LastModified']
                #size = obj['Size']
                if key.startswith(prefix) and key.endswith(suffix):
                    if after and last_modified < after:
                        continue
                    elif before and last_modified > before:
                        continue
                    else:
                        yield obj

            # The S3 API is paginated, returning up to 1000 keys at a time.
            # Pass the continuation token into the next response, until we
            # reach the final page (when this field is missing).
            try:
                kwargs['ContinuationToken'] = resp['NextContinuationToken']
            except KeyError:
                break


    def list_objects(self, bucket, **kwargs):
        """ List all of the objects in a bucket matching the requested criteria
        Args:
            bucket: name of the bucket
            kwargs {
                count: limit on number of entries to return
                after: return only entries modified on or after specified timestamp
                before: return only entries modified on or before specified timestamp
                prefix: return only entries with specifed prefix
                suffix: return only entries with specifed suffix
            }
        """
        after = kwargs.pop('after', None)
        if after:
            after = datetime.fromtimestamp(float(after), tz=pytz.utc)
        before = kwargs.pop('before', None)
        if before:
            before = datetime.fromtimestamp(float(before), tz=pytz.utc)
        prefix = kwargs.pop('prefix', '')
        suffix = kwargs.pop('suffix', '')

        for obj in self.get_matching_s3_objects(bucket, prefix, suffix, after, before):
            yield obj['Key']

    def get_metadata(self, bucket, key):
        """ Get the file metadata
        Args:
            bucket: name of the bucket
            key: name of the file in S3
        Return:
            metadata as dict or None
        """
        if self.exists(bucket):
            try:
                s3client = boto3.client('s3')
                response = s3client.head_object(Bucket=bucket, Key=key)
                return dict(status='ok'), response.get('Metadata')
            except ClientError as err:
                return dict(error=err.message), None
        else:
            return dict(error='Bucket does not exist'), None

    def remove_object(self, bucket, key):
        """ Remove the specified file from the bucket
        Args:
            bucket: name of the bucket
            key: name of the file in S3
        """
        if self.exists(bucket):
            try:
                self.sss.Object(bucket, key).delete()
                return dict(status='ok')
            except ClientError as err:
                return dict(error=err.message)
        else:
            return dict(error='Bucket does not exist')


def main():
    """ Unit tests
    """
    #ses = SES('alan@cyberfrosty.com')
    #html = '<a class="ulink" href="http://cyberfrosty.com/recipes" target="_blank">Recipes</a>.'
    #ses.send_email(['frosty.alan@gmail.com'], 'Howdy', html, 'Check out my recipes')
    #s3 = S3()
    #for key in s3.list_objects('snowyrangesolutions.com', **{'prefix':'static/img/', 'suffix':'.jpg'}):
    #    print(key)

if __name__ == '__main__':
    main()
