#!/usr/bin python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost. All rights reserved.

AWS Utility classes for DynamoDB, SNS and Route 53
"""

from __future__ import print_function

import hashlib
import hmac
import json
import boto3
from botocore.exceptions import ClientError

CONFIG_DNS_TTL = 60 # TTL (Time To Live) in seconds tells DNS servers how long to cache
CONFIG_DNS_TYPE = 'A' # A record

def load_config(config_file):
    """ Load the config.json file
    Args:
        config file path
    Returns:
        dict for success or None for failure
    """
    config = None
    try:
        with open(config_file) as json_file:
            config = json.load(json_file)
    except (IOError, ValueError) as err:
        print('Load of config file failed:', err.message)

    if isinstance(config.get('hmac_secret'), unicode):
        config['hmac_secret'] = config.get('hmac_secret').encode('ascii', 'ignore')
    if isinstance(config.get('encryption_secret'), unicode):
        config['encryption_secret'] = config.get('encryption_secret').encode('ascii', 'ignore')
    return config

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

    def hash_id(self, user):
        """ Use an HMAC to generate a user id to keep DB more secure. This prevents someone from
            looking up users by name or even hash of user name, without using the official API.
        Args:
            user name
        Returns:
            hex id
        """
        return hmac.new(self.config.get('hmac_secret'), user, digestmod=hashlib.sha224).hexdigest()

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
            return {'error', err.message}

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
                    if 'user' in user and 'shared_secret' in user:
                        if 'id' not in user:
                            user['id'] = self.hash_id(user['user'])
                        response = self.put_item(user)
                        if response:
                            loaded = loaded + 1
                        else:
                            print('Load of user failed: ' + user['id'])
                return {'message': 'Loaded ' + str(loaded) + ' users'}
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


def main():
    """ Unit tests
    """
    ses = SES('alan@cyberfrosty.com')
    html = '<a class="ulink" href="http://cyberfrosty.com/recipes" target="_blank">Recipes</a>.'
    ses.send_email(['frosty.alan@gmail.com'], 'Howdy', html, 'Check out my recipes')

if __name__ == '__main__':
    main()
