#!/usr/bin python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, Inc. All rights reserved.

Classes to access AWS resources
"""

import boto3
from botocore.exceptions import ClientError


class DynamoDB(object):
    """ Abstract base class for access to AWS DynamoDB.
    """
    def __init__(self, table_name):
        """ Constructor, get AWS resource and table.
        Args:
            table_name: name of the database table
        """
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(table_name)

    def create_table(self, table_name, primary_key):
        """ Create a table.
        Args:
            table_name: name of the table
            primary_key: table primary key, e.g. 'username'
        """
        active = False
        try:
            active = self.table.table_status == 'ACTIVE'
        except ClientError:
            print 'Creating table : ' + table_name

        if active:
            print 'Table exists: ' + table_name
        else:
            self.table = self.dynamodb.create_table(
                TableName=table_name,
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
            return True
        except ClientError as err:
            print err
            return False

    def get_item(self, key, value):
        """ Get an item from the table.
        Args:
            key: table primary key, e.g. 'username'
            value: primary key value to match
        """
        try:
            response = self.table.get_item(Key={key : value})
            return response['Item']
        except ClientError:
            return None
        except KeyError:
            #print 'Item not found for ' + key + ': ' + value
            return None

    def put_item(self, key, value):
        """ Create or replace an item in the table.
        Args:
            key: table primary key, e.g. 'username'
            value: json item data
        """
        try:
            response = self.table.put_item(Item=value)
            return response
        except ClientError as err:
            print key + ':'
            print err
            return None


class SNS(object):
    """ Abstract base class for access to AWS SNS.
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
                print err

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
            print err
