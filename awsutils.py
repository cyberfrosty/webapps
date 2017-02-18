import boto3

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



