import boto3
from botocore.exceptions import ClientError
from config import Config

class DynamoDB:
    def __init__(self):
        self.dynamodb = boto3.resource(
            'dynamodb',
        )

    def create_tables(self):
        """Create all required tables if they don't exist"""
        tables = {
            Config.USERS_TABLE: {
                'KeySchema': [{'AttributeName': 'email', 'KeyType': 'HASH'}],
                'AttributeDefinitions': [{'AttributeName': 'email', 'AttributeType': 'S'}],
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            },
            Config.PRODUCTS_TABLE: {
                'KeySchema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
                'AttributeDefinitions': [{'AttributeName': 'id', 'AttributeType': 'S'}],
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            },
            Config.ORDERS_TABLE: {
                'KeySchema': [
                    {'AttributeName': 'id', 'KeyType': 'HASH'},
                    {'AttributeName': 'user_email', 'KeyType': 'RANGE'}
                ],
                'AttributeDefinitions': [
                    {'AttributeName': 'id', 'AttributeType': 'S'},
                    {'AttributeName': 'user_email', 'AttributeType': 'S'}
                ],
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            },
            Config.CART_TABLE: {
                'KeySchema': [
                    {'AttributeName': 'user_email', 'KeyType': 'HASH'},
                    {'AttributeName': 'product_id', 'KeyType': 'RANGE'}
                ],
                'AttributeDefinitions': [
                    {'AttributeName': 'user_email', 'AttributeType': 'S'},
                    {'AttributeName': 'product_id', 'AttributeType': 'S'}
                ],
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            },
            Config.PRESCRIPTIONS_TABLE: {
                'KeySchema': [
                    {'AttributeName': 'id', 'KeyType': 'HASH'},
                    {'AttributeName': 'user_email', 'KeyType': 'RANGE'}
                ],
                'AttributeDefinitions': [
                    {'AttributeName': 'id', 'AttributeType': 'S'},
                    {'AttributeName': 'user_email', 'AttributeType': 'S'}
                ],
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            }
        }

        for table_name, table_config in tables.items():
            try:
                print(f"Creating table {table_name}...")
                self.dynamodb.create_table(
                    TableName=table_name,
                    **table_config
                )
                print(f"Waiting for table {table_name} to be created...")
                waiter = self.dynamodb.meta.client.get_waiter('table_exists')
                waiter.wait(TableName=table_name)
                print(f"Table {table_name} created successfully!")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceInUseException':
                    print(f"Table {table_name} already exists")
                else:
                    print(f"Error creating table {table_name}: {str(e)}")
                    raise

    def get_table(self, table_name):
        """Get a table reference"""
        return self.dynamodb.Table(table_name)

    def put_item(self, table_name, item):
        """Add an item to a table"""
        try:
            print(f"Putting item in table {table_name}:", item)  # Debug print
            table = self.get_table(table_name)
            # Don't convert the item to DynamoDB format, send it as is
            response = table.put_item(Item=item)
            print("Put item response:", response)  # Debug print
            return response
        except Exception as e:
            print(f"Error putting item in table {table_name}:", str(e))  # Debug print
            raise

    def get_item(self, table_name, key):
        """Get an item from a table"""
        try:
            print(f"Getting item from {table_name} with key:", key)  # Debug print
            table = self.get_table(table_name)
            response = table.get_item(Key=key)
            item = response.get('Item')
            print(f"Got item from {table_name}:", item)  # Debug print
            return item
        except Exception as e:
            print(f"Error getting item from table {table_name}:", str(e))  # Debug print
            raise

    def query(self, table_name, KeyConditionExpression=None, ExpressionAttributeValues=None, **kwargs):
        """Query items from a table"""
        try:
            print(f"Querying table {table_name}")  # Debug print
            table = self.get_table(table_name)
            
            query_params = {}
            if KeyConditionExpression:
                query_params['KeyConditionExpression'] = KeyConditionExpression
            if ExpressionAttributeValues:
                query_params['ExpressionAttributeValues'] = ExpressionAttributeValues
            query_params.update(kwargs)
            
            response = table.query(**query_params)
            items = response.get('Items', [])
            
            # Handle pagination if there are more items
            while 'LastEvaluatedKey' in response:
                query_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
                response = table.query(**query_params)
                items.extend(response.get('Items', []))
            
            print(f"Found {len(items)} items in query")  # Debug print
            return items
            
        except Exception as e:
            print(f"Error querying table {table_name}:", str(e))  # Debug print
            raise

    def scan(self, table_name):
        """Scan a table and return all items."""
        try:
            table = self.get_table(table_name)
            response = table.scan()
            items = []
            
            if 'Items' in response:
                items.extend(response['Items'])
                
                # Handle pagination
                while 'LastEvaluatedKey' in response:
                    response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                    if 'Items' in response:
                        items.extend(response['Items'])
                        
            return items
        except Exception as e:
            print(f"Error scanning table {table_name}: {str(e)}")
            return []

    def _convert_to_dynamodb_format(self, item):
        """Convert a regular dictionary to DynamoDB format"""
        dynamodb_item = {}
        for key, value in item.items():
            if isinstance(value, str):
                dynamodb_item[key] = {'S': value}
            elif isinstance(value, (int, float)):
                dynamodb_item[key] = {'N': str(value)}
            elif isinstance(value, dict):
                dynamodb_item[key] = {'M': self._convert_to_dynamodb_format(value)}
            elif isinstance(value, list):
                dynamodb_item[key] = {'L': [self._convert_to_dynamodb_format(v) if isinstance(v, dict) else {'S': str(v)} for v in value]}
            elif value is None:
                dynamodb_item[key] = {'NULL': True}
            else:
                dynamodb_item[key] = {'S': str(value)}
        return dynamodb_item

    def _convert_from_dynamodb_format(self, item):
        """Convert from DynamoDB format to regular dictionary"""
        python_item = {}
        for key, value in item.items():
            if 'S' in value:
                python_item[key] = value['S']
            elif 'N' in value:
                python_item[key] = float(value['N']) if '.' in value['N'] else int(value['N'])
            elif 'M' in value:
                python_item[key] = self._convert_from_dynamodb_format(value['M'])
            elif 'L' in value:
                python_item[key] = [self._convert_from_dynamodb_format(v) if 'M' in v else v['S'] for v in value['L']]
            elif 'NULL' in value:
                python_item[key] = None
            else:
                python_item[key] = str(value)
        return python_item 