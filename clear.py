import boto3
from config import Config
import time

def delete_all_tables():
    try:
        # Initialize DynamoDB client
        dynamodb = boto3.client('dynamodb',
            aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY,
            region_name=Config.AWS_REGION
        )

        # List of tables to delete
        tables = [
            Config.USERS_TABLE,
            Config.PRODUCTS_TABLE,
            Config.ORDERS_TABLE,
            Config.CART_TABLE,
            Config.PRESCRIPTIONS_TABLE
        ]

        # Delete each table
        for table_name in tables:
            try:
                print(f"Attempting to delete table: {table_name}")
                dynamodb.delete_table(TableName=table_name)
                print(f"Successfully initiated deletion of table: {table_name}")
                
                # Wait for table to be deleted
                print(f"Waiting for table {table_name} to be deleted...")
                waiter = dynamodb.get_waiter('table_not_exists')
                waiter.wait(
                    TableName=table_name,
                    WaiterConfig={'Delay': 5, 'MaxAttempts': 20}
                )
                print(f"Table {table_name} has been deleted")
                
            except dynamodb.exceptions.ResourceNotFoundException:
                print(f"Table {table_name} does not exist")
            except Exception as e:
                print(f"Error deleting table {table_name}: {str(e)}")

        print("\nAll tables have been processed")

    except Exception as e:
        print(f"Error initializing DynamoDB client: {str(e)}")

if __name__ == "__main__":
    print("Warning: This will delete all MediMart tables from DynamoDB!")
    print("You have 5 seconds to cancel (Ctrl+C to cancel)...")
    try:
        time.sleep(5)
        delete_all_tables()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"An error occurred: {str(e)}") 