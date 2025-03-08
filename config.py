import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # AWS Configuration
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    AWS_REGION = os.getenv('AWS_REGION', 'ap-south-1')
    
    # S3 Configuration
    S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME', 'medimart-prescriptions')
    
    # App Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    SALT_ROUNDS = int(os.getenv('SALT_ROUNDS', '12'))
    
    # Admin Configuration
    ADMIN_EMAILS = os.getenv('ADMIN_EMAILS', 'admin@medimart.com').split(',')
    
    # DynamoDB Tables
    USERS_TABLE = os.getenv('USERS_TABLE', 'MediMart_Users')
    PRODUCTS_TABLE = os.getenv('PRODUCTS_TABLE', 'MediMart_Products')
    ORDERS_TABLE = os.getenv('ORDERS_TABLE', 'MediMart_Orders')
    CART_TABLE = os.getenv('CART_TABLE', 'MediMart_Cart')
    PRESCRIPTIONS_TABLE = os.getenv('PRESCRIPTIONS_TABLE', 'MediMart_Prescriptions') 