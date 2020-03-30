import json
import boto3
import botocore
import uuid
import bcrypt
from boto3.dynamodb.conditions import Attr
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

def testing(event, context):
    body = {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "input": event
    }

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps(body)
    }

    return response

def get_users(event, context):
    
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("Users")

    all_items = table.scan()

    response = {
        "statusCode": 200,
        #"body": json.dumps(list(all_items['Items'])),
        "body": json.dumps({
            'message': 'hello'
        }),
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        }
    }

    return response


def register(event, context):

    payload = json.loads(event['body'])
    user_id = str(uuid.uuid4())
    username = payload['username']
    password = payload['password']
    email = payload['email']
    first_name = payload['first_name']
    last_name = payload['last_name']

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("Users")

    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    message = "Sucessful"

    try:
        table_response = table.put_item(
            Item = {
                'user_id': user_id,
                'username': username,
                'password': hashedPassword,
                'email': email,
                'first_name': first_name,
                'last_name': last_name
            },
            ConditionExpression = 'attribute_not_exists(username) AND attribute_not_exists(email)'
        )
    except botocore.exceptions.ClientError as e:
       if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
        message = 'ERROR: Username or Email was not unique'

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            "status": message
        })
    }

    return response


def login(event, context):

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("Users")

    #payload = json.loads(event['body'])
    username = 'chris'
    password = bcrypt.hashpw(('password').encode('utf-8'), bcrypt.gensalt())

    try:
        result = table.scan(
            FilterExpression=Key('username').eq(username)
        )
    except ClientError as e:
        result = e.response['Error']['Message']
    
    print(result)

    response = {
        "statusCode": 200,
        "body": json.dumps({
            'message': 'hello'
        }),
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        }
    }

    return response
