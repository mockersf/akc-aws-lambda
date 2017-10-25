import json
import os
import boto3

akc_accounts_url = 'https://accounts.artik.cloud'
akc_api_url = 'https://api.artik.cloud/v1.1'

def auth_redirect_akc(event, context):
    akc_client_id = os.environ['akc_client_id']

    return {
        'statusCode': 303,
        'headers': {
            'location': '{}/authorize?prompt=login&response_type=code&client_id={}'.format(akc_accounts_url, akc_client_id)
        }
    }

def auth_code(event, context):
    topic = os.environ['topic']

    code = event['queryStringParameters']['code']
    boto3.client('sns').publish(
        TopicArn=topic,
        Message=code
    )
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json'
        },
        'body': json.dumps({'status': 'ok'})
    }

def token_exchange(event, context):
    import requests
    from requests.auth import HTTPBasicAuth

    akc_client_id = os.environ['akc_client_id']
    akc_client_secret = os.environ['akc_client_secret']
    topic = os.environ['topic']

    for record in event['Records']:
        code = record['Sns']['Message']
        tokens = requests.post('{}/token'.format(akc_accounts_url), auth=HTTPBasicAuth(akc_client_id, akc_client_secret),
                                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                data='grant_type=authorization_code&code={}'.format(code))
        boto3.client('sns').publish(
            TopicArn=topic,
            Message=tokens.text
        )

def create_device(event, context):
    import requests

    akc_dtid = os.environ['akc_dtid']
    akc_device_name = os.environ['device_name']
    topic = os.environ['topic']

    for record in event['Records']:
        message = json.loads(record['Sns']['Message'])
        access_token = message['access_token']
        uid = json.loads(requests.get('{}/users/self'.format(akc_api_url), headers={'Authorization': 'bearer {}'.format(access_token)}).text)['data']['id']
        did = json.loads(requests.post('{}/devices'.format(akc_api_url), data=json.dumps({'dtid': akc_dtid, 'name': akc_device_name, 'uid': uid}),
                        headers={'Authorization': 'bearer {}'.format(access_token), 'Content-Type': 'application/json'}).text)['data']['id']
        token = json.loads(requests.put('{}/devices/{}/tokens'.format(akc_api_url, did), headers={'Authorization': 'bearer {}'.format(access_token)}).text)['data']['accessToken']
        boto3.client('sns').publish(
            TopicArn=topic,
            Message=json.dumps({'did': did, 'token': token})
        )

def save_device(event, context):
    table = os.environ['table']

    for record in event['Records']:
        message = json.loads(record['Sns']['Message'])
        boto3.client('dynamodb').put_item(
            TableName=table,
            Item={
                'id': {
                    'S': message['did']
                },
                'token': {
                    'S': message['token']
                }
            }
        )
    
def subscribe(event, context):
    import requests

    akc_client_id = os.environ['akc_client_id']

    for record in event['Records']:
        message = json.loads(record['Sns']['Message'])
        subscription = json.loads(requests.post('{}/subscriptions'.format(akc_api_url),
                data=json.dumps({'ddid': message['did'], 'messageType': 'action', 'subscriptionType': 'httpCallback',
                                 'aid': akc_client_id, 'callbackUrl': 'callbackurl'}),
                headers={'Authorization': 'bearer {}'.format(message['token']), 'Content-Type': 'application/json'}).text)
