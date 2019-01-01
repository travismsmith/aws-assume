import argparse
import configparser
import urllib
from os.path import expanduser

import boto3
import requests

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument('-v', '--verbose', action='store_true')
group.add_argument('-q', '--quiet', action='store_true')
parser.add_argument('-a', '--role', default='AssumeRole-Administrator')
parser.add_argument('-c', '--config', default=(expanduser("~") + '/.aws/'),
                    help='location of configuration files (Default: ~/.aws/')
parser.add_argument('-d', '--default', default='root',
                    help='Select a profile for initial login to STS')
parser.add_argument('-p', '--profile', default='default',
                    help='profile to save credentials (Default: default)')
parser.add_argument('-r', '--region', default='us-east-1',
                    help='STS region to connct to (Default: us-east-1')
parser.add_argument('-t', '--timeout', default='3600', type=int,
                    choices=range(900, 3601), metavar="[900-3600]",
                    help='credential/url timeout in seconds (Default: 3600)')
args = parser.parse_args()


def get_account_role(path, role_name):
    with open(path + 'accounts') as f:
        account_list = f.read().splitlines()
    for i in range(len(account_list)):
        print('  ' + str(i) + ": " + account_list[i])
    selection = input("Select account: ")
    role_arn = 'arn:aws:iam::{}:role/{}'.format(
        account_list[int(selection)],
        role_name
    )
    return role_arn


def get_credentials(client, timeout, role_arn, user_arn, token):
    response = client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=user_arn.split("/")[1],
        DurationSeconds=timeout,
        SerialNumber=user_arn.replace(':user/', ':mfa/'),
        TokenCode=token
    )
    creds = response['Credentials']
    return creds


def set_config(profile_name, path, creds):
    config = configparser.RawConfigParser()
    config.read(path+'credentials')
    config[profile_name] = {}
    config[profile_name]['aws_access_key_id'] = creds['AccessKeyId']
    config[profile_name]['aws_secret_access_key'] = creds['SecretAccessKey']
    config[profile_name]['aws_session_token'] = creds['SessionToken']
    with open(path + 'credentials', 'w') as configfile:
        config.write(configfile)


def get_url(credentials):
    federation_url = 'https://signin.aws.amazon.com/federation'
    destination_url = 'https://console.aws.amazon.com/'
    creds = '{{"sessionId":"{}","sessionKey":"{}","sessionToken":"{}"}}'

    # Generate a console URL
    # https://aws.amazon.com/blogs/security/how-to-enable-cross-account-access-to-the-aws-management-console/
    json_credentials = urllib.parse.quote_plus(
        creds.format(
            credentials['AccessKeyId'],
            credentials['SecretAccessKey'],
            credentials['SessionToken']
        )
    )
    request_url = '{}?Action=getSigninToken&Session={}'.format(
        federation_url,
        json_credentials
    )
    r = requests.get(request_url)

    return '{}?Action=login&Issuer=&Destination={}&SigninToken={}'.format(
        federation_url,
        urllib.parse.quote_plus(destination_url),
        r.json()['SigninToken']
    )


session = boto3.session.Session(
    profile_name=args.default,
    region_name=args.region
)
sts = session.client('sts')
user = sts.get_caller_identity()['Arn']
role = get_account_role(args.config, args.role)
token = input("MFA Token: ")
creds = get_credentials(sts, args.timeout, role, user, token)
set_config(args.profile, args.config, creds)

if not args.quiet:
    print('\nSaved to profile: ' + args.profile)
    if args.verbose:
        print('Role Assumed: ' + role)
        print('Access Key: ' + creds['AccessKeyId'])
        print('Expiration Date: ' + creds['Expiration'])
    print('\nConsole URL: ' + get_url(creds))
