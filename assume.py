import argparse
import configparser
import urllib
from os.path import expanduser

import boto3
import requests


# parse arguments
def parse_all_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-v', '--verbose',
        action='store_true'
    )
    group.add_argument(
        '-q', '--quiet',
        action='store_true'
    )
    parser.add_argument(
        '-a', '--assume',
        default='assume'
    )
    parser.add_argument(
        '-c', '--config',
        default=(expanduser("~") + '/.aws/credentials'),
        help='location of configuration files (Default: ~/.aws/credentials'
    )
    parser.add_argument(
        '-d', '--dest',
        default='default',
        help='profile to save credentials (Default: default)'
    )
    parser.add_argument(
        '-l', '--login',
        default='root',
        help='Select a profile for initial login to STS'
    )
    parser.add_argument(
        '-r', '--region',
        default='us-east-1',
        help='STS region to connct to (Default: us-east-1'
    )
    parser.add_argument(
        '-t', '--timeout',
        default='3600', type=int,
        choices=range(900, 3601), metavar="[900-3600]",
        help='credential/url timeout in seconds (Default: 3600)'
    )
    parser.add_argument('token')
    return parser.parse_args()


# verify that required roles exist in config file
def verify_roles(config, login_profile, assume_profile):
    if config.has_section(login_profile):
        if config.has_section(assume_profile):
            if config.has_option(assume_profile, 'role_arn'):
                return True
            else:
                raise NameError('profile missing role_arn: ' + assume_profile)
        else:
            raise NameError('profile missing: ' + assume_profile)
    else:
        raise NameError('profile missing: ' + login_profile)


# use sts to retrieve temporary credentials
def get_credentials(login_profile, region, timeout, role_arn, token):
    sts = boto3.session.Session(
        profile_name=login_profile,
        region_name=region
    ).client('sts')
    user_arn = sts.get_caller_identity()['Arn']
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=user_arn.split("/")[1],
        DurationSeconds=timeout,
        SerialNumber=user_arn.replace(':user/', ':mfa/'),
        TokenCode=token
    )
    return response['Credentials']


# get the temporary console url
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


args = parse_all_args()
c_file = configparser.ConfigParser()
c_file.read(args.config)
if verify_roles(c_file, args.login, args.assume):
    role = c_file.get(args.assume, 'role_arn')
    creds = get_credentials(args.login, args.region, args.timeout, role, args.token)

    c_file[args.dest] = {}
    c_file[args.dest]['aws_access_key_id'] = creds['AccessKeyId']
    c_file[args.dest]['aws_secret_access_key'] = creds['SecretAccessKey']
    c_file[args.dest]['aws_session_token'] = creds['SessionToken']
    with open(args.config, 'w') as configfile:
        c_file.write(configfile)
    url = get_url(creds)

    if not args.quiet:
        print('Saved to profile: ' + args.dest)
        if args.verbose:
            print('Role Assumed: ' + role)
            print('Access Key: ' + creds['AccessKeyId'])
            print('Expiration Date: ' + str(creds['Expiration']))
        print('Console URL: ' + url)
