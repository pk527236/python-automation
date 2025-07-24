import boto3
from datetime import datetime, timedelta

SNS_TOPIC_ARN = 'arn:aws:sns:ap-south-1:165066919250:security-alerts'
ROLE_NAME = 'SecurityAuditRole'

# Central account check (set to True if you want to include the account running the Lambda)
INCLUDE_CENTRAL_ACCOUNT = True

# List of target (child) AWS account IDs
TARGET_ACCOUNTS = [
    '369315415589'
]

# --- Cross-account assume role ---
def assume_role(account_id, role_name):
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"SecCheck-{account_id}"
    )
    creds = response['Credentials']
    return creds

# --- Generate clients from credentials ---
def get_boto3_clients(creds=None):
    if creds:
        return {
            'iam': boto3.client('iam',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            ),
            'ec2': boto3.client('ec2',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            ),
            's3': boto3.client('s3',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            ),
            'cloudtrail': boto3.client('cloudtrail',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            ),
            'sts': boto3.client('sts',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            )
        }
    else:
        # For central account (no assume role)
        return {
            'iam': boto3.client('iam'),
            'ec2': boto3.client('ec2'),
            's3': boto3.client('s3'),
            'cloudtrail': boto3.client('cloudtrail'),
            'sts': boto3.client('sts')
        }

def get_account_id(clients):
    return clients['sts'].get_caller_identity()['Account']

# --- Security checks---
def check_iam_users_without_mfa(iam):
    users = iam.list_users()['Users']
    result = []
    for user in users:
        try:
            iam.get_login_profile(UserName=user['UserName'])
            mfa = iam.list_mfa_devices(UserName=user['UserName'])
            if not mfa['MFADevices']:
                result.append(user['UserName'])
        except iam.exceptions.NoSuchEntityException:
            pass
    return result

def check_open_security_groups(ec2):
    sgs = ec2.describe_security_groups()['SecurityGroups']
    result = []
    for sg in sgs:
        for permission in sg.get('IpPermissions', []):
            for ip in permission.get('IpRanges', []):
                if ip.get('CidrIp') == '0.0.0.0/0':
                    port = permission.get('FromPort')
                    if port in [22, 3389]:
                        result.append(f"{sg['GroupId']} ({sg['GroupName']}) - Port {port}")
    return result

def check_unused_access_keys(iam):
    result = []
    users = iam.list_users()['Users']
    for user in users:
        keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
        for key in keys:
            last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
            last_used_date = last_used['AccessKeyLastUsed'].get('LastUsedDate')
            if last_used_date:
                days = (datetime.utcnow() - last_used_date.replace(tzinfo=None)).days
                if days > 90:
                    result.append(f"{user['UserName']} - {key['AccessKeyId']} unused for {days} days")
            else:
                result.append(f"{user['UserName']} - {key['AccessKeyId']} never used")
    return result

def check_public_s3_buckets(s3):
    result = []
    for bucket in s3.list_buckets()['Buckets']:
        try:
            status = s3.get_bucket_policy_status(Bucket=bucket['Name'])
            if status['PolicyStatus']['IsPublic']:
                result.append(bucket['Name'])
        except Exception:
            continue
    return result

def check_root_account_usage(cloudtrail):
    now = datetime.utcnow()
    past = now - timedelta(days=7)
    events = cloudtrail.lookup_events(
        LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': 'root'}],
        StartTime=past,
        EndTime=now
    )
    return bool(events['Events'])

def check_cloudtrail_enabled(cloudtrail):
    trails = cloudtrail.describe_trails()['trailList']
    return any(trail.get('IsMultiRegionTrail') for trail in trails)

def check_unused_elastic_ips(ec2):
    addresses = ec2.describe_addresses()['Addresses']
    return [addr['PublicIp'] for addr in addresses if 'InstanceId' not in addr]

# --- Reusable account scanner ---
def scan_account(account_id=None, creds=None):
    clients = get_boto3_clients(creds)
    acct_id = account_id or get_account_id(clients)
    report = f"--- Account: {acct_id} ---\n"

    mfa = check_iam_users_without_mfa(clients['iam'])
    if mfa:
        report += "IAM Users without MFA:\n" + "\n".join(f"- {u}" for u in mfa) + "\n\n"

    open_sg = check_open_security_groups(clients['ec2'])
    if open_sg:
        report += "Open Security Groups:\n" + "\n".join(f"- {sg}" for sg in open_sg) + "\n\n"

    unused_keys = check_unused_access_keys(clients['iam'])
    if unused_keys:
        report += "Unused Access Keys:\n" + "\n".join(f"- {k}" for k in unused_keys) + "\n\n"

    public_buckets = check_public_s3_buckets(clients['s3'])
    if public_buckets:
        report += "Public S3 Buckets:\n" + "\n".join(f"- {b}" for b in public_buckets) + "\n\n"

    if check_root_account_usage(clients['cloudtrail']):
        report += "Root account login detected in last 7 days\n\n"

    if not check_cloudtrail_enabled(clients['cloudtrail']):
        report += "CloudTrail is NOT enabled\n\n"

    unused_eips = check_unused_elastic_ips(clients['ec2'])
    if unused_eips:
        report += "Unused Elastic IPs:\n" + "\n".join(f"- {ip}" for ip in unused_eips) + "\n\n"

    return report

# --- Send email alert ---
def send_email(subject, body):
    boto3.client('sns').publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=body
    )

# --- Lambda main entry point ---
def lambda_handler(event, context):
    full_report = "AWS Multi-Account Security Report\n\n"

    # First: Scan the central account if enabled
    if INCLUDE_CENTRAL_ACCOUNT:
        try:
            full_report += scan_account()
        except Exception as e:
            full_report += f"--- Central Account ---\nFailed to scan: {str(e)}\n\n"

    # Then scan target accounts via assume role
    for account_id in TARGET_ACCOUNTS:
        try:
            creds = assume_role(account_id, ROLE_NAME)
            full_report += scan_account(account_id, creds)
        except Exception as e:
            full_report += f"--- Account: {account_id} ---\nFailed to scan: {str(e)}\n\n"

    send_email("AWS Multi-Account Security Alert", full_report)
    print("Security report sent.")
