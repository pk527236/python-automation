import boto3
from datetime import datetime, timedelta

# Replace this with your SNS Topic ARN
SNS_TOPIC_ARN = 'arn:aws:sns:ap-south-1:165066919250:security-alerts'

def check_iam_users_without_mfa():
    iam = boto3.client('iam')
    users = iam.list_users()['Users']
    users_without_mfa = []

    for user in users:
        username = user['UserName']
        try:
            iam.get_login_profile(UserName=username)
            mfa_devices = iam.list_mfa_devices(UserName=username)
            if not mfa_devices['MFADevices']:
                users_without_mfa.append(username)
        except iam.exceptions.NoSuchEntityException:
            pass  # No console access

    return users_without_mfa

def check_open_security_groups():
    ec2 = boto3.client('ec2')
    sgs = ec2.describe_security_groups()['SecurityGroups']
    risky_sgs = []

    for sg in sgs:
        for permission in sg.get('IpPermissions', []):
            ip_ranges = permission.get('IpRanges', [])
            for ip_range in ip_ranges:
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    port = permission.get('FromPort')
                    if port in [22, 3389]:
                        risky_sgs.append({
                            'GroupId': sg['GroupId'],
                            'GroupName': sg['GroupName'],
                            'Port': port
                        })
    return risky_sgs

def check_unused_access_keys():
    iam = boto3.client('iam')
    users = iam.list_users()['Users']
    unused_keys = []

    for user in users:
        username = user['UserName']
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            key_id = key['AccessKeyId']
            last_used_info = iam.get_access_key_last_used(AccessKeyId=key_id)
            last_used_date = last_used_info['AccessKeyLastUsed'].get('LastUsedDate')
            if last_used_date:
                days_unused = (datetime.utcnow() - last_used_date.replace(tzinfo=None)).days
                if days_unused > 90:
                    unused_keys.append(f"{username} - {key_id} unused for {days_unused} days")
            else:
                unused_keys.append(f"{username} - {key_id} never used")
    return unused_keys

def check_public_s3_buckets():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    public_buckets = []

    for bucket in buckets:
        try:
            status = s3.get_bucket_policy_status(Bucket=bucket['Name'])
            if status['PolicyStatus']['IsPublic']:
                public_buckets.append(bucket['Name'])
        except Exception:
            pass  # Likely no policy, private by default

    return public_buckets

# Uncomment if you want to include EBS encryption check later
# def check_unencrypted_ebs_volumes():
#     ec2 = boto3.client('ec2')
#     volumes = ec2.describe_volumes()['Volumes']
#     unencrypted = [vol['VolumeId'] for vol in volumes if not vol['Encrypted']]
#     return unencrypted

def check_root_account_usage():
    ct = boto3.client('cloudtrail')
    now = datetime.utcnow()
    past = now - timedelta(days=7)
    events = ct.lookup_events(
        LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': 'root'}],
        StartTime=past,
        EndTime=now
    )
    return bool(events['Events'])

def check_cloudtrail_enabled():
    ct = boto3.client('cloudtrail')
    trails = ct.describe_trails()['trailList']
    enabled_trails = [trail for trail in trails if trail.get('IsMultiRegionTrail')]
    return bool(enabled_trails)

def check_unused_elastic_ips():
    ec2 = boto3.client('ec2')
    addresses = ec2.describe_addresses()['Addresses']
    unused = [addr['PublicIp'] for addr in addresses if 'InstanceId' not in addr]
    return unused

def send_email(subject, body):
    sns = boto3.client('sns')
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=body
    )

def main():
    report = ""

    users_without_mfa = check_iam_users_without_mfa()
    if users_without_mfa:
        report += "IAM Users without MFA:\n" + "\n".join(users_without_mfa) + "\n\n"

    open_sgs = check_open_security_groups()
    if open_sgs:
        report += "Open Security Groups:\n"
        for sg in open_sgs:
            report += f"{sg['GroupId']} ({sg['GroupName']}) - Port {sg['Port']}\n"
        report += "\n"

    unused_keys = check_unused_access_keys()
    if unused_keys:
        report += "Unused Access Keys (>90 days):\n" + "\n".join(unused_keys) + "\n\n"

    public_buckets = check_public_s3_buckets()
    if public_buckets:
        report += "Public S3 Buckets:\n" + "\n".join(public_buckets) + "\n\n"

    # unencrypted_vols = check_unencrypted_ebs_volumes()
    # if unencrypted_vols:
    #     report += "Unencrypted EBS Volumes:\n" + "\n".join(unencrypted_vols) + "\n\n"

    if check_root_account_usage():
        report += "Root account login activity detected in last 7 days!\n\n"

    if not check_cloudtrail_enabled():
        report += "CloudTrail is not enabled!\n\n"

    unused_eips = check_unused_elastic_ips()
    if unused_eips:
        report += "Unused Elastic IPs:\n" + "\n".join(unused_eips) + "\n\n"

    if report:
        send_email("AWS Security Alert Report", report)
        print("Alert email sent.")
    else:
        print("No security issues found.")

# Lambda entry point
def lambda_handler(event, context):
    main()
