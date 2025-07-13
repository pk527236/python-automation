import boto3

# Use boto3 client for bucket creation
s3_resource = boto3.resource("s3")
s3_client = boto3.client("s3")

def show_buckets(s3_resource):
    for bucket in s3_resource.buckets.all():
        print(bucket.name)

def create_bucket(s3_client, bucket_name, region):
    if region == "us-east-1":
        # us-east-1 does NOT need a LocationConstraint
        s3_client.create_bucket(Bucket=bucket_name)
    else:
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': region}
        )
    print("✅ Bucket created successfully:", bucket_name)

# Show existing buckets
show_buckets(s3_resource)

# Create a new bucket
bucket_name = "demo-bucket-python-unique-12345"
region = "us-east-2"
# create_bucket(s3_client, bucket_name, region)

def upload_backup(s3_client, bucket_name, file_path):
    try:
        s3_client.upload_file(file_path, bucket_name, file_path.split('/')[-1])
        print(f"✅ File '{file_path}' uploaded to bucket '{bucket_name}' successfully.")
    except Exception as e:
        print(f"❌ Failed to upload file: {e}")

# Example usage of upload_backup
upload_backup(s3_client, bucket_name, "/home/user/python-automation/backup/backup_2025-07-13.tar.gz")

def delete_bucket(s3_client, bucket_name):
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"✅ Bucket '{bucket_name}' deleted successfully.")
    except Exception as e:
        print(f"❌ Failed to delete bucket: {e}")

# Example usage of delete_bucket
delete_bucket(s3_client, bucket_name)        

