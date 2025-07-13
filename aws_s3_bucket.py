import boto3

# Use boto3 client and resource
s3_resource = boto3.resource("s3")
s3_client = boto3.client("s3")

def show_buckets(s3_resource):
    print("📦 Existing Buckets:")
    for bucket in s3_resource.buckets.all():
        print(f" - {bucket.name}")

def create_bucket(s3_client, bucket_name, region):
    try:
        if region == "us-east-1":
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        print("✅ Bucket created successfully:", bucket_name)
    except Exception as e:
        print(f"❌ Error creating bucket: {e}")

def upload_backup(s3_client, bucket_name, file_path):
    try:
        s3_client.upload_file(file_path, bucket_name, file_path.split('/')[-1])
        print(f"✅ File '{file_path}' uploaded to bucket '{bucket_name}' successfully.")
    except Exception as e:
        print(f"❌ Failed to upload file: {e}")

def delete_all_objects_in_bucket(s3_resource, bucket_name):
    try:
        bucket = s3_resource.Bucket(bucket_name)
        object_count = sum(1 for _ in bucket.objects.all())
        if object_count == 0:
            print(f"ℹ️ Bucket '{bucket_name}' is already empty.")
            return
        bucket.objects.all().delete()
        print(f"🧹 Deleted all ({object_count}) objects from bucket '{bucket_name}'.")
    except Exception as e:
        print(f"❌ Failed to delete objects: {e}")

def delete_bucket(s3_client, s3_resource, bucket_name):
    delete_all_objects_in_bucket(s3_resource, bucket_name)
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"✅ Bucket '{bucket_name}' deleted successfully.")
    except Exception as e:
        print(f"❌ Failed to delete bucket: {e}")

# === Example Usage ===

bucket_name = "demo-bucket-python-unique-12345"
region = "us-east-2"

# Step 1: Show current buckets
show_buckets(s3_resource)

# Step 2: Create bucket
# create_bucket(s3_client, bucket_name, region)

# Step 3: Upload file
# upload_backup(s3_client, bucket_name, "/home/user/python-automation/backup/backup_2025-07-13.tar.gz")

# Step 4: Delete bucket and all contents
# delete_bucket(s3_client, s3_resource, bucket_name)
