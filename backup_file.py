import os
import datetime
import shutil
import tarfile

def backup_and_extract(source, dest):
    # Create today's date string
    today = datetime.date.today()
    backup_file_name = os.path.join(dest, f"backup_{today}")
    
    # Step 1: Create the .tar.gz backup
    archive_path = shutil.make_archive(backup_file_name, "gztar", source)
    print(f"Backup created: {archive_path}")
    
    # Step 2: Extract the archive to the destination folder
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(path=dest)
        print(f"Backup extracted to: {dest}")
    except Exception as e:
        print(f"Failed to extract archive: {e}")

# Set your paths
sourcefile = "/home/user/python-automation"
destinationfile = "/home/user/python-automation/backup"

# Ensure destination directory exists
os.makedirs(destinationfile, exist_ok=True)

# Run the backup and extract function
backup_and_extract(sourcefile, destinationfile)
