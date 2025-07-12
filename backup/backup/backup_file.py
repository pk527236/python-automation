import os
import datetime
import shutil

def backup_file(source,dest):
    today=datetime.date.today()
    backup_file_name=os.path.join(dest,f"backup_{today}")
    shutil.make_archive(backup_file_name,"gztar",source)

sourcefile="/home/user/python-automation"
destinationfile="/home/user/python-automation/backup"
backup_file(sourcefile,destinationfile)