################ Email Alerts settings ################
EMAIL_ALERTS_ENABLED = False

USE_SMTP = False
SMTP_HOST = "smtp.example.net"
SMTP_PORT = 587
SMTP_USERNAME = "soc@example.org"
SMTP_PASSWORD = "123456"
SMTP_SSL = True


FROM = "soc@example.org"
FROM_NAME = "File WatchTower"
TO = "soc@example.org"

################ General settings ################
WATCH_LIST_FILE_PATH = 'watch_list.txt'  # files and directories path list to be watched
DEBUG_LOG_ENABLED = False
DEBUG_LOG_FILE_PATH = 'debug.log'
FILE_RENAME_LOG_FILE_PATH = 'file_rename.log'
FILE_CREATION_LOG_FILE_PATH = 'file_creation.log'
FILE_CHANGE_LOG_FILE_PATH = 'file_change.log'
FILE_DELETION_LOG_FILE_PATH = 'file_delete.log'
