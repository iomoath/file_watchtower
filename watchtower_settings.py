# Email notification settings
EMAIL_NOTIFICATIONS_ENABLED = False
SMTP_HOST = "smtp.example.net"
SMTP_PORT = 587
SMTP_USERNAME = "noc@example.net"
SMTP_PASSWORD = "123"
SMTP_SSL = True

FROM_NAME = "File Watchtower"
TO = "noc@example.org"

WATCH_LIST_FILE_PATH = 'watch_list.txt'  # files and directories path list to be watched
