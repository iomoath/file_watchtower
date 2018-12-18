# File WatchTower

File WatchTower project is a lightweight and File Integrity Montiroing Tool. File WatchTower is able to detect, log and report a modification in a file content, file deletion, file renaming and file creation. Whenever an violation is occurs, File WatchTower will notify you by Email and also will produce logs about the incident.

Example scenarios:
- Detect unauthorized file content modification. ex; configuration files and source code.
- Detect unauthorized file creation, ex; web shells.
- Detect unauthorized file deletion. ex; log file deletion


# Installation

1. Place the project files into writble directory, outside the directories being watched. 
Preferable location: '/opt'

2. Add the files and directories that should be watched in the file 'watch_list.txt' new line separated

Single File Format:
```
/var/www/html/config.php
```

Directory Format: directory path, scan_sub folders, excluded extensions, max file size in byte unit
```
/var/www/html/wordpress/wp-content/themes, yes, .css|.woff|.ttf, 1048576
```

3. Modify the Email sending (SMTP) sttings in 'watchtower_settings.py'

4. Run the script 'watchtower.py' with Initial scan option.

```
python3 watchtower.py --init
```

5. Create a cron job for routine scanning. The cron schedule is up to you. 

```
watchtower.py --run
```

# Command Line Args

```
-h, --help   show this help message and exit
-i, --init   This Type of scan is executed to scan the Watch List file and
           create file records in the database for the first time. Execute
           this scan whenever you add new files into the directories being
           watched.
-r, --run    This is the routine scan and usually executed by OS cron
           manager. Will scan for 'File content change', 'File deletion',
           'File Rename' and will detect new files in the directories
           being watched.
--export-db  Export the database file records to a CSV file
           'file_records.csv'
--reset      --reset: Empty the File WatchTower database.
--version    show program's version number and exit

```

# Screenshots
![Email Alerts](File_WathTower_Alerts.png?raw=true "Email Alerts")



# Contact Us

If you have any questions or would like to report errors/bugs. My email is:

moath@vegalayer.com

