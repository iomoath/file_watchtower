# File Watchtower

File WatchTower project is a lightweight File Integrity Monitoring Tool. File WatchTower is able to detect, log and report a change in a file content, file deletion, file renaming and file creation. Whenever an violation is occurs, File WatchTower will notify you by Email and also will produce logs about the incident.

Features:
* Detect a change in a file content.
* Detect a new file(s) added to a directory.
* Detect a file rename.
* Detect a file deletion.
* Filter(s) options for excluding files from watching zone.
* Watch a single or multiple files.
* Delivering reports by email.
* Logging.


Example scenarios:
* Detect unauthorized file content modification. ex; configuration files and source code.
* Detect unauthorized file creation, ex; web shells.
* Detect unauthorized file deletion. ex; log file deletion

### Prerequisites
* Python 3

# Installation
1. Clone or download the project files.
2. Place the project files in a writble directory, and outside the directories being watched.
3. Add the file(s) and directorie(s) path that should be watched in the file 'watch_list.txt' separated by a new line.

Example on 'watch_list.txt' entries

Single File Format:
```
/var/www/html/config.php
```

Directory Format:

```directory path, include sub directories [true or false], excluded file extensions [comma separated], max file size in byte unit```

```
/var/www/html/wordpress/wp-content/themes, false, .css|.woff|.ttf, 1048576

/var/www/html/wordpress/wp-content/themes, true, .css, 1048576

/var/www/html/wordpress/wp-content/themes, true, .css
```


3. To enable email alerts, modify the Email sending (SMTP) sttings in 'watchtower_settings.py'
4. Run the script 'watchtower.py' with ```silent-scan``` option.

```
python3 watchtower.py --silent-scan
```
The silent scan option will scan the watch list file (watch_list.txt) and create a records for the files. no alarms and notifications will be made. Use this option whenever you add new files into the directories being watched.

5. Create a cron job for routine scanning. The following cron will run at 12:00 AM every day. Adjust as your requirements.

```
$ crontab -e
# append the following line, adjust project path

0 0 * * * python3 /opt/file_watchtower/watchtower.py --routine_scan
```


# Command Line Args

```
  -h, --help          show this help message and exit
  -r, --routine_scan  This is the routine scan and usually executed by OS cron
                      manager. The routine scan type, Will scan and report the
                      changes that occurs within the directories or files
                      being watched
  -s, --silent-scan   This type of scan will parse the watch list file
                      (watch_list.txt) and create a records for the file(s).
                      no alarms and notifications will be made. Use this
                      option whenever you add new files into the directories
                      being watched.
  --export-db         Export the database file records to a CSV file.
  --reset             Empty the file records database.
  --version           show program's version number and exit
```

# Screenshots
![Email Alerts](File_WathTower_Alerts.png?raw=true "Email Alerts")



## License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details


## Meta
Moath Maharmeh - [@iomoaaz](https://twitter.com/iomoaaz) - moath@vegalayer.com

https://github.com/iomoath/file_watchtower
