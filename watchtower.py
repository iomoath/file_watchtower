#!/usr/local/bin/python3
__author__ = "Moath Maharmeh"

"""
File WatchTower project is a lightweight tool is a basic file integrity montiroing. 
File WatchTower is able to detect, log and report a change in a file content, 
file deletion, file renaming and any files added to the directories being watched. 
Whenever an violation is occurs, File WatchTower will notify you by Email and also will produce logs about the incident.
Created By: Moath Maharmeh
Contact: moath@vegalayer.com
"""

import argparse
import sys
import watchtower_core
import db


def run(args):
    if args["init"]:
        watchtower_core.start_initial_scan()
    elif args["run"]:
        watchtower_core.scan()
    elif args["export_db"]:
        export_path = input("Enter the path that you would like to: ")
        watchtower_core.export_file_records_to_csv(export_path)
    elif args["reset"]:
        ans = input("WARNING: This will delete all records stored in the database. Do you really want to continue [Y/N]? ")
        if ans.upper() == "Y":
            db.delete_all_data()
            print("Database has been cleared.")
        else:
            sys.exit()


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("-i", "--init", action='store_true',
                    help="This Type of scan is executed to scan the Watch List "
                         "file and create file records in the database for the first time. "
                         "Execute this scan whenever you add new files into the directories being watched.")

    ap.add_argument("-r", "--run", action='store_true',
                    help="This is the routine scan and usually executed by OS cron manager. "
                         "Will scan for 'File content change', 'File deletion', "
                         "'File Rename' and will detect new files in the directories being watched.")

    ap.add_argument("--export-db", action='store_true',
                    help="Export the database file records to a CSV file 'file_records.csv'")

    ap.add_argument("--reset", action='store_true',
                    help="--reset: Empty the File WatchTower database.")

    ap.add_argument("--version", action="version", version='File WatchTower Version 1.0')

    if len(sys.argv) < 2:
        ap.print_help()
        sys.exit(0)
    args = vars(ap.parse_args())
    run(args)


if __name__ == "__main__":
    main()
