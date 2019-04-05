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

arg_parser = None


def run(args):

    if args['routine_scan']:
        watchtower_core.start_scan(False)
    elif args['silent_scan']:
        watchtower_core.start_scan(True)
    elif args["export_db"]:
        export_path = input("Enter the output path: ")
        watchtower_core.export_file_records_to_csv(export_path)
    elif args["reset"]:
        ans = input("WARNING: This will delete all records stored in the database. Do you really want to continue [Y/N]? ")
        if ans.upper() == "Y":
            db.delete_all_data()
            print("Database has been cleared.")
        else:
            sys.exit()
    else:
        arg_parser.print_help()
        sys.exit()

def generate_argparser():

    ascii_logo = """
 ________  _   __          ____      ____      _          __       _                                      
|_   __  |(_) [  |        |_  _|    |_  _|    / |_       [  |     / |_                                    
  | |_ \_|__   | | .---.    \ \  /\  / /,--. `| |-'.---.  | |--. `| |-' .--.   _   _   __  .---.  _ .--.  
  |  _|  [  |  | |/ /__\\    \ \/  \/ /`'_\ : | | / /'`\] | .-. | | | / .'`\ \[ \ [ \ [  ]/ /__\\[ `/'`\] 
 _| |_    | |  | || \__.,     \  /\  / // | |,| |,| \__.  | | | | | |,| \__. | \ \/\ \/ / | \__., | |     
|_____|  [___][___]'.__.'      \/  \/  \'-;__/\__/'.___.'[___]|__]\__/ '.__.'   \__/\__/   '.__.'[___]    
 

    https://github.com/iomoath/file_watchtower
    """
    ap = argparse.ArgumentParser(ascii_logo)

    ap.add_argument("-r", "--routine_scan", action='store_true',
                    help="This is the routine scan and usually executed by OS cron manager. "
                         "The routine scan type, Will scan and report the changes that occurs within the directories or files being watched")

    ap.add_argument("-s", "--silent-scan", action='store_true',
                    help="This type of scan will parse the watch list file (watch_list.txt) and create a records for the file(s). no alarms and notifications will be made. Use this option whenever you add new files into the directories being watched.")

    ap.add_argument("--export-db", action='store_true',
                    help="Export the database file records to a CSV file.")

    ap.add_argument("--reset", action='store_true',
                    help="Empty the file records database.")

    ap.add_argument("--version", action="version", version='File WatchTower Version 1.1')

    return ap


def main():
    global arg_parser
    arg_parser = generate_argparser()

    args = vars(arg_parser.parse_args())
    run(args)


if __name__ == "__main__":
    main()
