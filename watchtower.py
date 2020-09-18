__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__version__ = "1.2"
__email__ = "moath@vegalayer.com"
__created__ = "13/Dec/2018"
__modified__ = "31/Mar/2020"
__project_page__ = "https://github.com/iomoath/file_watchtower"


import argparse
import sys
import watchtower_core
import db
import notifier

arg_parser = None


def run(args):

    if args['routine_scan']:
        watchtower_core.start_scan(False)
    elif args['silent_scan']:
        watchtower_core.start_scan(True)
    elif args['process_email_queue']:
        notifier.send_queued_messages()
    elif args["export_db"]:
        export_path = input("Enter the output path: ")
        watchtower_core.export_file_records_to_csv(export_path)
    elif args["reset"]:
        ans = input("WARNING: This will delete all database records. Do you really want to continue [Y/N]? ")
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
 
    
    Lightweight File Integrity Monitoring Tool

    https://github.com/iomoath/file_watchtower
    """
    ap = argparse.ArgumentParser(ascii_logo)

    ap.add_argument("-r", "--routine-scan", action='store_true',
                    help="This is the routine scan and usually executed by OS cron manager."
                         "The routine scan type, Will scan and report the changes that occurs within the directories or files being watched")

    ap.add_argument("-s", "--silent-scan", action='store_true',
                    help="This type of scan will parse the watch list file (watch_list.txt) and create a records for the file(s). no alerts will be made. Use this option whenever you add new files into the directories being watched.")

    ap.add_argument("-e", "--process-email-queue", action='store_true',
                    help="Send pending email alerts.")

    ap.add_argument("--export-db", action='store_true',
                    help="Export the database file records to a CSV file.")

    ap.add_argument("--reset", action='store_true',
                    help="Empty the file records database.")

    ap.add_argument("--version", action="version", version='File WatchTower Version 1.2')

    return ap


def main():
    global arg_parser
    arg_parser = generate_argparser()

    args = vars(arg_parser.parse_args())
    run(args)


if __name__ == "__main__":
    main()
