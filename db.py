__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__version__ = "1.1"
__email__ = "moath@vegalayer.com"
__created__ = "13/Dec/2018"
__modified__ = "5/Apr/2019"
__project_page__ = "https://github.com/iomoath/file_watchtower"


import sqlite3
import os
import csv

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), 'database.sqlite3')


def get_db_path():
    global DEFAULT_PATH

    return DEFAULT_PATH


def db_connect(db_path=DEFAULT_PATH):
    con = sqlite3.connect(db_path)
    return con


def create_tables():


    file_record_query = """
    CREATE TABLE IF NOT EXISTS file_record (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    file_size TEXT NOT NULL,
    exists_on_disk varchar(6) NOT NULL,
    datetime_last_check TEXT NOT NULL)"""

    email_msg_query = """
    CREATE TABLE IF NOT EXISTS email_msg (
    id INTEGER PRIMARY KEY,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    attachment TEXT,
    is_sent VARCHAR(6) DEFAULT 'False')"""

    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute(file_record_query)
        cursor.execute(email_msg_query)
    except:
        pass
    finally:
        conn.commit()
        conn.close()



def insert_file_record(file_record_dict):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        query = """
            INSERT INTO file_record (file_path, hash, file_size, exists_on_disk, datetime_last_check)
            VALUES (?, ?, ?, ?, ?)"""
        cursor.execute(query,
                       (file_record_dict["path"], file_record_dict["hash"], file_record_dict["file_size"],
                        file_record_dict["exists_on_disk"], file_record_dict["datetime_last_check"]))
        return cursor.lastrowid
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


def get_exists_on_disk_value(file_path):
    conn = db_connect()

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT exists_on_disk FROM file_record WHERE file_path=? LIMIT 1", (file_path,))
        rows = cursor.fetchall()
        return rows[0][0]
    except IndexError:
        return None
    finally:
        conn.close()


def get_exists_on_disk_value_by_hash(file_hash):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT exists_on_disk FROM file_record WHERE hash=? LIMIT 1", (file_hash,))
        rows = cursor.fetchall()
        return rows[0][0]
    except IndexError:
        return None
    finally:
        conn.close()


def update_exists_on_disk_value(file_path, new_value):
    conn = db_connect()

    try:
        cursor = conn.cursor()
        query = """UPDATE file_record SET exists_on_disk =? WHERE file_path =?"""
        cursor.execute(query, (new_value, file_path,))
        return cursor.rowcount
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


def update_exists_on_disk_value_by_hash(file_hash, new_value):
    conn = db_connect()

    try:
        cursor = conn.cursor()
        query = """UPDATE file_record SET exists_on_disk =? WHERE hash =?"""
        cursor.execute(query, (new_value, file_hash,))
        return cursor.rowcount
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


def update_file_last_check(file_path, new_datetime_check):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        query = """UPDATE file_record SET datetime_last_check =? WHERE file_path =?"""
        cursor.execute(query, (new_datetime_check, file_path,))
        return cursor.rowcount
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


def update_file_path(file_hash, old_path, new_path):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        query = """UPDATE file_record SET file_path =? WHERE hash =? and file_path=?"""
        cursor.execute(query, (new_path, file_hash, old_path))
        return cursor.rowcount
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


def get_file_records(file_path):
    conn = db_connect()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM file_record WHERE file_path=?", (file_path,))
        rows = cursor.fetchall()
        return rows
    except IndexError:
        return None
    finally:
        conn.commit()
        conn.close()



def get_file_records_by_hash(file_hash):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM file_record WHERE hash=?", (file_hash,))
        rows = cursor.fetchall()
        return rows
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_all_file_paths():
    # returns all files paths
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT file_path FROM file_record")
        rows = cursor.fetchall()

        path_list = []
        for row in rows:
            path_list.append(row[0])

        return path_list
    except:
        conn.rollback()
    finally:
        conn.close()


def get_file_hash(file_path):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT hash FROM file_record WHERE file_path=? LIMIT 1", (file_path,))
        rows = cursor.fetchall()
        return rows[0][0]
    except IndexError:
        return None
    finally:
        conn.close()


def get_file_path_by_hash(file_hash):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT file_path FROM file_record WHERE hash=? LIMIT 1", (file_hash,))
        rows = cursor.fetchall()
        return rows[0][0]
    except IndexError:
        return None
    finally:
        conn.close()


def is_file_has_record_by_path(file_path):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM file_record WHERE file_path=? LIMIT 1", (file_path,))
        rows = cursor.fetchall()
        return len(rows) > 0
    except:
        conn.rollback()
        return False
    finally:
        conn.close()


def is_file_has_record_by_hash(hash):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM file_record WHERE hash=? LIMIT 1", (hash,))

        rows = cursor.fetchall()
        return len(rows) > 0
    except:
        conn.rollback()
    finally:
        conn.close()


def get_file_size(file_path):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT file_size FROM file_record WHERE file_path=? LIMIT 1", (file_path,))
        rows = cursor.fetchall()
        return rows[0][0]
    except IndexError:
        return None
    finally:
        conn.close()


def get_file_size_by_hash(file_hash):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT file_size FROM file_record WHERE hash=? LIMIT 1", (file_hash,))
        rows = cursor.fetchall()
        return rows[0][0]
    except IndexError:
        return None
    finally:
        conn.close()


def update_file_hash(file_path, new_hash):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        query = """UPDATE file_record SET hash =? WHERE file_path =?"""
        cursor.execute(query, (new_hash, file_path,))
        return cursor.rowcount
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


def delete_file_record(file_path):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        query = """DELETE FROM file_record WHERE file_path=?"""
        cursor.execute(query, (file_path,))
        return cursor.rowcount
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


def insert_email_msg(email_msg_dict):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        query = """
            INSERT INTO email_msg (subject, body, attachment)
            VALUES (?, ?, ?)"""

        cursor.execute(query,
                       (
                           email_msg_dict["subject"],
                           email_msg_dict["body"],
                           email_msg_dict["attachment"]))
        return cursor.lastrowid
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()

def delete_msg(msg_id):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        query = """DELETE FROM email_msg WHERE id=?"""
        cursor.execute(query, (msg_id,))
        return cursor.rowcount
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


def get_unsent_messages():
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM email_msg WHERE is_sent='False'")
        rows = cursor.fetchall()
        list_messages = []
        for row in rows:
            msg = {
                "id": row[0],
                "subject": row[1],
                "body": row[2],
                "attachments": row[3],
                "is_sent": row[4]
            }
            list_messages.append(msg)

        return list_messages
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_sent_messages():
    conn = db_connect()
    try:
        cursor = conn.cursor()
        query = """DELETE FROM email_msg WHERE is_sent=?"""
        cursor.execute(query, ("True",))
        return cursor.rowcount
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


def dump_file_records_to_csv(export_path):
    conn = db_connect()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM file_record')
        with open(export_path, 'w') as out_csv_file:
            csv_out = csv.writer(out_csv_file)

            # write header
            csv_out.writerow([d[0] for d in cursor.description])

            # write data
            for result in cursor:
                csv_out.writerow(result)
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_all_data():
    conn = db_connect()

    try:
        cursor = conn.cursor()
        query1 = """DELETE FROM email_msg"""
        query2 = """DELETE FROM file_record"""
        cursor.execute(query1, )
        cursor.execute(query2, )
        return cursor.rowcount
    except:
        conn.rollback()
        raise
    finally:
        conn.commit()
        conn.close()


# init the database, if no db file or tables, it will be created here
create_tables()
