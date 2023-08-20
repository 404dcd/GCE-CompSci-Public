import sqlite3 # needed for database
import os # needed to reset the database by deleting file
import datetime # needed to format user registration timestamp
from hashlib import sha256 # needed to add compromised to database

def stats():
    with sqlite3.connect("db.sqlite3") as con: # acquire database connection
        cur = con.cursor()
        # Lookup various stats
        numUsers = cur.execute("SELECT COUNT(uid) FROM users").fetchone()[0]
        numPWs = cur.execute("SELECT COUNT(pid) FROM passwords").fetchone()[0]
        numHashes = cur.execute("SELECT COUNT(hid) FROM hashes").fetchone()[0]
        maxUID = cur.execute("SELECT MAX(uid) FROM users").fetchone()[0]
        # Print with formatting
        print(f"  -- Users registered: {numUsers}")
        print(f"  -- Passwords stored: {numPWs}")
        print(f"  -- Compromised logged: {numHashes}")
        if numUsers != 0:
            # Only if at least one user has registered, select the email of the last one
            lastUserMail = cur.execute("SELECT email FROM users WHERE uid = ?", (maxUID,)).fetchone()[0]
            print(f"  -- Last user to register: {lastUserMail}")

def search():
    with sqlite3.connect("db.sqlite3") as con:
        cur = con.cursor()
        email = input("Enter email > ").strip().lower() # Take and sanitise input
        user = cur.execute("SELECT uid, registered FROM users WHERE email = ?", (email,)).fetchone()
        if user: # If user exists
            print("  -- User exists")
            uid = user[0] # Extract UID
            # Use this to count how many passwords they have
            numPWs = cur.execute("SELECT COUNT(pid) FROM passwords WHERE owner = ?", (uid,)).fetchone()[0]
            reg = datetime.datetime.fromtimestamp(user[1]).strftime('%Y-%m-%d %H:%M:%S') # format timestamp date nicely
            print(f"  -- Registered: {reg}") # format data nicely
            print(f"  -- Passwords stored: {numPWs}")
        else:
            print("  -- User does not exist")


def remove():
    with sqlite3.connect("db.sqlite3") as con:
        cur = con.cursor()
        email = input("Enter email > ").strip().lower() # sanitise
        # Try to fetch this user:
        user = cur.execute("SELECT uid FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            # Not only delete them, but delete their passwords too
            cur.execute("DELETE FROM users WHERE uid = ?", (user[0],))
            cur.execute("DELETE FROM passwords WHERE owner = ?", (user[0],))
            con.commit()
            print("  -- Success")
        else:
            print("  -- User does not exist, no action taken")

def add():
    with sqlite3.connect("db.sqlite3") as con:
        cur = con.cursor()
        mode = input("Add from (f)ile or (s)ingle entry > ").strip().lower() # sanitise
        if mode == "f": # If they want to add from a file
            fname = input("Enter filename > ")
            try:
                # Try to open this file, it might not exist
                with open(fname, "r") as fh:
                    # If it does, iterate through lines
                    for line in fh.readlines():
                        # And add each password properly in turn
                        toAdd = sha256(line.encode('utf-8')).hexdigest()
                        cur.execute("INSERT INTO hashes (hash) VALUES (?)", (toAdd,))
                        con.commit()
                print("  -- Success")
            except FileNotFoundError:
                print("  -- File does not exist")

        elif mode == "s":
            # Otherwise, just do the above one time.
            toAdd = sha256(input("Provide entry > ").encode('utf-8')).hexdigest()
            cur.execute("INSERT INTO hashes (hash) VALUES (?)", (toAdd,))
            con.commit()
            print("  -- Success")

        else:
            # If they make a bad choice
            print("  -- Failed to recognise choice")

def reset():
    # DOUBLE CHECK for confirmation before performing this risky action
    conf = input("Are you sure you wish to DELETE all users and passwords? y/n > ").strip().lower()
    if conf == "y":
        os.remove("db.sqlite3") # quickly delete all data
        with sqlite3.connect("db.sqlite3") as con:
            cur = con.cursor()
            # Set up tables as needed
            cur.execute("""
CREATE TABLE users(
  uid INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  token BLOB NOT NULL,
  pubkey BLOB NOT NULL,
  registered INTEGER NOT NULL
);
""")
            cur.execute("""
CREATE TABLE passwords(
  pid INTEGER PRIMARY KEY,
  category TEXT NOT NULL,
  user TEXT,
  name TEXT NOT NULL,
  data BLOB NOT NULL,
  owner INTEGER NOT NULL
);
""")
            cur.execute("""
CREATE TABLE hashes(
  hid INTEGER PRIMARY KEY,
  hash TEXT NOT NULL
);
""")
            con.commit()
        print("  -- Success") # Report on status of action
    else:
        print("  -- No action taken")


def main():
    while True: # Run a continuous command prompt interface
        action = input("\n>> ").strip().lower() # sanitise their input
        if action == "stats":
            stats()
        elif action == "search":
            search()
        elif action == "remove":
            remove()
        elif action == "add":
            add()
        elif action == "reset":
            reset()
        else:
            # If nothing matches, give them some help
            print("""
Usage:
        stats - print out whole-site statistics
        search - report on a user by email
        remove - ban a user from the site
        add - add details of compromised passwords to the health database
        reset - reset the entire database
"""
            )

main() # Run the main routine