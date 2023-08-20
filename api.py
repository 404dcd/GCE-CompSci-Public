from flask import Flask, request, session, redirect # flask essentials
import sqlite3 # for database connection
import re # for searching text
import time # for logging time of registration

app = Flask(__name__, static_url_path="")
# IN A PRODUCTION ENVIRONMENT, CHANGE THE NEXT LINE RANDOMLY:
app.secret_key = bytes.fromhex("[GENERATE RANDOM HEX HERE]")
DB_PATH = "db.sqlite3"

# Helper function to read exactly n bytes from a JS array (dictionary) into a python byte array
def readBinary(jsArray, n):
    ret = bytearray()
    for x in range(n):
        item = jsArray.get(str(x))
        try:
            ret.append(item)
        except (TypeError, ValueError):
            return None
    
    return ret

# See if the hash given matches any of our compromised logged passwords
@app.route("/api/findmatch", methods=["POST"])
def findmatch():
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()

        h = request.json.get("hash") # Retrieve from request
        if type(h) is not str: # ensure it's a string
            return {"error": "missing hash"}, 400

        res = cur.execute("SELECT hash FROM hashes WHERE hash = ?", (h,)).fetchone()
        if res is None: # If no entry was returned
            return {"message": "no"}, 200

        # Otherwise it's in there
        return {"message": "yes"}, 200

# Deleting a password
@app.route("/api/delpass", methods=["POST"])
def delpass():
    if session.get("uid") is None: # This page is only available to logged-in users
        return {"error": "not logged in"}, 401

    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()

        pid = request.json.get("pid") # Retrieve from request
        if type(pid) is not int: # make sure it's of right format
            return {"error": "missing pid"}, 400

        # Do the deletion, but make sure they can only delete passwords they own
        cur.execute("DELETE FROM passwords WHERE pid = ? AND owner = ?", (pid, session["uid"]))
        con.commit()

        return {"message": "success"}, 200

# Getting a list of all passwords
@app.route("/api/listpass", methods=["POST"])
def listpass():
    if session.get("uid") is None: # User must be logged in
        return {"error": "not logged in"}, 401

    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()

        result = cur.execute("SELECT pid, category, user, name FROM passwords WHERE owner = ?", (session["uid"],)).fetchall()
        ret = {}
        for entry in result: # Set up the data in a nice format for JavaScript
            pid = entry[0]
            category = entry[1]
            user = entry[2]
            name = entry[3]
            if category not in ret: # make sure the inner data items are initialised
                ret[category] = {}  
            ret[category][f"p{pid}"] = {"user": user, "name": name}

        return {"data": ret}, 200

# To fetch a specific RSA-encrypted password given PID
@app.route("/api/getpass", methods=["POST"])
def getpass():
    if session.get("uid") is None: # User must be logged in
        return {"error": "not logged in"}, 401

    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()

        pid = request.json.get("pid") # Retrieve from request
        if type(pid) is not int: # Make sure type is correct
            return {"error": "missing pid"}, 400

        # Make sure the user can only fetch passwords that they actually own
        result = cur.execute("SELECT data FROM passwords WHERE owner = ? AND pid = ?", (session["uid"], pid)).fetchone()
        if result is None:
            return {"error": "cannot fetch password"}, 400

        # Format in a correct way for JavaScript
        return {"data": [x for x in result[0]]}, 200

# To add a password
@app.route("/api/addpass", methods=["POST"])
def addpass():
    if session.get("uid") is None: # ensure logged in
        return {"error": "not logged in"}, 401

    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        
        rawData = request.json.get("data") # initial fetch from request
        if type(rawData) is not dict:
            return {"error": "missing password"}, 400
        name = request.json.get("name")
        if type(name) is not str:
            return {"error": "missing name"}, 400
        category = request.json.get("category")
        if type(category) is not str:
            return {"error": "missing category"}, 400
        user = request.json.get("user")
        if type(user) is not str:
            return {"error": "missing user"}, 400
        
        # validate received data
        data = readBinary(rawData, 256)
        if data is None:
            return {"error": "bad password"}, 400
        if len(name) > 128 or len(name) == 0:
            return {"error": "bad name"}, 400
        if len(category) > 128 or len(category) == 0:
            return {"error": "bad category"}, 400
        if len(user) > 128:
            return {"error": "bad user"}, 400
        
        try:
            cur.execute("INSERT INTO passwords (category, user, name, data, owner) VALUES (?, ?, ?, ?, ?)", (category, user, name, data, session["uid"]))
            con.commit()
        except sqlite3.DatabaseError: # this should never happen
            return {"error": "database failure"}, 500

        return {"message": "success"}, 200

# Simple function to logout a user by modifying session
@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("uid", None)
    return {"message": "success"}, 200

# Route for logging in
@app.route("/api/login", methods=["POST"])
def login():
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        email = request.json.get("email") # initial fetch from request
        if type(email) is not str:
            return {"error": "missing email"}, 400
        rawToken = request.json.get("token")
        if type(rawToken) is not dict:
            return {"error": "missing token"}, 400
        
        # validate received data
        if not re.search("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", email):
            return {"error": "bad email"}, 400
        token = readBinary(rawToken, 32)
        if token is None:
            return {"error": "bad token"}, 400
        
        lookup = cur.execute("SELECT uid FROM users WHERE email=? AND token=?", (email, token)).fetchone()
        if lookup is not None:
            session["uid"] = lookup[0] # securely mark the user as authenticated
            return {"message": "success"}, 200
        else:
            return {"error": "login failed"}, 401

# Route to register a user
@app.route("/api/register", methods=["POST"])
def register():    
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        email = request.json.get("email") # initial fetch from request
        if type(email) is not str:
            return {"error": "missing email"}, 400
        rawToken = request.json.get("token")
        if type(rawToken) is not dict:
            return {"error": "missing token"}, 400
        rawPubkey = request.json.get("pubkey")
        if type(rawPubkey) is not dict:
            return {"error": "missing pubkey"}, 400

        # validate received data
        if not re.search("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", email):
            return {"error": "bad email"}, 400
        token = readBinary(rawToken, 32)
        if token is None:
            return {"error": "bad token"}, 400
        pubkey = readBinary(rawPubkey, 270)
        if pubkey is None:
            return {"error": "bad pubkey"}, 400
        
        try:
            cur.execute("INSERT INTO users (email, token, pubkey, registered) VALUES (?, ?, ?, ?)", (email, token, pubkey, int(time.time())))
            con.commit()
        except sqlite3.DatabaseError:
            return {"error": "email in use"}, 400

        return {"message": "success"}, 200


# Register other GET routes:

@app.route("/", methods=["GET"])
def root():
    return redirect("/index.html", code=302) # always send to index.html instead

@app.route("/index.html", methods=["GET"])
def indexPage():
    if session.get("uid") is None: # Can only use index.html if logged in
        return redirect("/login.html", code=302)
    else:
        return app.send_static_file("index.html")

@app.route("/login.html", methods=["GET"])
def loginPage():
    if session.get("uid") is not None: # Can only use login.html if NOT logged in
        return redirect("/index.html", code=302)
    else:
        return app.send_static_file("login.html")

@app.route("/register.html", methods=["GET"])
def registerPage():
    if session.get("uid") is not None: # Can only use register.html if NOT logged in
        return redirect("/index.html", code=302)
    else:
        return app.send_static_file("register.html")

# This enables debugging mode, do not run in production
app.run("127.0.0.1", 32768, True)
