#!/usr/bin/env python3

# Author: K. Walsh <kwalsh@cs.holycross.edu>
# Date: 15 January 2015
# Updated: 17 September 2020 - update to python3, add classes
# Updated: 15 September 2022 - bug fixes

# Modified: Eugene Mantilla
# Date: 20 October 2024 
# Updated: updated Whisper server side integration

# READ: Things to note are that I can't seem to figure out why every time
#       I post something, the error "HTTP POST to whisper seems to have failed..."
#       always pops up, but it still works somehow

# A simple web server from scratch in Python. Run it like this:
#   python3 webserver.py  localhost  8888
# or:
#   ./webserver.py  localhost  8888
#
# The two parameters are the hostname of the server, and the port number to
# listen on. An optional third parameter specifies a the server root directory.
# - For the port number, use any number between 1024 and 49151 that is not being
#   used by another program. Port 80 would be ideal for HTTP, as it is the
#   default used by web browsers, but using port numbers below 1024 requires
#   administrator privileges. 
# - For the server hostname, using "localhost" or "127.0.0.1" will ensure that
#   your server is only accessible to browsers on your own machine, and not from
#   attackers trying to access your server from over the internet. Using an
#   ampty string "" for the server hostname would allow all connections, even
#   from outside attackers.
# - By default, files from the "./web_root" directory will be served to clients.
#   If you want to serve files from a different directory, you can specify this
#   as a third argument, for example:
#       python3 webserver.py localhost 8888 ~/Desktop/Stuff
#
# Note: This code is not "pythonic" at all; there are much more concise ways to
# write this code by using various python features like dicts and string
# interpolation. We also avoid use of any modules except for the following very
# basic things:

import os             # for file and directory stuff, like os.path.isfile()
import socket         # for socket stuff
import sys            # for sys.argv and sys.exit()
import urllib.parse   # for urllib.parse.unquote() and urllib.parse.unquote_plus()
import time           # for time of day and date functions
import threading      # for concurrent threads and locks
import random         # for random numbers
import re             # for regex split() to split up strings
import string         # for various string operations

# Global configuration variables.
# These never change once the server has finished initializing, so they don't
# need any special protection even if used concurrently.
server_host = None # e.g. localhost, 127.0.0.1, logos.holycross.edu, or similar
server_port = None # e.g. 8888 or similar
server_root = "./web_root"
server_ip = None

# Global variables necessary for this project
my_lock = threading.Condition()     # Protect these global variables
visit_counter = 0                   # Counter to track page visits
name = ""                           # User's name for hello
favcolor = ""                       # User's favorite color for hello

# Global variables to keep track of statistics, with initial values. These get
# updated by different connection handler threads. To avoid concurrency
# problems, these must only be accessed within a "with" block, like this:
#     x = ...
#     with stats.lock:
#        stats.tot_time += x
#        if x > stats.max_time:
#            stats.max_time = x
#        ...
class Statistics:
    def __init__(self):
        self.lock = threading.Condition() # protects all variables below 
        self.total_connections = 0
        self.active_connections = 0
        self.num_requests = 0
        self.num_errors = 0
        self.max_time = 0 # max time spent handling a request
        self.tot_time = 0 # total time spent handling requests
        self.avg_time = 0 # average time spent handling requests
stats = Statistics()

# Request objects are used to hold information associated with a single HTTP
# request from a client.
class Request:
    def __init__(self):
        self.method = ""  # GET, POST, PUT, etc. for this request
        self.path = ""    # url path for this request
        self.version = "" # http version for this request
        self.headers = [] # headers from client for this request
        self.length = 0   # length of the request body, if any
        self.body = None  # contents of the request body, if any

# Response objects are used to hold information associated with a single HTTP
# response that will be sent to a client. The code is required, and should be
# something like "200 OK" or "404 NOT FOUND". The mime_type and body are
# optional. If present, the mime_type should be something like "text/plain" or
# "image/png", and the body should be a string or bytes object containing
# contents appropriate for that mime type.
class Response:
    def __init__(self, code, mime_type=None, body=None):
        self.code = code             # example: "200 OK"
        self.mime_type = mime_type   # example: "image.png"
        self.body = body             # a bytes object, or a string
        self.cookies = None          # a list of name=value strings (optional)

# Topic objects are used to hold information associated with a single topic.
class Topic:
    def __init__(self, name):
        self.lock = threading.Condition()  # Lock for controlling access to this topic's data
        self.name = name                   # The name of the topic (e.g., "#whatever")
        self.version_num = 0               # Version number for the topic, initialized to 0
        self.message_count = 0             # Count of how many messages have mentioned this topic
        self.like_count = 0                # Count of how many likes this topic has received
        self.messages = []                 # List to store messages that mention this topic

topics_lock = threading.Condition()  # Lock for synchronizing access to topics
topics = [
    Topic("whatever"),
    Topic("blahblah"),
    Topic("umm"),
    Topic("holycross")
]
topic_version = 0

# Helper function to check if a string looks like a common IPv4 address. Note:
# This is intentionally picky, only accepting the most common
# 4-numbers-with-dots notation, to avoid likely user input errors.
def isTypicalIPv4Address(s):
    parts = s.split('.')
    try: return len(parts) == 4 and all(0 <= int(p) < 256 for p in parts)
    except ValueError: return False

# SocketError objects represent errors that can occur with sockets.
class SocketError:
    def __init__(self, msg):
        self.msg = msg
    def __repr__(self):
        return "Socket Error: " + self.msg

# ERR_SOCKET_WAS_CLOSED means the other side unexpectedly closed the connection.
ERR_SOCKET_WAS_CLOSED = SocketError("Connection Closed")
# ERR_SOCKET_HAD_TIMEOUT means it's been a long time the other side sent data.
ERR_SOCKET_HAD_TIMEOUT = SocketError("Read Timeout")
# ERR_SOCKET_HAD_ERROR means something unknown went wrong.
ERR_SOCKET_HAD_ERROR = SocketError("Read/Write Failure")

# This variable controls how long the server is willing to wait for data from a
# client. If set to None, the server will wait indefinitely.
SOCKET_TIMEOUT = None # Or use 10.0 to give up after 10 seconds waiting for data from client.

# Connection objects are used to hold information associated with a single HTTP
# connection, like the socket for the connection, the client's IP address,
# statistics specific to that connection, any leftover data from the client that
# hasn't yet been processed, etc.
class Connection:
    def __init__(self, connected_socket, addr):
        self.sock = connected_socket        # the socket connected to the client
        self.client_addr = addr             # IP address of the client
        self.leftover_data = b""            # data from client, not yet processed
        self.num_requests = 0               # number of requests from client handled so far
        self.start_time = time.time()       # time connection was established
        self.last_active_time = time.time() # time connection was last used

    # wait_until_data_arrives() examines the socket and waits until some data
    # has arrived from the client. Normally, this function returns None, but if
    # something goes wrong, this function instead returns:
    # - ERR_SOCKET_HAD_TIMEOUT if a timeout occurs before data arrives,
    # - ERR_SOCKET_WAS_CLOSED if the socket was closed before any data arrives,
    # - ERR_SOCKET_HAD_ERROR if some other error is encountered.
    def wait_until_data_arrives(self):
        if len(self.leftover_data) > 0:
            return None
        try:
            # Set the timeout value, if present, to prevent infinite waiting.
            if SOCKET_TIMEOUT is not None:
                self.sock.settimeout(SOCKET_TIMEOUT)
            # Read (up to) another 4KB of data from the client
            more_data = self.sock.recv(4096)
            if not more_data: # Connection has died?
                log("Client %s closed the socket." % (self.client_addr))
                return ERR_SOCKET_WAS_CLOSED
            self.leftover_data = self.leftover_data + more_data
            return None
        except socket.timeout as err:
            log("Client %s has not sent data in %s seconds." %
                (self.client_addr, SOCKET_TIMEOUT))
            return ERR_SOCKET_HAD_TIMEOUT
        except:
            log("Error reading from client %s socket" % (self.client_addr))
            return ERR_SOCKET_HAD_ERROR
        finally:
            # Remove timeout, if present, so future operations are unaffected.
            if SOCKET_TIMEOUT is not None:
                self.sock.settimeout(None)

    # read_until_blank_line() returns data from the client up to (but not
    # including) the next blank line, i.e. "\r\n\r\n". The "\r\n\r\n" sequence
    # is discarded. Any leftovers after the blank line is saved for later. This
    # function returns one of the ERR_SOCKET values if an error is encountered.
    def read_until_blank_line(self):
        data = self.leftover_data
        try:
            # Set the timeout value, if present, to prevent infinite waiting.
            if SOCKET_TIMEOUT is not None:
                self.sock.settimeout(SOCKET_TIMEOUT)
            # Keep reading until we get a blank line.
            while b"\r\n\r\n" not in data:
                # Read (up to) another 4KB of data from the client
                more_data = self.sock.recv(4096)
                if not more_data: # Connection has died?
                    log("Client %s closed the socket." % (self.client_addr))
                    self.leftover_data = data # save it all for later?
                    return ERR_SOCKET_WAS_CLOSED
                data = data + more_data
            # The part we want is everything up to the first blank line.
            data, self.leftover_data = data.split(b"\r\n\r\n", 1)
            return data.decode()
        except socket.timeout as err:
            log("Client %s has not sent data in %s seconds." %
                (self.client_addr, SOCKET_TIMEOUT))
            self.leftover_data = data # save it all for later?
            return ERR_SOCKET_HAD_TIMEOUT
        except:
            log("Error reading from client %s socket" % (self.client_addr))
            self.leftover_data = data # save it all for later?
            return ERR_SOCKET_HAD_ERROR
        finally:
            # Remove timeout, if present, so future operations are unaffected.
            if SOCKET_TIMEOUT is not None:
                self.sock.settimeout(None)

    # read_amount(n) returns the next n bytes of data from the client. Any
    # leftovers after the n bytes are saved for later. This function returns
    # None if an error is encountered. It does not use timeouts, but instead
    # will wait indefinitely for enough data to arrive.
    def read_amount(self, n):
        data = self.leftover_data
        try:
            while len(data) < n:
                more_data = self.sock.recv(n - len(data))
                if not more_data: # Connection has died?
                    self.leftover_data = data # save it all for later
                    return None
                data = data + more_data
            # The part we want is the first n bytes.
            data, self.leftover_data = (data[0:n], data[n:])
            return data.decode()
        except:
            log("Error reading from client %s socket" % (self.client_addr))
            self.leftover_data = data # save it all for later
            return None

# log(msg) prints a message to standard output. Since multi-threading can jumble
# up the order of output on the screen, we print out the current thread's name
# on each line of output along with the message.
# Example usage:
#   log("Hello %s, you are customer number %d, have a nice day!" % (name, n))
# You can also use python's f-strings instead of the modulo operator:
#   log(f"Hello {name}, you are customer number {n}, have a nice day!")
def log(msg):
    # Convert msg to a string, if it is not already
    if not isinstance(msg, str):
        msg = str(msg)
    # Each python thread has a name. Use current thread's in the output message.
    myname = threading.current_thread().name
    # When printing multiple lines, indent each line a bit
    #indent = (" " * len(myname))
    indent = "    "
    linebreak = "\n" + indent + ": "
    lines = msg.splitlines()
    msg = linebreak.join(lines)
    # Print it all out, prefixed by this thread's name.
    print(myname + ": " + msg)

# get_header_value() finds a specific header value from within a list of header
# key-value pairs. If the requested key is not found, None is returned instead.
# The headers list comes from an HTTP request sent from the client. The key
# should usually be a standard HTTP header, like "Content-Type",
# "Content-Length", "Connection", etc. This will properly handle upper-case,
# lower-case, and mixed-case header names.
def get_header_value(headers, key):
    for hdr in headers:
        if hdr.lower().startswith(key.lower() + ": "):
            val = hdr.split(" ", 1)[1]
            return val
    return None

# get_cookies() returns the entire "Cookie" header, or None if it's not present.
def get_cookies(headers):
    vals = get_header_value(headers, "Cookie")
    return vals

# get_cookie() extracts the value of a specific named cookie from "Cookie"
# header, if the header is present and there is a matching "name=value" pair in
# that header. This returns None if there was no header, or the header didn't
# have the given "name=value" pair. The name is case-sensitive.
def get_cookie(headers, name):
    vals = get_header_value(headers, "Cookie")
    if vals == None:
        return None
    # There are many possible formats for the Cookie header...
    # - a single named value: "name=something"
    # - a single named value: "name1=value1; name2=value2; name3=value3"
    # - a single unnamed value: "something"
    pairs = vals.split("; ") # separator is exactly one semi-colon and one space 
    for pair in pairs:
        keyval = pair.split("=", 1)
        if len(keyval) == 2:
            # If this part is like "name1=value1", use those as key and val
            key = keyval[0].rstrip()
            val = keyval[1].lstrip()
        else:
            # If this part is like "value1", key is blank, entire thing is val
            key = ""
            val = keyval.lstrip()
        if key == name:
            return val
    return None

# make_printable() does some substitutions on a string so that it prints nicely
# on the console while still showing unprintable characters (like "\r" or "\n")
# in a sensible way.
printable = string.ascii_letters + string.digits + string.punctuation + " \r\n\t"
def make_printable(s):
    if isinstance(s, bytes):      # if s is raw binary...
        try:
            s = s.decode()
        except:
            return "{binary data, %d bytes total, not shown here}\n" % (len(s))
    if not isinstance(s, str):  # if s is not a string...
        body = str(s)             # ... convert to string
    s = s.replace("\n", "\\n\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    return ''.join(c if c in printable else r'\x{0:02x}'.format(ord(c)) for c in s)

# handle_one_http_request() reads one HTTP request from the client, parses it,
# decides what to do with it, then sends an appropriate response back to the
# client. 
def handle_one_http_request(conn):
    # The HTTP request is everything up to the first blank line
    data = conn.read_until_blank_line()
    if data == ERR_SOCKET_WAS_CLOSED:
        # Client disconnected... that's fine, nothing more to do here.
        return # caller will close socket
    if data == ERR_SOCKET_HAD_TIMEOUT:
        # Client is not sending requests... let's close the connection.
        log("Connection has been idle more than %s seconds, closing immediately.")
        return # caller will close socket
    if data == ERR_SOCKET_HAD_ERROR:
        # Unknown error... let's close the connection.
        return # caller will close socket

    conn.last_active_time = time.time()

    log("Request %d has arrived...\n%s" %
        (conn.num_requests, make_printable(data+"\r\n\r\n")))

    # Make a Request object to hold all the info about this request
    req = Request()

    # The first line is the request-line, the rest is the headers.
    lines = data.splitlines()
    if len(lines) == 0:
        log("Request is missing the required HTTP request-line")
        resp = Response("400 BAD REQUEST", "text/plain", "You need a request-line!")
        send_http_response(conn, resp)
        return
    request_line = lines[0] # first line is the request line
    req.headers = lines[1:] # remaining lines are the headers

    # The request-line can be further split into method, path, and version.
    words = request_line.split()
    if len(words) != 3:
        log("The request-line is malformed: '%s'" % (request_line))
        resp = Response("400 BAD REQUEST", "text/plain", "Your request-line is malformed!")
        send_http_response(conn, resp)
        return
    req.method = words[0]
    req.path = words[1]
    req.version = words[2]

    log("Request has method=%s, path=%s, version=%s, and %d headers" % (
        req.method, req.path, req.version, len(req.headers)))

    # The path will look like either "/foo/bar" or "/foo/bar?key=val&baz=boo..."
    # Unmangle any '%'-signs in the path, but just the part before any '?'-mark
    if "?" in req.path:
        req.path, params = req.path.split("?", 1)
        req.path = urllib.parse.unquote(req.path) + "?" + params
    else:
        req.path = urllib.parse.unquote(req.path)

    # Browsers that use chunked transfer encoding are tricky, don't bother.
    if get_header_value(req.headers, "Transfer-Encoding") == "chunked":
        log("The request uses chunked transfer encoding, which isn't yet supported")
        resp = Response("411 LENGTH REQUIRED",
                        "text/plain",
                        "Your request uses chunked transfer encoding, sorry!")
        send_http_response(conn, resp)
        return

    # If request has a Content-Length header, get the body of the request.
    n = get_header_value(req.headers, "Content-Length")
    if n is not None:
        req.length = int(n)
        req.body = conn.read_amount(int(n))

    # Finally, look at the method and path to decide what to do.
    if req.method == "GET":
        resp = handle_http_get(req, conn)
    # Handle the POST whisper requests
    elif req.method == "POST" or req.method == "PUT":
        if req.path.startswith("/whisper/messages"):
            resp = handle_http_post_messages(req)
        elif req.path.startswith("/whisper/like"):
            resp = handle_http_post_like(req)
        else:
            # Handle any other POST request that is not defined
            resp = Response("405 METHOD NOT ALLOWED", "text/plain", "Method not allowed and defined for this endpoint.")
    else:
        log("HTTP method '%s' is not recognized by this server" % (req.method))
        resp = Response("405 METHOD NOT ALLOWED",
                "text/plain",
                "Unrecognized method: " + req.method)

    # Now send the response to the client.
    send_http_response(conn, resp)

# send_http_response() sends an HTTP response to the client. The response code
# should be something like "200 OK" or "404 NOT FOUND". The mime_type and body
# are sent as the contents of the response.
def send_http_response(conn, resp):
    # If this is anything other than code 200, tally it as an error.
    if not resp.code.startswith("200 "):
        with stats.lock: # update overall server statistics
            stats.num_errors += 1
    # Make a response-line and all the necessary headers.
    data = "HTTP/1.1 " + resp.code + "\r\n"
    data += "Server: csci356\r\n"
    data += "Date: " + time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(time.time())) + "\r\n"

    if resp.cookies != None:
        # set cookies to expire in 1 week
        expiration = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(time.time() + 7*24*60*60))
        for cookie in resp.cookies:
            data += "Set-Cookie: " + cookie + "; Expires=" + expiration + "\r\n" 

    body = None
    if resp.mime_type == None:
        data += "Content-Length: 0\r\n"
    else:
        if isinstance(resp.body, bytes):   # if response body is raw binary...
            body = resp.body               # ... no need to encode it
        elif isinstance(resp.body, str):   # if response body is a string...
            body = resp.body.encode()      # ... convert to raw binary
        else:                              # if response body is anything else...
            body = str(resp.body).encode() # ... convert it to raw binary
        data += "Content-Type: " + resp.mime_type + "\r\n"
        data += "Content-Length: " + str(len(body)) + "\r\n"

    data += "\r\n"

    # Send response-line, headers, and body
    log("Sending response-line and headers...\n%s" % (make_printable(data)))
    conn.sock.sendall(data.encode())
    if body is not None:
        log("Response body (not shown) has %d bytes, mime type '%s'" %
            (len(body), resp.mime_type))
        # If you want to see the body in the console, uncomment this next line
        log("\n====BEGIN BODY====\n" + make_printable(body) + "=====END BODY====")
        conn.sock.sendall(body)

# handle_http_get_status() returns a response for GET /status
def handle_http_get_status(conn):
    log("Handling http get status request")
    msg = "Web server for csci 356, version 0.1\n"
    msg += "\n"
    msg += "Server Statistics:\n"
    with stats.lock:
        msg += str(stats.total_connections) + " connections in total\n"
        msg += str(stats.active_connections) + " active connections\n"
        msg += str(stats.num_requests) + " requests handled\n"
        msg += str(stats.num_errors) + " errors encountered\n"
        msg += "%.3f ms average request handling time\n" % (stats.avg_time * 1000)
        msg += "%.3f ms slowest request handling time\n" % (stats.max_time * 1000) 
    msg += "\n"
    msg += "Connection Statistics:\n"
    msg += str(conn.num_requests) + " requests handled on this connection so far\n"
    msg +=  "%.3f s elapsed since start of this connection\n" % (time.time() - conn.start_time)
    return Response("200 OK", "text/plain", msg)

# handle_http_get_whoami() returns a response for GET /whoami
def handle_http_get_whoami(req, conn):
    log("Handling HTTP GET whoami request")
    
    # Get client's IP address and port
    client_ip, client_port = conn.client_addr

    # Extract headers
    user_agent = get_header_value(req.headers, "User-Agent")
    accepted_languages = get_header_value(req.headers, "Accept-Language")
    cookies = get_cookies(req.headers)
    dnt_header = get_header_value(req.headers, "DNT")
    sec_gpc_header = get_header_value(req.headers, "Sec-GPC")

    # Build the HTML response
    msg = '<html>'
    msg += '<head>'
    msg += '<title>Who Am I?</title>'
    msg += '</head><body>'

    # Main client information
    msg += f'<h1>Your Client Information</h1>'
    msg += f'<p><strong>IP Address:</strong> {client_ip}</p>'
    msg += f'<p><strong>Port:</strong> {client_port}</p>'
    msg += f'<p><strong>User-Agent:</strong> {user_agent}</p>'
    msg += f'<p><strong>Accepted Languages:</strong> {accepted_languages}</p>'
    msg += f'<p><strong>Cookies:</strong> {cookies} </p>'
    msg += f'<p><strong>DNT Header:</strong> {dnt_header}</p>'
    msg += f'<p><strong>Sec-GPC Header:</strong> {sec_gpc_header}</p>'
    msg += '</body></html>'

    return Response("200 OK", "text/html", msg)

# handle_http_get_hello() returns a response for GET /hello
def handle_http_get_hello(req, conn):
    # Protect the name, favcolor, and visit_counter global variables
    with my_lock: 
        global name, favcolor, visit_counter

        # Increment the current visit count by 1
        visit_counter += 1

        log("Handling http get hello request")

        # Initialize color list and random color
        colors = ["coral", "crimson", "navy", "purple", "tomato", "teal", "wheat"]
        random_color = random.choice(colors) 

        # Start building the HTML response
        msg = '<html>'
        msg += '<head>'
        msg += '<title>Hello page for CSCI356!</title>'

        # Customize the page so that it greets the user once it knows their name
        if name == "": 
            msg += '<h1>Welcome to this page!</h1>'
        else:
            msg += f'<h1>Welcome back, {name}!</h1>'
        msg += '</head>'

        # Set background color dynamically
        msg += f'<body style="background-color: {random_color};">'

        # Add current date
        msg += f'<p><font face="Arial" size="2">The current date is {time.strftime("%a, %d %b %Y %H:%M:%S %Z")}.</font></p>'
        
        # Add visit counter, random color, and a message about the user's favorite color
        msg += f'<p>You have visited this page {visit_counter} time(s) before!</p>'
        msg += f'<p>This page\'s color is {random_color}.</p>'
        if favcolor != "": 
            if favcolor == random_color: 
                msg += f'<p>Your favorite color is {favcolor}! That\'s a sweet color!!</p>'
            else: 
                msg += f'<p>Your favorite color is <font color="{favcolor}">{favcolor}</font color>! That\'s a sweet color!!</p>'

        # Update links to be relative paths in a list
        # List formatting taken from https://www.w3schools.com/html/html_lists.asp
        msg += '<p>You can also go to these exciting pages:</p>'
        msg += '<ul>'
        msg += '<li><a href="/hello">This page</a></li>'
        msg += '<li><a href="/status">Status and statistics</a></li>'
        msg += '<li><a href="/quote">A random quote</a></li>'
        msg += '<li><a href="/welcome.html">A welcome page</a></li>'
        msg += '<li><a href="/index.html">Some fancy web page</a></li>'
        msg += '</ul>'

        # Create the user input forms
        # The following forms, drop down menu and submit button have been taken from https://www.youtube.com/watch?v=2O8pkybH6po
        msg += '<form method="GET">'
        msg += '<label for="username">Enter your name: </label>'
        msg += f'<input type="text" id="username" name="username" placeholder="{name}">'
        msg += '<br>'

        # Create the drop down menu for favorite colors
        msg += '<label for="Color">Favorite color: </label>'
        msg += '<select id ="Color" name="Color">'

        # Cycle through the given colors
        for color in colors:
            msg += f'<option value="{color}" selected>{color}</option>'
        
        msg += '</select>'
        msg += '<br><br>'

        # Submit button
        msg += '<input type="submit" value="Submit for a special surprise...">'
        msg += '</form>'

        # Add the silly randomized images after the user presses submit
        if visit_counter > 1:
            msg += f'<p>Silliness overload!</p>'
            msg += f'<img src="/silly{random.randint(1, 7)}.jpg" alt="Silly!!" width="200" height="200">'

        # Create audio element
        # Taken from https://www.w3schools.com/html/html5_audio.asp
        msg += '<br>'
        msg += f'<p>Here is some calm background music for you! (Song: Ico - Heal)</p>'
        msg += '<audio controls> <source src = "Heal.mp3" type="audio/mpeg"> </audio>'
        
        # Close the body and html tags
        msg += '</body>'
        msg += '</html>'

        # Create the response with the updated message
        resp = Response('200 OK', 'text/html', msg)
        return resp


# handle_http_get_quote() returns a response for the GET /quote
def handle_http_get_quote():
    log("Handling http get quote request")
    with open('quotations.txt') as f:
        quotes = re.split('(?m)^%$', f.read())
    msg = '<html><head><title>Quotes!</title></head>'
    msg += '<body>'
    msg += '<p>Here is a randomly generated quote from'
    msg += '  <a href="https://www.cs.cmu.edu/~pattis/quotations.html">Richard Pattis\' page</a> at CMU.'
    msg += "<pre>%s</pre>" % (random.choice(quotes))
    msg += '<p>Hit page refresh (F5) or <a href="/quote">click here</a> to refresh this page.</p>'
    msg += '<p>You can also check the <a href="/status">server status</a>, '
    msg += '  a <a href="/index.html">copy of the Holy Cross home page or something</a>, '
    msg += '</body></html>'
    return Response("200 OK", "text/html", msg)

# handle_http_get_file() returns an appropriate response for a GET request that
# seems to be for a file, rather than a special URL. If the file can't be found,
# or if there are any problems, an error response is generated.
def handle_http_get_file(url_path):
    log("Handling http get file request, for "+ url_path)
    
    file_path = server_root + url_path

    # First security precaution: "normalize" to eliminate ".." elements
    file_path = os.path.normpath(file_path)

    # Second security precaution: make sure the requested file is in server_root
    if os.path.commonprefix([file_path, server_root]) != server_root:
        log("Path traversal attack detected: " + url_path)
        return Response("403 FORBIDDEN", "text/plain", "Permission denied: " + url_path)

    # Third security precaution: check if the path is actually a file
    if not os.path.isfile(file_path):
        log("File was not found: " + file_path)
        return Response("404 NOT FOUND", "text/plain", "No such file: " + url_path)

    # Finally, attempt to read data from the file, and return it
    try:
        with open(file_path, "rb") as f: # "rb" mode means read "raw bytes"
            data = f.read()

        # Extract the extension from the file path and make it lowercased
        # Format taken from https://docs.python.org/3/library/os.path.html
        ext = os.path.splitext(file_path)[1].lower()

        # Assign mime-types according to its found extension
        # Reference from https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
        if ext in ['.html', '.htm']:
            mime_type = 'text/html'
        elif ext in ['.jpg', '.jpeg']:
            mime_type = 'image/jpeg'
        elif ext == '.png':
            mime_type = 'image/png'
        elif ext == '.txt':
            mime_type = 'text/plain'
        elif ext == '.css':
            mime_type = 'text/css'
        elif ext == '.js':
            mime_type = 'text/javascript'
        elif ext == '.mp3':
            mime_type = 'audio/mpeg'

        return Response("200 OK", mime_type, data)
    except:
        log("Error encountered reading from file")
        return Response("403 FORBIDDEN", "text/plain", "Permission denied: " + url_path)

# handle_http_get_topics() returns a response for the GET /whisper/topics request
def handle_http_get_topics(req):
    global topic_version 

    version_number = 0  # Default to 0 if no version is specified in the request
    path_parts = req.path.split('?')  # Split the request path to separate the path from the query string

    # Validate that the request path is not empty
    if not req.path:
        log("Received an empty request path.")
        return Response("400 BAD REQUEST", "text/plain", "Invalid request path.")
    
    # Check if there is a query string present
    if len(path_parts) > 1:
        query_string = path_parts[1]  

        # If 'version=' is included in the query string, extract the version number
        if 'version=' in query_string:
            try:
                # Split the query string to get the current version and attempt to convert it to an integer
                version_value = query_string.split('version=', 1)[1].split('&')[0]
                version_number = int(version_value)  # Convert the version to an integer
            except ValueError:
                # Log an error if conversion fails, and default to version 0
                log("Invalid version number requested. Defaulting to 0.")
    
    with topics_lock:  
        # Wait until the requested version number is updated
        while version_number > topic_version:
            log(f"Client requested version {version_number}, but server has version {topic_version}. Waiting...")
            topics_lock.wait()  
        
        # Build the response with the current topic version
        response = f'{topic_version}\n'
        
        for topic in topics:
            response += f'{topic.message_count} {topic.like_count} {topic.name}\n' 
        
    return Response("200 OK", "text/plain", response)

# Helper function to add a new topic to the list of topics if it does not already exist
def add_topic_if_needed(topic_name):
    global topic_version

    with topics_lock:
        # Check if the topic already exists in the 'topics' list
        for topic in topics:
            if topic.name == topic_name:
                return topic  

        # Create a new Topic if not found and add and log it to the topics list
        new_topic = Topic(topic_name)
        topics.append(new_topic)  
        log(f"Created new topic: {topic_name}") 

        # Increment the global topic version to update the topics and notify all threads of this change
        topic_version += 1 
        topics_lock.notify_all()  

        return new_topic

# handle_http_get_feed() returns a response for the GET /whisper/feed request
def handle_http_get_feed(req):
    global topics 

    # Split the request path into path and query string parts
    path_parts = req.path.split('?')
    
    # Check if the request path contains no parts after being split by '?' and ensure 
    # that the first part (the path) contains at least 4 segments when split by '/'
    if len(path_parts) < 1 or len(path_parts[0].split('/')) < 4:
        return Response("400 BAD REQUEST", "text/plain", "Invalid request format.")
    
    # Get the topic name from the path
    topic_name = path_parts[0].split('/')[3] 
    
    # Initialize version number to 0 and update if provided in the query
    version_number = 0
    if len(path_parts) > 1 and 'version=' in path_parts[1]:
        # Attempt to extract and convert the version number from the query string
        try:
            version_value = path_parts[1].split('version=')[1].split('&')[0]
            version_number = int(version_value)  # Convert to integer
        except ValueError:
            log("Invalid version number requested. Defaulting to 0.")
    
    # Locate the requested topic in the global topics list
    requested_topic = None
    for topic in topics:
        if topic.name == topic_name:
            requested_topic = topic
            break
        
    # Return a 404 response if the topic doesn't exist
    if not requested_topic:
        return Response("404 NOT FOUND", "text/plain", "Topic not found.")

    with requested_topic.lock:  # Lock this topic 
        # Wait until the requested version is available
        while version_number > requested_topic.version_num:
            log(f"Client requested version {version_number} for topic '{topic_name}', but has {requested_topic.version_num}. Waiting...")
            requested_topic.lock.wait()

        # Build the response with current version number and subsequent messages
        response = f'{requested_topic.version_num}\n'

        for message in requested_topic.messages:
            response += f'- {message}\n'

    return Response("200 OK", "text/plain", response)  

# handle_http_post_messages() returns a response for the POST /whisper/messages request
def handle_http_post_messages(req):
    # Split the request body into lines and strip any leading/trailing whitespace
    # Split method learned from here: https://www.geeksforgeeks.org/python-string-methods/
    lines = req.body.strip().split('\n')
    
    # Ensure that there are exactly two lines in the request body
    if len(lines) != 2:
        return Response("400 BAD REQUEST", "text/plain", "Invalid request format. Expected two lines.")

    # Get the first line containing tags and the second line containing the message
    tags_line = lines[0].strip()  
    message_line = lines[1].strip() 
    
    # Make sure that the tags and messages start with the correct prefixes
    if not tags_line.startswith("tags... ") or not message_line.startswith("message... "):
        return Response("400 BAD REQUEST", "text/plain", "Invalid format for tags or message.")

    # Extracts tags (after the first 7 characters) and messages (after the first 9 characters)
    # into a list and trims the whitespace
    tags = tags_line[7:].strip().split() 
    message = message_line[9:].strip() 

    # Check if the extracted message is empty, and handle accordingly
    if not message:
        return Response("200 OK", "text/plain", "Empty messages are ignored.")

    # Use a default tag if no tags are provided
    if not tags:
        tags = ["#default"]  
        log("No tags provided. Using default tag: #default")

    # Process each tag by adding the topic if it doesn't exist and appending the message
    for tag in tags:
        topic = add_topic_if_needed(tag)
        
        with topic.lock:                  
            topic.message_count += 1    

            # Add the message to the topic's messages
            topic.messages.append(message)  
            topic.version_num += 1      

            # Increment the global topic_version and notify all waiting threads that a new message was added
            global topic_version  
            topic_version += 1              
            topics_lock.notify_all()      

    log(f"Received message: '{message}' with tags: {tags}")

    return Response("200 OK", "text/plain", "Message received successfully.")

# handle_http_post_like() returns a response for the POST /whisper/like request
def handle_http_post_like(req):
    # Extract the topic name from the request path
    path_parts = req.path.split('/')

    # Make sure that there isn't more than 3 parts in the request path
    if len(path_parts) < 4:
        return Response("400 BAD REQUEST", "text/plain", "Invalid request format.")
    
    # Get the topic from the path
    topic_name = path_parts[3]  

    # Find the requested topic
    with topics_lock:
        requested_topic = None
        for topic in topics:
            if topic.name == topic_name:
                requested_topic = topic
                break

        if not requested_topic:
            return Response("404 NOT FOUND", "text/plain", "Topic not found.")

        # Increment the like count
        requested_topic.like_count += 1
        
        # Increment the global topic version and notify all threads on the change
        global topic_version
        topic_version += 1
        topics_lock.notify_all()

    return Response("200 OK", "text/plain", "success")

# handle_http_get() returns an appropriate response for a GET request
def handle_http_get(req, conn):
    # Check for the User-Agent header first
    user_agent = get_header_value(req.headers, "User-Agent")
    
    # Check if the User-Agent indicates Firefox on macOS
    if user_agent and "Firefox" in user_agent and "Macintosh" in user_agent:
        # Create and return a response indicating that the browser is not supported
        msg = '<html>'
        msg += '<head>'
        msg += '<title>Unsupported Browser</title></head><body>'
        msg += '<h1>Sorry, your browser is not supported.</h1>'
        msg += f'<p><strong>Your browser information:</strong> {user_agent}</p>'
        msg += '<p>Please consider using a different browser for the optimal experience.</p>'
        msg += '</body></html>'
        return Response("400 BAD REQUEST", "text/html", msg)

    # Generate a response
    if req.path == "/status":
        resp = handle_http_get_status(conn)
    elif req.path == "/whoami":
        resp = handle_http_get_whoami(req, conn)
    # Handle whisper topics and feed requests
    elif req.path.startswith("/whisper/topics"):
        resp = handle_http_get_topics(req)
    elif req.path.startswith("/whisper/feed"):
        resp = handle_http_get_feed(req)
    # Proceed with the following when "/hello" is requested alone or with user data
    elif "/hello" in req.path:
        # Protect the name, favcolor, and visit_counter global variables
        with my_lock: 
            global name, favcolor, visit_counter

            # Proceed if the URL contains data to be parsed and used
            if req.path != "/hello": 
                # Extract the username and favcolor elements of the URL
                _, extracted = req.path.split("?", 1)

                # Parse the query string using parse_qs (since it results in a key-value pair of what we need)
                # Taken from https://docs.python.org/3/library/urllib.parse.html
                query_string = urllib.parse.parse_qs(extracted)
                
                # Assign the user data from username to global name if it exists
                if query_string.get("username", []):  
                    name = query_string.get("username", [])[0]
                    log("User's Name: " + name)
                
                # Assign the favorite color from Color to global favcolor if it exists
                if query_string.get("Color", []):
                    favcolor = query_string.get("Color", [])[0] 
                    log("Favorite Color: " + favcolor)
            else: 
                # Initialize the visit_counter only if this is the first visit
                if visit_counter <= 1: 
                    name = ""
                    favcolor = ""
            resp = handle_http_get_hello(req, conn)
    elif req.path == "/quote":
        resp = handle_http_get_quote()
    # Change the path to end with "/index.html" if it is only "GET /"
    elif req.path == "/":
        resp = handle_http_get_file("/index.html")
    # Change the path to end with "/index.html" if it ends with "/"
    elif req.path.endswith("/"):
        resp = handle_http_get_file(req.path + "index.html")
    # Check if the path is a directory and doesn't end with "/"
    # Taken from https://docs.python.org/3/library/os.path.html
    elif os.path.isdir(server_root + req.path):
        resp = handle_http_get_file(req.path + "/index.html")
    else:
        resp = handle_http_get_file(req.path)
    return resp

# handle_http_connection() reads one or more HTTP requests from a client, parses
# each one, and sends back appropriate responses to the client.
def handle_http_connection(conn):
    with stats.lock: # update overall server statistics
        stats.active_connections += 1
    log("Handling connection from " + str(conn.client_addr))
    try:
        # Process one HTTP request from client
        start = time.time()
        handle_one_http_request(conn)
        end = time.time()
        duration = end - start

        # Do end-of-request statistics and cleanup
        conn.num_requests += 1 # counter for this connection
        log("Done handling request %d from %s" % (conn.num_requests, conn.client_addr))
        with stats.lock: # update overall server statistics
            stats.num_requests += 1
            stats.tot_time = stats.tot_time + duration
            stats.avg_time = stats.tot_time / stats.num_requests
            if duration > stats.max_time:
                stats.max_time = duration
    finally:
        conn.sock.close()
        log("Done with connection from " + str(conn.client_addr))
        with stats.lock: # update overall server statistics
            stats.active_connections -= 1


# This remainder of this file is the main program, which listens on a server
# socket for incoming connections from clients, and starts a handler thread for
# each one.

# Get command-line parameters
if len(sys.argv) not in [3, 4]:
    print("This program expects 2 or 3 arguments.")
    print("  python3 webserver.py  SERVER_HOSTNAME  SERVER_PORTNUM [SERVER_ROOT_DIR]")
    print("For example:")
    print("  python3 webserver.py  localhost  8888")
    print("  python3 webserver.py  127.0.0.1  8000")
    print("  python3 webserver.py  logos.holycross.edu  9001")
    print("  python3 webserver.py  192.133.83.134  8765")
    print("The optional last argument specifies the server root directory:")
    print("  python3 webserver.py  localhost  8123  ./testing/my_files/")
    print("If the last argument is omitted, then '" + server_root + "'")
    print("  will be used as the server root directory.")
    sys.exit(1)
server_host = sys.argv[1]
server_port = int(sys.argv[2])
if len(sys.argv) >= 4:
    server_root = sys.argv[3]

# Ensure root path has a slash at the end
server_root = os.path.normpath(server_root + '/')

# Determine the IP address for listening
if isTypicalIPv4Address(server_host):
    server_ip = server_host
else:
    try:
        short_name = server_host.split('.')[0]
        server_ip = socket.gethostbyname(short_name)
    except:
        print("Could not determine IP address for listening.")
        sys.exit(1)

# Print a welcome message
log("Starting web server.")
log(f"Serving files from directory {server_root}")
log(f"Attempting to listen at IP address {server_ip} port {server_port}")

# Create the server welcoming socket, and set it up to listen for connections
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_addr = (server_ip, server_port)
s.bind(server_addr)
s.listen(5)

log("Server can be accessed at URLs such as:")
log(f"    http://{server_host}:{server_port}/")
log(f"    http://{server_host}:{server_port}/welcome.html")
log(f"    http://{server_host}:{server_port}/status.html")
log("Ready for connections...")

try:
    # Repeatedly accept and handle connections
    while True:
        sock, client_addr = s.accept()
        # A new client socket connection has been accepted. Count it.
        with stats.lock:
            stats.total_connections += 1
        # Put the info into a Connection object.
        conn = Connection(sock, client_addr)
        # Start a thread to handle the new connection.
        t = threading.Thread(target=handle_http_connection, args=(conn,))
        t.daemon = True
        t.start()
finally:
    log("Shutting down...")
    s.close()

log("Done")
