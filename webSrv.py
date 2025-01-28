from flask import Flask, render_template, request
import json
import pyotp
import time
import re
import sys
import os
import logging
from logging.handlers import RotatingFileHandler
import subprocess

# Call Flask and associate it with the app
app = Flask(__name__)
app.secret_key = 'websrv' # For session

# Log message format settings.
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Log file path settings.
log_file = 'logs/app.log'

log_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
log_handler.setFormatter(log_formatter)

# Remove default handler
for handler in app.logger.handlers:
    app.logger.removeHandler(handler)

# Add new handler.
app.logger.addHandler(log_handler)

"""
Set the log level based on FLASK_ENV.
If FLASK_ENV is set to 'development', the log level is raised to DEBUG.
FLASK_ENV is configured in the webSrv.ini file.
"""
FLASK_ENV = os.getenv('FLASK_ENV', 'production')
if FLASK_ENV == 'development':
    app.logger.setLevel(logging.DEBUG)
    log_handler.setLevel(logging.DEBUG)
    app.logger.info("Development Env: Enable debug log.")
else:
    app.logger.setLevel(logging.INFO)
    log_handler.setLevel(logging.INFO)
    app.logger.info("Production env: Disable debug log")

# Log a message indicating the application startup
app.logger.info('Application startup')

def getIPaddressFromRequestHeader():
    # Retrieves the IP address from the request headers.
    app.logger.debug('Call getIPaddressFromRequestHeader')

    # Use the X-Real-IP header value as the IP address, if present.
    if request.headers.getlist("X-Real-IP"):
        x_real_ip = request.headers.getlist("X-Real-IP")
        if isinstance(x_real_ip, list):
            # Use the first value in X-Real-IP if it has multiple values.
            client_ip = x_real_ip[0].split(',')[0].replace(' ', '')
        else:
            # otherwise, use the single value.
            client_ip = x_real_ip

        app.logger.debug(f"client_ip={client_ip} (Using X-Real-IP:{x_real_ip})")

    else:
        # If X-Real-IP is not set, use the remote_addr.
        client_ip = request.remote_addr
        app.logger.debug(f"client_ip={client_ip} (Using remote_addr)")
    return(client_ip)


def run_accept_ip_one_time(client_ip, settings):
    # Collect argments for accept.py
    app.logger.debug("Call run_accept_ip_one_time")
    zone = settings["firewalld_zone"]
    service = settings["firewalld_service"]

    # Run accept.py
    try:
        subprocess.run(
            ["sudo", "./accept_ip_one_time.py", "allow", zone , service ,  client_ip],
            check=True
        )
        return True

    except subprocess.CalledProcessError as e:
        app.logger.error(f"Exec Error: {e}")
        return False

def receivePost(client_ip, settings):
    app.logger.debug("Call receiveGet")
    # default values
    error = None
    success = False

    # Prepare data for OTP generation.
    totp = pyotp.TOTP(settings["otp_key"])

    # Wait for this duration before displaying the error message, if an error occures.
    errWaitTime = 3000

    # Retrieves the OTP entered by the user.
    otp_input = request.form.get("otp")
    # Verify OTP
    if totp.verify(otp_input, valid_window=1):
        app.logger.debug("totp verify passed")
        # Wait for 1 sec to mitigate bture-force attacks.
        time.sleep(1)
        success = True
        app.logger.info("Accept: "+str(client_ip))

        if not run_accept_ip_one_time(client_ip, settings):         
            # Increase errWaitTime if an expected error occures,
            #  as the default value is short.
            errWaitTime = 30000

            error = "Unknown error occured."
            success = False
    else:
        app.logger.debug("totp verify failed")
        #  Wait for this duration before displaying the error message, if an error occures.
        time.sleep(3)
        app.logger.info("Failed: "+str(client_ip))
        error = "Authentication failed! Please try again."

    # Display HTML.
    return render_template(
        "otp_form.html",
        client_ip=client_ip,
        error=error,
        success=success,
        errWaitTime=errWaitTime
    )

def receiveGet(client_ip):
    app.logger.debug("Call receiveGet")
    return render_template(
        "otp_form.html",
        client_ip=client_ip,
    )

def createHandler(settings):
    def handler(settings=settings):
        app.logger.debug("Call handler")

        # Retrieves the IP address
        client_ip = getIPaddressFromRequestHeader()
        method = request.method

        app.logger.info("Request "+request.url+" method="+method+" client_ip="+str(client_ip))

        if method == 'GET':
            return(receiveGet(client_ip))
        elif method == 'POST':
            return(receivePost(client_ip, settings))
        return('Unexpected Error')

    handler.__name__ = endpoint
    return(handler)

# Load configuration from config.json
try:
    with open("config.json", "r") as f:
        config = json.load(f)
except FileNotFoundError:
    app.logger.error("Error: config.json not found.")
    sys.exit(1)
except json.JSONDecodeError:
    app.logger.error("Error: Invalid JSON format in config.json.")
    sys.exit(1)
except Exception as e:
    app.logger.error(f"Error: Failed to load config.json: {e}")
    sys.exit(1)

# Registering routes
app.logger.debug("Start registering routes")
for path, settings in config.items():
    app.logger.info("Regist Route:" + path)
    endpoint = "handler_get_" + re.sub(r"[/<>_?#%.-]", "_", path)
    app.add_url_rule(path, view_func=createHandler(settings), endpoint=endpoint, methods=['GET', 'POST'])

app.logger.debug("Registering complete.")


# Main
if __name__ == "__main__":
    app.run(debug=True)
