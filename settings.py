import logging


# LOGGING
console_log_level = logging.INFO
file_log_level = logging.INFO
save_logs_to_file = False

# REQUESTS
# if the Plextrac instance is running on https without valid certs, requests will respond with cert error
# change this to false to override verification of certs
verify_ssl = True
# number of times to rety a request before throwing an error. will only throw the last error encountered if
# number of retries is exceeded. set to 0 to disable retrying requests
retries = 0

# description of script that will be print line by line when the script is run
script_info = ["====================================================================",
               "= Writeup Export to CSV                                            =",
               "=------------------------------------------------------------------=",
               "= This script will export all writeups in a writeups repository    =",
               "= to a CSV. The CSV will have the same schema Plextrac uses to     =",
               "= import writeups to a repository.                                 =",
               "=                                                                  =",
               "===================================================================="
            ]
