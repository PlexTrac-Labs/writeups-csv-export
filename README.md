# writeup-csv-export
This Python script is designed for interacting with the writeupsDB in Plextrac. It will export all writeups in a selected Writeups Repository to a CSV. The CSV export feature allows for easy backups, bulk updates via re-import, and data transfer between Plextrac repositories.

### De-Duplication Issue
While writeup repositories allow multiple writeups with the same name, the writeup CSV import process currently de-duplicates writeups on import. If you try to import a CSV with multiple rows sharing the same title, only the last row will be added as a writeup.

### Important Consideration for CSV Re-Import: Custom Fields
Note that the writeup custom fields are integral to Plextrac's CSV schema during the import process. Each custom field column in the CSV corresponds to the addition of a custom field for every writeup created through the import. It's essential to be cautious during re-import, especially when dealing with repositories where not all writeups share the same set of custom fields. This script exports all custom fields for each writeup, which, if not consistent across the repository, may result in the addition of blank custom fields during re-import. Refer to the example below to understand how this could impact the re-import process.

#### Original Writeup Repository in Plextrac
 - Writeup 1
   - Custom Impact Field
 - Writeup 2
   - Custom Exploitability Field

#### CSV Created from Original Repository
```
title     | ... | Custom Impact Field | Custom Exploitability Field | ...
Writeup 1 | ... | impact value        |                             | ...
Writeup 2 | ... |                     | exploitability value        | ...
```

#### Writeup Repository from Imported CSV
 - Writeup 1
   - Custom Impact Field
   - Custom Exploitability Field
 - Writeup 2
   - Custom Impact Field
   - Custom Exploitability Field

# Requirements
- [Python 3+](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [pipenv](https://pipenv.pypa.io/en/latest/)

# Installing
After installing Python, pip, and pipenv, run the following commands to setup the Python virtual environment.
```bash
git clone this_repo
cd path/to/cloned/repo
pipenv install
```

# Setup
After setting up the Python environment the script will run in, you will need to setup a few things to configure the script before running.

## Credentials
In the `config.yaml` file you should add the full URL to your instance of Plextrac.

The config also can store your username and password. Plextrac authentication lasts for 15 mins before requiring you to re-authenticate. The script is set up to do this automatically through the authentication handler. If these 3 values are set in the config, and MFA is not enabled for the user, the script will take those values and authenticate automatically, both initially and every 15 mins. If any value is not saved in the config, you will be prompted when the script is run and during re-authentication.

# Usage
After setting everything up you can run the script with the following command. You should run the command from the folder where you cloned the repo.
```bash
pipenv run python main.py
```
You can also add values to the `config.yaml` file to simplify providing the script with custom parameters needed to run.

## Required Information
The following values can either be added to the `config.yaml` file or entered when prompted for when the script is run.
- PlexTrac Top Level Domain e.g. https://yourapp.plextrac.com
- Username
- Password

## Script Execution Flow
- Authenticates user to provided instance of Plextrac
- Pulls writeup repository data from your instance
- Prompts user to select a writeups repository to export to CSV
- Pulls all writeup information from selected repository
- Parses writeup data and saves in CSV 
