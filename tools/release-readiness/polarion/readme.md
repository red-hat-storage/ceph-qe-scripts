# Polarion report generation by tiers

## Installation 
-----------------------------



Install packages using requirement.txt<br>
```
    pip install -r requirements.txt 
```

## Configure the pylero
-----------------------------

For configure pylero , Go to config/config.yml file and change with respective details.
```
    url:
    svn_repo: 
    user: 
    password: 
    default_project: 
```
if you dont want share above credentials, follow givin documentation<br>
https://github.com/RedHatQE/pylero<br>
note: remove first line of main.py file "import setup"
## Requirements
_________________
```
    python_version > '3.5'
    pygsheets = 2.0.5
    gspread
```

## Configure the Google APIs for gspread and pygsheets
______
Read the documentation which provided in below link <br>
Enable Google APIs<br>
https://docs.gspread.org/en/latest/oauth2.html#enable-api-access-for-a-project<br>
Make sure to create service account <br>
https://docs.gspread.org/en/latest/oauth2.html#for-bots-using-service-account
<br><br>

`Note :- You will receive a client email after completing an above process, share your sheet with client email `

## How to use
_______________________

<ol>
    <li> Go to 'Config/config.yml'</li>
    <li> Change the below fields, As per your need</li>

```
    project_id: # Your project id 
    file_name: # Filename which you shared
    key: # like Tags or Tier (Make sure key is as same as in polarion)
    tags: # list of tags/Attributes example ['Tier1','Tier2]
    filter: {
    Automation: {
        keys: # example "caseautomation.KEY",
        labels: # example ["Total Automated","Not Automated","Manual Only"],
        values: # example ['automated','notautomated','manualonly']
    }
    }
    GS_CREDENTIALS: # JSON file which you downloaded in ' Configure the Google APIs for gspread and pygsheets'
```
<li>Run First_run.py</li>

```
    python3 First_run.py
```

`
Note: Go to your library files -> pygsheets -> chart.py and check for "# Chart customized version
"
if Not there then 
manual Move replace_file/chart.py to your pygsheets library <br>
example:
    For local env :- /usr/lib/python3.6/site-packages/pygsheets
    For venv :- ~/venv/lib/python3.6/site-packages/pygsheets
    Location of custom chart.py :- replace_file/chart.py
`
<li>Run Main.py file</li>

```
    python3 main.py
```

</ol>
