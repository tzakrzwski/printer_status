import json, time, re
import os.path
import concurrent.futures
import requests
import threading
from requests.exceptions import Timeout, ConnectionError, HTTPError
from json.decoder import JSONDecodeError

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]

WRITE_QUOTA_PER_MINUTE = 50

DISCOVERY_RETRY_THRESHOLD = 3

STATUS_FORMAT = [
    "name",
    "serial",
    "address",
    "api_key",
    "*", #Format last_update in pretty format
    "state",
    "job_display_name",
    "progress",
    "time_remaining",
    "time_printing"
]

STATUS_FORMAT_HEADERS = [
    "Printer Name",
    "Printer Serial Number",
    "IP Address",
    "Password",
    "Last Update",
    "Printer State",
    "Print Name",
    "Print Progress (%)",
    "Time Remaining (s)",
    "Time Printing (s)"
]

OFFLINE_STATUS_FORMAT = [
    "name",
    "serial",
    "address",
    "*", #Format last_update in pretty format
    "~", #Format State as 'Offline'
    "",
    "",
    "",
    ""
]

def convert_address(ip):
    return "".join(['.'+str(elem) for elem in ip]).removeprefix('.')


def update_headers():
    body = {"values": [STATUS_FORMAT_HEADERS]}
    try:
        result = (
            service.spreadsheets()
            .values()
            .update(
                spreadsheetId=config_options["spreadsheet_id"],
                range=config_options["sheet_name"]+"!"+header_range,
                valueInputOption="USER_ENTERED",
                body=body,
            )
            .execute()
        )
        #print(f"{result.get('updatedCells')} cells updated.")
        return result
    except HttpError as error:
        print(f"Google Sheet Error: {error}")
        return error
    except Exception as error:
        print(f"Unknown Google Sheet Error: {error}")


class Printer():

    def __init__(self, printer_info, range):
        self.name = printer_info['name']
        self.address = "0.0.0.0"
        self.api_key = printer_info['key']
        self.serial = printer_info['serial']
        self.last_update = 0
        self.range = range
        self.state = ""
        self.progress = 0
        self.time_remaining = 0
        self.time_printing = 0
        self.job_display_name = ""
        self.offline = True

        self.discover_retry_count = 0 #Number of failed get_status() before try to find address again
        self.rediscover_address_thread = threading.Thread(target=self.discover_address, daemon=True)

    def main(self):
        if time.time() - self.last_update > update_interval:
            self.get_status()
            self.post_status()

    def rediscover_address(self):
        if not self.rediscover_address_thread.is_alive():
            print(f"{self.name} Attempt rediscovery")
            self.rediscover_address_thread = threading.Thread(target=self.discover_address, daemon=True)
            self.rediscover_address_thread.start()
            return True
        else:
            print(f"{self.name} rediscovery Already in Progress")
            return False

    def discover_address(self):
        headers = {'X-Api-Key': self.api_key}
        ip = ip_range_start[:]

        while True:

            address = convert_address(ip)
            info_address = "http://"+address+"/api/v1/info"

            try:
                r = requests.get(info_address,headers=headers,timeout=0.1)
                if r.status_code == 200:
                    info_content = r.json()
                    print(f"Printer Found {address}: {info_content['serial']}")

                    if info_content['serial'] == self.serial:
                        self.address = address
                        return True

            except Timeout as error:
                pass
                #print(f"Discovery Timeout ({address}): {error}")

            except Exception as error:
                pass
                #print(f"{address}: {error}")

            if address == convert_address(ip_range_end) or address == "255.255.255.255":
                return False

            ip[3] = ip[3] + 1

            for i in range(3,-1,-1):
                if ip[i] > 255:
                    ip[i-1] = ip[i-1] + 1
                    ip[i] = 0


    def get_status(self):
        headers = {'X-Api-Key': self.api_key}

        status_address = "http://"+self.address+"/api/v1/status"
        job_address = "http://"+self.address+"/api/v1/job"

        try:
            r = requests.get(status_address, headers=headers, timeout=0.1)
            if r.status_code == 200:
                status_content = r.json()
                self.state = status_content['printer']['state']
                self.offline = False

            r = requests.get(job_address, headers=headers, timeout=0.1)
            if r.status_code == 200:
                job_content = r.json()

                try:
                    self.job_display_name = job_content['file']['display_name']
                    self.progress = status_content['job']['progress']
                    self.time_remaining = status_content['job']['time_remaining']
                    self.time_printing = status_content['job']['time_printing']
                except:
                    self.job_display_name = ""
                    self.progress = ""
                    self.time_remaining = ""
                    self.time_printing = ""


            else:
                print(self.name+": Prusa Request Bad Result Code: "+str(r.status_code))

            return True
        
        except (ConnectionError, HTTPError) as error:
            print(f"Prusa Request Error (Connection): {error}")

            self.offline = True

            if self.discover_retry_count >= DISCOVERY_RETRY_THRESHOLD:
                self.rediscover_address()
                self.discover_retry_count = 0
            else:
                self.discover_retry_count = self.discover_retry_count + 1

            return False

        except Exception as error:
            print(f"Prusa Request Error: {error}")
            self.offline = True
            return False

    def format_status(self):
        val = []
        format = STATUS_FORMAT
        if self.offline:
            format = OFFLINE_STATUS_FORMAT

        for field in format:
            if field == "*":
                val.append(
                    time.strftime(
                        "%x %X",
                        time.localtime(self.last_update)
                    )
                )
            elif field == "~":
                val.append('Offline')
            elif field == "":
                val.append("")
            else:
                val.append(getattr(self,field))
        
        return val


    def post_status(self):
        self.last_update = time.time()
        values = self.format_status()
        body = {"values": [values]}
        try:
            result = (
                service.spreadsheets()
                .values()
                .update(
                    spreadsheetId=config_options["spreadsheet_id"],
                    range=config_options["sheet_name"]+"!"+self.range,
                    valueInputOption="USER_ENTERED",
                    body=body,
                )
                .execute()
            )
            #print(f"{result.get('updatedCells')} cells updated.")
            return result
        except HttpError as error:
            print(f"Google Sheet Error: {error}")
            return error
        except Exception as error:
            print(f"Unknown Google Sheet Error: {error}")


creds = None
  # The file token.json stores the user's access and refresh tokens, and is
  # created automatically when the authorization flow completes for the first
  # time.
if os.path.exists("token.json"):
    creds = Credentials.from_authorized_user_file("token.json", SCOPES)
# If there are no (valid) credentials available, let the user log in.
if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(
            "credentials.json", SCOPES
        )
        creds = flow.run_local_server(port=0)
# Save the credentials for the next run
with open("token.json", "w") as token:
    token.write(creds.to_json())

service = build("sheets", "v4", credentials=creds)



Printer_List = []
i = 0

with open("config.json") as f:
    config_options = json.loads(f.read())
    sheet_range = config_options["range"]
    update_interval = float(config_options["update_interval"])
    ip_range_start = [int(x) for x in config_options["ip_start"].split('.')]
    ip_range_end = [int(x) for x in config_options["ip_end"].split('.')]
    add_header = config_options["add_header"]
    range_i = int(re.findall(r'^[^\d]*(\d+)',sheet_range)[0])
    pass

header_range = re.sub(r'(?<=^[A-Z])\d+',str(range_i),sheet_range)
range_i = range_i+1

with open("printer_info.json") as f:
    printer_info = json.loads(f.read())
    for p in printer_info['printers']:
        p_range = re.sub(r'(?<=^[A-Z])\d+',str(range_i),sheet_range)
        Printer_List.append(Printer(p, p_range))
        range_i = range_i+1

# Change update interval to be less than minimum for project
if (60/update_interval)*len(Printer_List) > WRITE_QUOTA_PER_MINUTE:
    print("Update Interval limited by WRITE_QUOTA_PER_MINUTE")
    update_interval = 60/(WRITE_QUOTA_PER_MINUTE/len(Printer_List))

with concurrent.futures.ThreadPoolExecutor(max_workers=len(Printer_List)) as executor:
    future_list = {executor.submit(p.discover_address): p for p in Printer_List}

if add_header == "true":
    update_headers()

print("Start Main Loop")

while True:
    for p in Printer_List:
        p.main()
            