#!/usr/bin/env python
# -*- coding: utf-8 -*-

###########################################################################
#                                                                         #
# Copyright (C) 2014 Airbus DS CyberSecurity SAS. All rights reserved.    #
# This document is the property of Cassidian CyberSecurity SAS, it may    #
# not be circulated without prior licence                                 #
#                                                                         #
###########################################################################

import argparse
import json
import os
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()


class Colors(object):
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    ORANGE = '\033[93m'
    NO = '\033[0m'

    def disable(self):
        self.RED = ''
        self.GREEN = ''
        self.BLUE = ''
        self.ORANGE = ''
        self.NO = ''


def showexec(code, status, description, exception=None):
    """
    Report a message with a pretty status display (Failed/Success) and status code
    """
    if len(description) > 65:
        description = description[0:65] + "..."

    if not status:
        status = 'Success'

    # Display the command

    statuscolor = Colors.BLUE
    if 200 <= code < 300:
        statuscolor = Colors.GREEN

    if 400 <= code or exception:
        statuscolor = Colors.RED
        status = 'Failed'

    sys.stdout.write("Status : (%s)" % (statuscolor + status + Colors.NO) + " Code : (%s) " %
                     (statuscolor + str(code) + Colors.NO) + "MSG : (%s)" % description + "\n")

    sys.stdout.flush()


def send_file(path, portal_url, visibility, session, key, tls_certificate, delete_level):
    """
    La valeur 'user' indique le login
    La valeur 'force' indique si on veut forcer une reanalyse
    """

    with open(path, 'rb') as f:
        data = f.read()

    url = portal_url + '/orion/api/v4.0/tasks'

    json_data = {
        'filename': os.path.basename(path),
        'client_version': 1,
        'visibility': visibility,
        'force': False,
        'callback_url': '',
    }

    form = {
        'json': json.dumps(json_data)
    }

    files = {
        'data': (os.path.basename(path), data)
    }

    headers = {
        'apikey': key
    }

    try:
        r = session.post(url, data=form, files=files,
                         headers=headers, verify=tls_certificate)
    except requests.exceptions.ConnectionError as e:
        sys.stderr.write("Invalid portal address. Please try again.\n")
        sys.stderr.write(f"{e}")
        return

    if r.status_code == 405 or r.status_code == 502:
        showexec(r.status_code, "Failed", "Host may be not reachable ?")
    else:

        try:
            # print(r.json())
            if 'msg' in r.json():
                showexec(r.status_code, r.json().get(
                    'status'), r.json()['msg'])
            else:
                task_id = r.json()['task']['$oid']
                # print(task_id)
                check_scan(task_id, key, portal_url,
                           session, path, delete_level)
        except Exception as ex:
            print(ex)
            showexec(r.status_code, None, r.text, exception=ex)


def delete_file(path):
    # print(f"Removing Path {path}")
    try:
        os.remove(path)
    except OSError as e:
        print("Error: %s : %s" % (path, e.strerror))
        pass


def check_scan(task_id, key, portal_url, session, path, delete_level="low"):
    """
    Vérifier l'état d'un scan et afficher le niveau de risque pour chaque résultat
    """

    url = f"{portal_url}/orion/api/v4.0/tasks/id={task_id}"
    headers = {'apikey': key, 'Content-Type': 'application/json'}
    r = session.get(url, headers=headers)
    # print(r.status_code)
    if int(r.status_code) in [200, 201]:
        # print(r.json())
        result = [r.json()['task']]
        if result:
            for file in result:
                if 'risk' in file and "global" in file['risk']:
                    risk = file['risk']['global']
                    if risk in ["Low", "Safe", "N/A"]:
                        print(
                            f"{file['filename']}: {Colors.GREEN}{risk.upper()}{Colors.NO}")
                    elif risk == "Medium":
                        print(
                            f"{file['filename']}: {Colors.ORANGE}{risk.upper()}{Colors.NO}")
                    elif risk == "High":
                        print(
                            f"{file['filename']}: {Colors.RED}{risk.upper()}{Colors.NO}")
                    elif risk == "Severe":
                        print(
                            f"{file['filename']}: {Colors.RED}{risk.upper()}{Colors.NO}")
                    if risk.lower() == delete_level.lower():
                        delete_file(path)
    else:
        showexec(r.status_code, "Failed", "Scan failed")


def orion_scan(path: str, portal_url: str, visibility: str, key: str, tls_certificate: str, delete_level):
    """
    Scan files with Orion
    """

    session = requests.Session()
    print(f"Scanning {path} files with Orion at {portal_url}")
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for i in files:
                n = os.path.join(root, i)
                try:
                    send_file(n, portal_url, visibility,
                              session, key, tls_certificate, delete_level)
                except Exception as e:
                    print("%s : %s" % (n, str(e)))
    else:
        send_file(path, portal_url, visibility, session,
                  key, tls_certificate, delete_level)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="USB Cleaner - A tool to clean USB devices from malware \nThe current version support the VirusTotal API, and Orion to scan the files. \nFollow me on Github: @sparksam")

    parser.add_argument(
        '--provider', help="Specify the Malware scanner to use: orion or virus_total", type=str, default='orion', choices=['orion', 'virus_total'])
    parser.add_argument(
        '--key', help="API key to use for provider", type=str, required=False)
    parser.add_argument(
        '--scan', help="Scan the files for malware", action='store_true')

    parser.add_argument(
        '--path', help="Path of the directory/file to scan", type=str)
    parser.add_argument(
        '--tls-certificate', help="Path to the TLS CA certificate bunde. eg: tls-certificate.pem", type=str, required=False)
    parser.add_argument('--visibility', help='Visibility of generated task(s)',
                        choices=['public', 'group', 'private'])
    parser.add_argument(
        '--format', help="Format the device", action='store_true')
    parser.add_argument(
        '--delete-malwares', help="Delete malicious files, by specifying the risk threshold.", type=str, default='low', choices=['low', 'medium', 'high', 'severe', "safe", "n/a"])
    args = parser.parse_args()
    env = Path(__file__).parent.parent / '.env'
    if env.exists():
        print(f"Environment file found at: {env}")
        for line in env.read_text().split('\n'):
            if len(line):
                k, v = [s.strip() for s in line.split('=')]
                os.environ[k] = v
    else:
        print(f"Environment file not found at: {env}")
    if args.provider == 'orion':
        portal_url = 'https://orion.cyberrange.cloud'
        orion_key = args.key if args.key else os.environ.get('ORION_KEY')
        if not orion_key:
            print("Orion API key is required")
            exit(1)
        orion_scan(args.path, portal_url,  args.visibility,
                   args.key, args.tls_certificate, args.delete_malwares)
