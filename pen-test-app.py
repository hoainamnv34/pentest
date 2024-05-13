#!/usr/bin/env python

import sys
import time
import argparse
import re
import requests

from zapv2 import ZAPv2


def openZapProxy(args):
    args.zap_host = re.sub(r'^((?!http://).*)',
                           r'http://\1', args.zap_host)
    args.zap_host_ssh = re.sub(r'^((?!http?s://).*)',
                               r'https://\1', args.zap_host_ssh)

    return ZAPv2(proxies={'http': args.zap_host,
                          'https': args.zap_host_ssh})


def fetchArguments():
    parse = argparse.ArgumentParser()
    parse.add_argument('-t', '--target', help='Specify target to scan',
                       default='http://localhost:80', dest='target')
    parse.add_argument('-z', '--zap-host', help='address and port of ZAP host',
                       default='127.0.0.1:8080', dest='zap_host')
    parse.add_argument('-Z', '--zap-host-ssh',
                       help='address and port of SSH ZAP host',
                       default='localhost:8080', dest='zap_host_ssh')
    

    return parse.parse_args()

def download_file(zap_url, file_name):
    """
    Download a file from a URL constructed by combining zap_url and endpoint, and save it to disk.

    Args:
    zap_url (str): The zap URL of the server.
    file_name (str): The name of the file to save the downloaded data.

    Returns:
    bool: True if download successful, False if unsuccessful.
    """

    endpoint = "OTHER/core/other/xmlreport/"

    try:
        url = zap_url.rstrip('/') + '/' + endpoint.lstrip('/')
        response = requests.get(url)
        if response.status_code == 200:
            with open(file_name, 'wb') as file:
                file.write(response.content)
            print("File downloaded successfully!")
            return True
        else:
            print("Error: Unable to download file. Status code:", response.status_code)
            return False
    except Exception as e:
        print("Error: Unable to download file:", str(e))
        return False


def delete_site(zap_url, site_url):
    """
    Delete a site from ZAP using GET request.

    Args:
    zap_url (str): The base URL of the ZAP server.
    site_url (str): The URL of the site to be deleted.

    Returns:
    dict: JSON response from the ZAP API if successful, None otherwise.
    """

    endpoint = "JSON/core/action/deleteSiteNode/"

    url = zap_url.rstrip('/') + '/' + endpoint.lstrip('/')

    headers = {'Accept': 'application/json'}
    params = {'url': site_url}
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        print(response.status_code, params)
        return response.json()  # Return JSON response
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None





def main():
    args = fetchArguments()
    print("target ", args.target, " http: ", args.zap_host, " https: ", args.zap_host_ssh)


    zap = openZapProxy(args)

    sys.stdout.write('Accessing %s\n' % args.target)

    open_con = False

    retry=10

    while not open_con:
        try:
            res=zap.urlopen(args.target)
            print("Open connection :-)")
            open_con = True
            break
        except:
            retry -= 1
            if retry == 0:
                print(res)
                sys.exit(f'[ERROR] Cannot connect to target {args.target}')   
            print("Connection refused by the server..")
            print("Let me sleep for 5 seconds")
            print("ZZzzzz...")
            time.sleep(5)
            continue

    # Give the sites tree a chance to get updated
    time.sleep(5)

    

    print('Spidering target {}'.format(args.target))
    scanID = zap.spider.scan(args.target)

    while int(zap.spider.status(scanID)) < 100:
        # Poll the status until it completes
        print('Spider progress %: {}'.format(zap.spider.status(scanID)))
        time.sleep(1)

    print('Spider has completed!')
    # Prints the URLs the spider has crawled
    print('\n'.join(map(str, zap.spider.results(scanID))))
    num_urls = len(zap.core.urls())
    print('Total of ' + str(num_urls) + ' URLs')



    print('Active Scanning target {}'.format(args.target))
    scanID = zap.ascan.scan(args.target)
    while int(zap.ascan.status(scanID)) < 100:
    # Loop until the scanner has finished
        print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
        time.sleep(5)
    
    print('Active Scan completed')
    # Print vulnerabilities found by the scanning
    print('Hosts: {}'.format(', '.join(zap.core.hosts)))
    print('Alerts: ')
    print(zap.core.alerts())

    

    zap_url = args.zap_host
    file_name = "report.xml"
    download_file(zap_url, file_name)
    # rp = reports(zap)
    # result = rp.generate(title="ZAP Scanning Report",template= "traditional-xml", reportfilename="testtt.xml", reportdir=None)
    # print(result)


    site_url = args.target
    result = delete_site(zap_url, site_url)

    if result:
        print(result)
    else:
        print("Failed to delete site from ZAP.")




if __name__ == '__main__':
    main()
