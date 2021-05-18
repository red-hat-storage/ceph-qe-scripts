"""
s3cmd auth file
"""


from configparser import RawConfigParser
import os
from pathlib import Path
import shutil


def create_s3cfg_file():
    """
    Creates s3cfg file from sample file
    """
    shutil.copy('s3cfg_sample', 's3cfg')

def update_s3cfg_file(user_info, ip_and_port):
    """
    Updates s3cfg file with passed values
    Args:
        user_info(dict): User Information
        ip_and_port(str): RGW ip and port in <ip>:<port> forma
    """
    parser = RawConfigParser()
    parser.read('s3cfg')
    parser.set('default', 'access_key', user_info['access_key'])
    parser.set('default', 'secret_key', user_info['secret_key'])
    parser.set('default', 'host_base', ip_and_port)
    parser.set('default', 'host_bucket', ip_and_port)
    website_endpoint = parser.get('default', 'website_endpoint')
    endpoint = website_endpoint.replace('RGW_IP', ip_and_port.split(':')[0])
    parser.set('default', 'website_endpoint', endpoint)
    with open('s3cfg', 'w') as file:
        parser.write(file)

def copy_to_home_directory():
    """
    Copies s3cfg file to home directory as .s3cfg
    """
    shutil.copy('s3cfg', str(Path.home()) + '/' + '.s3cfg')


def do_auth(user_info, ip_and_port):
    """
    Performs steps for s3 authentication
    Args:
        user_info(dict): User Information
        ip_and_port(str): RGW ip and port in <ip>:<port> format
    """
    create_s3cfg_file()
    update_s3cfg_file(user_info, ip_and_port)
    copy_to_home_directory()
