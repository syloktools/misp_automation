#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This script uses the CIRCL NSRL webservice located here: https://circl.lu/services/hashlookup/

import sys
import time
import syslog
import json
import logging
import requests

from pymisp import ExpandedPyMISP, MISPObject, MISPEvent, MISPAttribute, MISPOrganisation, MISPServer
from keys import misp_url, misp_key, misp_verifycert
if misp_verifycert is False:
  import urllib3
  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, debug=False)
logfile = "/var/log/misp/nsrl_curate.log"
logger = logging.getLogger('nsrl_curate')
logger.setLevel(logging.DEBUG)
ch = logging.FileHandler(logfile,mode='a')
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

def nsrl_curate(misp, misp_type, logger):
  search_result = misp.search(controller='attributes', type_attribute=misp_type , published=False, to_ids=1, pythonify=True)
  for attribute in search_result:
        if attribute.type == 'sha256':
            hashinfo = requests.get('https://hashlookup.circl.lu/lookup/sha256/' + attribute.value)
            json_hashinfo = json.loads(hashinfo.text)
            if 'source' in json_hashinfo:
                if json_hashinfo['source'] == 'NSRL':
                    print(hashinfo.text)
                    new_comment = json_hashinfo['FileName']
                    attribute.to_ids = False
                    attribute.comment = new_comment
                    misp.tag(attribute, "NSRL")
                    misp.update_attribute(attribute)
                    logger.debug("Disabled to_ids on attribute {} - timestamp {} in event {} - Added NSRL tag and FileName as comment".format(attribute.value, attribute.timestamp,attribute.event_id))
                    sighting = {"value": attribute.value,"type":1, "source":"NSRL"}
                    misp.add_sighting(sighting)
                    logger.debug("Added negative sighting to attribute {} - timestamp {} globally.".format(attribute.value, attribute.timestamp,attribute.event_id))

        elif attribute.type == 'sha1':
            hashinfo = requests.get('https://hashlookup.circl.lu/lookup/sha1/' + attribute.value)
            json_hashinfo = json.loads(hashinfo.text)
            if 'source' in json_hashinfo:
                if json_hashinfo['source'] == 'NSRL':
                    print(hashinfo.text)
                    new_comment = json_hashinfo['FileName']
                    attribute.to_ids = False
                    attribute.comment = new_comment
                    misp.tag(attribute, "NSRL")
                    misp.update_attribute(attribute)
                    logger.debug("Disabled to_ids on attribute {} - timestamp {} in event {} - Added NSRL tag and FileName as comment".format(attribute.value, attribute.timestamp,attribute.event_id))
                    sighting = {"value": attribute.value,"type":1, "source":"NSRL"}
                    misp.add_sighting(sighting)
                    logger.debug("Added negative sighting to attribute {} - timestamp {} globally.".format(attribute.value, attribute.timestamp,attribute.event_id))

        elif attribute.type == 'md5':
            hashinfo = requests.get('https://hashlookup.circl.lu/lookup/md5/' + attribute.value)
            json_hashinfo = json.loads(hashinfo.text)
            if 'source' in json_hashinfo:
                if json_hashinfo['source'] == 'NSRL':
                    print(hashinfo.text)
                    new_comment = json_hashinfo['FileName']
                    attribute.to_ids = False
                    attribute.comment = new_comment
                    misp.tag(attribute, "NSRL")
                    misp.update_attribute(attribute)
                    logger.debug("Disabled to_ids on attribute {} - timestamp {} in event {} - Added NSRL tag and FileName as comment".format(attribute.value, attribute.timestamp,attribute.event_id))
                    sighting = {"value": attribute.value,"type":1, "source":"NSRL"}
                    misp.add_sighting(sighting)
                    logger.debug("Added negative sighting to attribute {} - timestamp {} globally.".format(attribute.value, attribute.timestamp,attribute.event_id))


nsrl_curate(misp, ["sha1","sha256","md5"], logger)
