#!/usr/bin/env python3

# (c) 2020 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>

# This software is GPLv2 licensed, except where otherwise indicated

import argparse
import datetime
import json
import pprint
import socket
import time
import requests
import urllib

from eiqlib import eiqjson
from eiqlib import eiqcalls

from config import settings


def transform(alerts, options):
    '''
    Take the DATP JSON object, extract all attributes into a list.
    '''
    if options.verbose:
        print("U) Converting DATP Events into EIQ incidents ...")
    try:
        if len(alerts) > 0:
            entityList = []
            for datpEvent in alerts:
                eventID = datpEvent['id']
                entity = eiqjson.EIQEntity()
                entity.set_entity(entity.ENTITY_INCIDENT)
                entity.set_entity_source(settings.EIQSOURCE)
                tlp = 'amber'
                reliability = 'B'
                if 'alertCreationTime' in datpEvent:
                    observedtime = datpEvent['alertCreationTime'].split('.')[0]
                    observedtime += 'Z'
                entity.set_entity_tlp(tlp)
                entity.set_entity_reliability(reliability)
                if 'category' in datpEvent:
                    category = datpEvent['category']
                else:
                    category = 'unknown category'
                if 'detectionSource' in datpEvent:
                    detectionSource = datpEvent['detectionSource']
                else:
                    detectionSource = 'unknown detection source'
                if datpEvent['assignedTo']:
                    assignedTo = datpEvent['assignedTo']
                else:
                    assignedTo = 'nobody'
                if datpEvent['relatedUser']:
                    domainName = datpEvent['relatedUser']['domainName']
                    userName = datpEvent['relatedUser']['userName']
                    handle = 'the ' + domainName + '\\' + userName
                    eiqtype = entity.OBSERVABLE_HANDLE
                    classification = entity.CLASSIFICATION_UNKNOWN
                    confidence = entity.CONFIDENCE_HIGH
                    link_type = entity.OBSERVABLE_LINK_OBSERVED
                    entity.add_observable(eiqtype,
                                          name,
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
                else:
                    handle = 'an unknown'
                if 'computerDnsName' in datpEvent:
                    computerDnsName = datpEvent['computerDnsName']
                    eiqtype = entity.OBSERVABLE_HOST
                    classification = entity.CLASSIFICATION_UNKNOWN
                    confidence = entity.CONFIDENCE_HIGH
                    link_type = entity.OBSERVABLE_LINK_OBSERVED
                    entity.add_observable(eiqtype,
                                          computerDnsName,
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
                else:
                    computerDnsName = 'an unknown system'
                if datpEvent['machineId']:
                    machineId = datpEvent['machineId']
                if datpEvent['investigationState']:
                    investigationState = datpEvent['investigationState']
                if datpEvent['threatFamilyName']:
                    threatFamilyName = datpEvent['threatFamilyName']
                    eiqtype = entity.OBSERVABLE_MALWARE
                    classification = entity.CLASSIFICATION_BAD
                    confidence = entity.CONFIDENCE_HIGH
                    link_type = entity.OBSERVABLE_LINK_OBSERVED
                    #link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                    entity.add_observable(eiqtype,
                                          threatFamilyName,
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
                else:
                    threatFamilyName = 'an unknown threat type'
                title = datpEvent['title'] + ' on ' + computerDnsName
                description = detectionSource + ' detected a(n) '
                description += category + ' event caused by '
                description += threatFamilyName + ', '
                description += 'performed by ' + handle + ' user.'
                description += '<br /><br />'
                description += detectionSource + ' action: '
                description += investigationState + '<br />'
                description += 'Assigned to: ' + assignedTo
                description += '<br /><br />'
                description += datpEvent['description'].replace('\n','<br />')
                entity.set_entity_title(title + " - Event " +
                                        str(eventID) + " - " +
                                        settings.TITLETAG)
                entity.set_entity_observed_time(observedtime)
                entity.set_entity_description(description)
                entity.set_entity_confidence(entity.CONFIDENCE_MEDIUM)
                if 'severity' in datpEvent:
                    if datpEvent['severity'] == 'Informational':
                        entity.set_entity_confidence(entity.CONFIDENCE_LOW)
                    if datpEvent['severity'] == 'High':
                        entity.set_entity_confidence(entity.CONFIDENCE_HIGH)
                uuid = str(eventID) + '-DATP'
                entityList.append((entity, uuid))
            return entityList
        else:
            if options.verbose:
                print("E) An empty result or other error was returned by " +
                      "DATP. Enable verbosity to see the JSON result that " +
                      "was returned.")
    except KeyError:
        print("E) An empty JSON result or other error was returned " +
              "by DATP:")
        print(alerts)
        raise


def eiqIngest(eiqJSON, uuid, options):
    '''
    Ingest the provided eiqJSON object into EIQ with the UUID provided
    (or create a new entity if not previously existing)
    '''
    if options.simulate:
        if options.verbose:
            print("U) Not ingesting anything into EIQ because the " +
                  "-s/--simulate flag was set.")
        return False

    if not settings.EIQSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for EIQ, " +
                  "this is not recommended.")

    eiqAPI = eiqcalls.EIQApi(insecure=not(settings.EIQSSLVERIFY))
    url = settings.EIQHOST + settings.EIQVERSION
    eiqAPI.set_host(url)
    eiqAPI.set_credentials(settings.EIQUSER, settings.EIQPASS)
    token = eiqAPI.do_auth()
    try:
        if options.verbose:
            print("U) Contacting " + url + ' to ingest ' + uuid + ' ...')
        if not options.duplicate:
            response = eiqAPI.create_entity(eiqJSON, token=token,
                                            update_identifier=uuid)
        else:
            response = eiqAPI.create_entity(eiqJSON, token=token)
    except IOError:
        raise
    if not response or ('errors' in response):
        if response:
            for err in response['errors']:
                print('[error %d] %s' % (err['status'], err['title']))
                print('\t%s' % (err['detail'], ))
        else:
            print('unable to get a response from host')
        return False
    else:
        return response['data']['id']


def download(options):
    '''
    Download the given DATP Event number from DATP
    '''
    try:
        '''
        Generate a token first
        '''
        if options.verbose:
            print("U) Generating DATP Access Token ...")

        body = {
            'resource' : settings.DATPRESOURCEIDURL,
            'client_id' : settings.DATPAPPID,
            'client_secret' : settings.DATPAPPSECRET,
            'grant_type' : 'client_credentials'
        }

        data = urllib.parse.urlencode(body).encode("utf-8")
        req = urllib.request.Request(settings.DATPTOKENURL, data)
        response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read().decode('utf-8'))
        aadToken = jsonResponse["access_token"]
    except:
        if options.verbose:
            print("E) Error generating DATP access token!")
            raise
    try:
        '''
        Download DATP Alerts
        '''
        if options.verbose:
            print("U) Downloading DATP Alerts ...")

        alerturl = settings.DATPAPPIDURL
        apiheaders = {
            'Content-Type' : 'application/json',
            'Accept' : 'application/json',
            'Authorization' : 'Bearer ' + aadToken
        }
        filter = 'alertCreationTime+gt+'
        endtime = int(time.time())
        starttime = endtime - (int(options.window))
        iso8601time = (datetime.datetime.utcfromtimestamp(
                       starttime).strftime("%Y-%m-%dT%H:%M:%SZ"))
        filter += iso8601time
        url = alerturl + "?$filter=" + filter
        if not settings.DATPSSLVERIFY:
            if options.verbose:
                print("W) You have disabled SSL verification for DATP, " +
                      "this is not recommended!")
            urllib3.disable_warnings()
        if options.verbose:
            print("U) Contacting " + url + " ...")
        req = urllib.request.Request(url, headers=apiheaders)
        response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read().decode('utf-8'))
        if options.verbose:
            print("U) Got a DATP JSON response package:")
            pprint.pprint(jsonResponse)
        return jsonResponse['value']
    except IOError:
        if options.verbose:
            print("E) An error occured downloading DATP alerts!")
        raise


def main():
    parser = argparse.ArgumentParser(description='DATP to EIQ converter')
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true',
                        default=False,
                        help='[optional] Enable progress/error info (default: disabled)')
    parser.add_argument('-w', '--window',
                        dest='window',
                        default=settings.DATPTIME,
                        help='[optional] Override time window of DATP alerts to '
                             'download, specified in seconds. Default setting '
                             'from config file is: '+str(settings.DATPTIME))
    parser.add_argument('-s', '--simulate',
                        dest='simulate',
                        action='store_true',
                        default=False,
                        help='[optional] Do not actually ingest anything into '
                             'EIQ, just simulate everything. Mostly useful with '
                             'the -v/--verbose flag.')
    parser.add_argument('-n', '--name',
                        dest='name',
                        default=settings.TITLETAG,
                        help='[optional] Override the default TITLETAG name from '
                             'the configuration file (default: TITLETAG in'
                             'settings.py)')
    parser.add_argument('-d', '--duplicate',
                        dest='duplicate',
                        action='store_true',
                        default=False,
                        help='[optional] Do not update the existing EclecticIQ '
                             'entity, but create a new one (default: disabled)')
    args = parser.parse_args()
    alerts = download(args)
    if alerts:
        entities = transform(alerts, args)
        if entities:
            for entity, uuid in entities:
                if args.verbose:
                    print(entity.get_as_json())
                eiqIngest(entity.get_as_json(), uuid, args)


if __name__ == "__main__":
    main()
