#!/usr/bin/env python3

# (c) 2020 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>

# This software is GPLv2 licensed, except where otherwise indicated

import argparse
import datetime
import json
import pprint
import time
import ssl
import urllib
import socket

from eiqlib import eiqjson
from eiqlib import eiqcalls

from graphlib import graph

from config import settings


def transform(alerts, options, AADTOKEN, GRAPHTOKEN):
    '''
    Take the DATP JSON object, extract all attributes into a list.
    '''
    if options.verbose:
        print("U) Converting DATP Events into EIQ incidents ...")
    try:
        if len(alerts) > 0:
            entityList = []
            for datpEvent in alerts:
                handles = []
                eventID = datpEvent['id'].split('_')[0]
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
                    category = datpEvent['category'].lower()
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
                if datpEvent['machineId']:
                    machineId = datpEvent['machineId']
                if datpEvent['relatedUser']:
                    domainName = datpEvent['relatedUser']['domainName'].lower()
                    accountName = datpEvent['relatedUser']['userName'].lower()
                    if domainName in settings.DATPADMAPPING:
                        email = accountName + '@' + settings.DATPADMAPPING[domainName]
                        sslcontext = ssl.create_default_context()
                        uri = settings.GRAPHURL + '/users/%s' % email
                        uri += '?$select=OnPremisesSamAccountName,'
                        uri += 'mail,'
                        uri += 'businessPhones,mobilePhone'
                        headers = {
                            'Content-type': 'application/json',
                            'Accept': 'application/json',
                            'Authorization': 'Bearer %s' % GRAPHTOKEN,
                        }
                        request = urllib.request.Request(uri,
                                                     headers=headers)
                        if not settings.GRAPHSSLVERIFY:
                            sslcontext.check_hostname = False
                            sslcontext.verify_mode = ssl.CERT_NONE
                        response = urllib.request.urlopen(request,
                                                          context=sslcontext)
                        jsonResponse = json.loads(response.read().decode('utf-8'))
                        confidence = entity.CONFIDENCE_HIGH
                        if 'onPremisesSamAccountName' in jsonResponse:
                            eiqtype = entity.OBSERVABLE_HANDLE
                            link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                            classification = entity.CLASSIFICATION_UNKNOWN
                            handle = domain + '\\' + jsonResponse['onPremisesSamAccountName']
                            entity.add_observable(eiqtype,
                                                  handle,
                                                  classification=classification,
                                                  confidence=confidence,
                                                  link_type=link_type)
                            if 'mail' in jsonResponse:
                                eiqtype = entity.OBSERVABLE_EMAIL
                                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                                classification = entity.CLASSIFICATION_UNKNOWN
                                mail = jsonResponse['mail']
                                entity.add_observable(eiqtype,
                                                      mail,
                                                      classification=classification,
                                                      confidence=confidence,
                                                      link_type=link_type)
                            phones = []
                            if 'businessPhones' in jsonResponse:
                                if jsonResponse['businessPhones']:
                                    numbers = jsonResponse['businessPhones']
                                    if isinstance(numbers, list):
                                        for number in numbers:
                                            phones.append(number)
                                    else:
                                        phones.append(number)
                            if 'mobilePhone' in jsonResponse:
                                if jsonResponse['mobilePhone']:
                                    numbers = jsonResponse['mobilePhone']
                                    if isinstance(numbers, list):
                                        for number in numbers:
                                            phones.append(number)
                                    else:
                                        phones.append(number)
                            if len(phones) > 0:
                                for number in phones:
                                    eiqtype = entity.OBSERVABLE_TELEPHONE
                                    link_type = entity.OBSERVABLE_LINK_OBSERVED
                                    classification = entity.CLASSIFICATION_UNKNOWN
                                    entity.add_observable(eiqtype,
                                                          number,
                                                          classification=classification,
                                                          confidence=confidence,
                                                          link_type=link_type)
                    else:
                        handle = domainName + '\\' + accountName
                        handles.append((handle, ('unknown type')))
                        eiqtype = entity.OBSERVABLE_HANDLE
                        classification = entity.CLASSIFICATION_UNKNOWN
                        confidence = entity.CONFIDENCE_HIGH
                        link_type = entity.OBSERVABLE_LINK_OBSERVED
                        entity.add_observable(eiqtype,
                                              handle,
                                              classification=classification,
                                              confidence=confidence,
                                              link_type=link_type)
                else:
                    '''
                    Attempt to find the logonusers for the system
                    '''
                    apiheaders = {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'Authorization': 'Bearer ' + AADTOKEN
                    }
                    url = settings.DATPAPPIDURL + '/machines/' + machineId + '/logonusers'
                    if options.verbose:
                        print("U) Contacting " + url + " ...")
                    sslcontext = ssl.create_default_context()
                    if not settings.DATPSSLVERIFY:
                        if options.verbose:
                            print("W) You have disabled SSL verification for DATP, " +
                                  "this is not recommended!")
                        sslcontext.check_hostname = False
                        sslcontext.verify_mode = ssl.CERT_NONE
                    req = urllib.request.Request(url, headers=apiheaders)
                    try:
                        response = urllib.request.urlopen(req, context=sslcontext)
                        jsonResponse = json.loads(response.read().decode('utf-8'))['value']
                        if options.verbose:
                            print("U) Got a DATP JSON response package:")
                            pprint.pprint(jsonResponse)
                        usertypes = []
                        for item in jsonResponse:
                            accountName = item['accountName'].lower()
                            domainName = item['accountDomain'].lower()
                            for key in settings.DATPADMAPPING:
                                addomain = settings.DATPADMAPPING[key]
                                if domainName == addomain:
                                    email = accountName + '@' + key
                                    sslcontext = ssl.create_default_context()
                                    uri = settings.GRAPHURL + '/users/%s' % email
                                    uri += '?$select=OnPremisesSamAccountName,'
                                    uri += 'mail,'
                                    uri += 'businessPhones,mobilePhone'
                                    headers = {
                                        'Content-type': 'application/json',
                                        'Accept': 'application/json',
                                        'Authorization': 'Bearer %s' % GRAPHTOKEN,
                                    }
                                    request = urllib.request.Request(uri,
                                                                 headers=headers)
                                    if not settings.GRAPHSSLVERIFY:
                                        sslcontext.check_hostname = False
                                        sslcontext.verify_mode = ssl.CERT_NONE
                                    if options.verbose:
                                        print('U) Contacting ' + uri + ' ...')
                                    response = urllib.request.urlopen(request,
                                                                      context=sslcontext)
                                    jsonResponse = json.loads(response.read().decode('utf-8'))
                                    if options.verbose:
                                        print("U) Got a DATP JSON response package:")
                                        pprint.pprint(jsonResponse)
                                    confidence = entity.CONFIDENCE_HIGH
                                    if 'onPremisesSamAccountName' in jsonResponse:
                                        userName = jsonResponse['onPremisesSamAccountName']
                                        eiqtype = entity.OBSERVABLE_HANDLE
                                        link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                                        classification = entity.CLASSIFICATION_UNKNOWN
                                        handle = addomain + '\\'
                                        handle += userName.lower()
                                        entity.add_observable(eiqtype,
                                                              handle,
                                                              classification=classification,
                                                              confidence=confidence,
                                                              link_type=link_type)
                                        if 'mail' in jsonResponse:
                                            eiqtype = entity.OBSERVABLE_EMAIL
                                            link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                                            classification = entity.CLASSIFICATION_UNKNOWN
                                            mail = jsonResponse['mail']
                                            entity.add_observable(eiqtype,
                                                                  mail,
                                                                  classification=classification,
                                                                  confidence=confidence,
                                                                  link_type=link_type)
                                        phones = []
                                        if 'businessPhones' in jsonResponse:
                                            if jsonResponse['businessPhones']:
                                                numbers = jsonResponse['businessPhones']
                                                if isinstance(numbers, list):
                                                    for number in numbers:
                                                        phones.append(number)
                                                else:
                                                    phones.append(number)
                                        if 'mobilePhone' in jsonResponse:
                                            if jsonResponse['mobilePhone']:
                                                numbers = jsonResponse['mobilePhone']
                                                if isinstance(numbers, list):
                                                    for number in numbers:
                                                        phones.append(number)
                                                else:
                                                    phones.append(number)
                                        if len(phones) > 0:
                                            for number in phones:
                                                eiqtype = entity.OBSERVABLE_TELEPHONE
                                                link_type = entity.OBSERVABLE_LINK_OBSERVED
                                                classification = entity.CLASSIFICATION_UNKNOWN
                                                entity.add_observable(eiqtype,
                                                                      number,
                                                                      classification=classification,
                                                                      confidence=confidence,
                                                                      link_type=link_type)
                            if item['isDomainAdmin']:
                                usertypes.append('Domain Admin')
                            else:
                                usertypes.append('Normal User')
                            if item['isOnlyNetworkUser']:
                                usertypes.append('Only Network')
                            usertypes.append(item['logonTypes'])
                            usertype = ', '.join(usertypes)
                            handles.append((handle, (usertype)))
                    except urllib.error.HTTPError:
                        if options.verbose:
                            print("U) Machine " + machineId + ' is unknown!')
                url = settings.DATPAPPIDURL + '/machines/' + machineId
                req = urllib.request.Request(url, headers=apiheaders)
                ips = []
                machineInfo = ''
                osInfo = []
                try:
                    response = urllib.request.urlopen(req, context=sslcontext)
                    jsonResponse = json.loads(response.read().decode('utf-8'))
                    if options.verbose:
                        print("U) Got a DATP JSON response package:")
                        pprint.pprint(jsonResponse)
                    if 'lastIpAddress' in jsonResponse:
                        ips.append(jsonResponse['lastIpAddress'])
                    if 'lastExternalIpAddress' in jsonResponse:
                        ips.append(jsonResponse['lastExternalIpAddress'])
                    if 'isAadJoined' in jsonResponse:
                        if jsonResponse['isAadJoined']:
                            isAadJoined = 'yes'
                        else:
                            isAadJoined = 'unknown'
                    else:
                        isAadJoined = 'no'
                    if 'firstSeen' in jsonResponse:
                        firstSeen = jsonResponse['firstSeen']
                    else:
                        firstSeen = 'unknown'
                    if 'lastSeen' in jsonResponse:
                        lastSeen = jsonResponse['lastSeen']
                    else:
                        lastSeen = 'unknown'
                    if 'osPlatform' in jsonResponse:
                        if jsonResponse['osPlatform']:
                            osInfo.append('OS: '+str(jsonResponse['osPlatform']))
                        else:
                            osInfo.append('Unknown OS')
                    if 'osBuild' in jsonResponse:
                        if jsonResponse['osBuild']:
                            osInfo.append('Build: '+str(jsonResponse['osBuild']))
                        else:
                            osInfo.append('Unknown build')
                    if 'version' in jsonResponse:
                        if jsonResponse['osVersion']:
                            osInfo.append('Version: '+str(jsonResponse['version']))
                        else:
                            osInfo.append('Unknown version')
                    if len(osInfo) > 0:
                        systemInfo = ', '.join(osInfo)
                    else:
                        systemInfo = 'unknown'
                    machineInfo += '<b>IP addresses:</b> '
                    for ip in ips:
                        try:
                            socket.inet_aton(ip)
                            eiqtype = entity.OBSERVABLE_IPV4
                        except socket.error:
                            pass
                        try:
                            socket.inet_pton(socket.AF_INET6, ip)
                            eiqtype = entity.OBSERVABLE_IPV6
                        except socket.error:
                            pass
                        classification = entity.CLASSIFICATION_UNKNOWN
                        confidence = entity.CONFIDENCE_HIGH
                        link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                        entity.add_observable(eiqtype,
                                              ip,
                                              classification=classification,
                                              confidence=confidence,
                                              link_type=link_type)
                    machineInfo += ', '.join(ips)
                    machineInfo += '<br />'
                    machineInfo += '<b>System info:</b>' + systemInfo + '<br />'
                    machineInfo += '<b>First seen:</b> ' + firstSeen + '<br />'
                    machineInfo += '<b>Last seen:</b> ' + lastSeen + '<br />'
                    machineInfo += '<b>Azure AD joined:</b> ' + isAadJoined + '<br />'
                except urllib.error.HTTPError:
                    if options.verbose:
                        print("U) Could not IP information for " + machineId + '!')
                    raise
                if len(handles) == 0:
                    handles.append(('Unknown user', ('unknown account type')))
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
                if datpEvent['investigationState']:
                    investigationState = datpEvent['investigationState']
                if datpEvent['threatFamilyName']:
                    threatFamilyName = datpEvent['threatFamilyName']
                    eiqtype = entity.OBSERVABLE_MALWARE
                    classification = entity.CLASSIFICATION_BAD
                    confidence = entity.CONFIDENCE_HIGH
                    link_type = entity.OBSERVABLE_LINK_OBSERVED
                    entity.add_observable(eiqtype,
                                          threatFamilyName,
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
                else:
                    threatFamilyName = 'an unknown threat type'
                title = datpEvent['title'] + ' on ' + computerDnsName
                description = '<h1>Event Description</h1>'
                description += detectionSource + ' detected a(n) '
                description += category + ' event on ' + computerDnsName
                description += ' (' + machineId + ') '
                description += 'caused by ' + threatFamilyName + '.<br /><br />'
                description += '<h1>System Information</h1>'
                description += machineInfo
                description += '<br />'
                description += '<h1>System Users</h1>'
                for account in handles:
                    handle, usertype = account
                    description += handle
                    description += ' (' + usertype +')<br />'
                description += '<br />'
                description += '<h1>Performed Action(s)</h1>'
                description += detectionSource + ' action: '
                description += investigationState + '<br /><br />'
                description += '<h1>Incident Assignment</h1>'
                description += 'Assigned to: ' + assignedTo
                description += '<br /><br />'
                description += '<h1>Additional Notes</h1>'
                description += datpEvent['description'].replace('\n', '<br />')
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
            'resource': settings.DATPRESOURCEIDURL,
            'client_id': settings.DATPAPPID,
            'client_secret': settings.DATPAPPSECRET,
            'grant_type': 'client_credentials'
        }

        data = urllib.parse.urlencode(body).encode("utf-8")
        req = urllib.request.Request(settings.DATPTOKENURL, data)
        response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read().decode('utf-8'))
        AADTOKEN = jsonResponse["access_token"]
    except urllib.error.HTTPError:
        if options.verbose:
            print("E) Error generating DATP access token!")
            raise
    try:
        '''
        Download DATP Alerts
        '''
        if options.verbose:
            print("U) Downloading DATP Alerts ...")

        alerturl = settings.DATPAPPIDURL + '/alerts/'
        apiheaders = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + AADTOKEN
        }
        filter = 'alertCreationTime+gt+'
        endtime = int(time.time())
        starttime = endtime - (int(options.window))
        iso8601time = (datetime.datetime.utcfromtimestamp(
                       starttime).strftime("%Y-%m-%dT%H:%M:%SZ"))
        filter += iso8601time
        url = alerturl + "?$filter=" + filter
        if options.verbose:
            print("U) Contacting " + url + " ...")
        if not settings.DATPSSLVERIFY:
            if options.verbose:
                print("W) You have disabled SSL verification for DATP, " +
                      "this is not recommended!")
            sslcontext = ssl.create_default_context()
            sslcontext.check_hostname = False
            sslcontext.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers=apiheaders)
            response = urllib.request.urlopen(req, context=sslcontext)
        else:
            req = urllib.request.Request(url, headers=apiheaders)
            response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read().decode('utf-8'))
        if options.verbose:
            print("U) Got a DATP JSON response package:")
            pprint.pprint(jsonResponse)
        return (jsonResponse['value'], AADTOKEN)
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
    alerts, AADTOKEN = download(args)
    if alerts:
        GRAPHTOKEN = graph.generateGraphToken(args, settings)
        if GRAPHTOKEN:
            entities = transform(alerts, args, AADTOKEN, GRAPHTOKEN)
            if entities:
                for entity, uuid in entities:
                    if args.verbose:
                        print("U) EIQ JSON entity generated:")
                        print(entity.get_as_json())
                    eiqIngest(entity.get_as_json(), uuid, args)


if __name__ == "__main__":
    main()
