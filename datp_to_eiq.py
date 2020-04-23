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
    First, merge all alerts from the time period of one machine
    into a single event
    '''
    if options.verbose:
        print("U) Merging correlated DATP Events ...")
    if len(alerts) > 0:
        machineIds = dict()
        entityList = []
        for datpEvent in alerts:
            eventId = datpEvent['id']
            machineId = datpEvent['machineId']
            if not machineId in machineIds:
                machineIds[machineId] = set()
            machineIds[machineId].add(eventId)
        for machineId in machineIds:
            entityTime = str(datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
            assignees = set()
            categories = set()
            detectionSources = set()
            threats = set()
            investigationStates = set()
            severities = set()
            titles = set()
            handles = set()
            hostnames = set()
            machineInfo = queryMachineInformation(machineId,
                                                  options,
                                                  AADTOKEN)
            logonUsers = queryLogonUsers(machineId,
                                         options,
                                         AADTOKEN,
                                         GRAPHTOKEN)
            for eventId in machineIds[machineId]:
                for datpEvent in alerts:
                    if eventId == datpEvent['id']:
                        '''
                        Now grab all related fields from all events
                        '''
                        if 'alertCreationTime' in datpEvent:
                            alertCreationTime = datpEvent['alertCreationTime'].split('.')[0]
                            if alertCreationTime < entityTime:
                                entityTime = alertCreationTime
                        if 'category' in datpEvent:
                            categories.add(datpEvent['category'])
                        if 'detectionSource' in datpEvent:
                            detectionSources.add(datpEvent['detectionSource'])
                        if 'assignedTo' in datpEvent:
                            if datpEvent['assignedTo']:
                                assignees.add(datpEvent['assignedTo'])
                        if 'relatedUser' in datpEvent:
                            if datpEvent['relatedUser']:
                                userName = datpEvent['relatedUser']['userName'].lower()
                                domainName = datpEvent['relatedUser']['domainName'].lower()
                                handle = domainName + '\\' + userName
                                handles.add(handle)
                        if 'investigationState' in datpEvent:
                            if datpEvent['investigationState']:
                                investigationStates.add(datpEvent['investigationState'])
                        if 'severity' in datpEvent:
                            if datpEvent['severity']:
                                severities.add(datpEvent['severity'])
                        if 'title' in datpEvent:
                            if datpEvent['title']:
                                titles.add(datpEvent['title'].lower())
                        if 'threatFamilyName' in datpEvent:
                            if datpEvent['threatFamilyName']:
                                threats.add(datpEvent['threatFamilyName'])
            '''
            All machine information collected, now build the EclecticIQ
            entity with all relevant information
            '''
            entity = eiqjson.EIQEntity()
            if 'active malware detected' in titles or \
               'hacktool was detected' in titles or \
               'an active ' in titles:
                eventType = 'Incident'
                entity.set_entity(entity.ENTITY_INCIDENT)
            elif 'malware detected' in titles:
                eventType = 'Incident'
                entity.set_entity(entity.ENTITY_INCIDENT)
            else:
                eventType = 'Sighting'
                entity.set_entity(entity.ENTITY_SIGHTING)
            entity.set_entity_tlp('amber')
            entity.set_entity_source(settings.EIQSOURCE)
            entity.set_entity_observed_time(entityTime + 'Z')
            if 'High' in severities:
                entity.set_entity_confidence(entity.CONFIDENCE_HIGH)
            elif 'Informational' in severities:
                entity.set_entity_confidence(entity.CONFIDENCE_LOW)
            else:
                entity.set_entity_confidence(entity.CONFIDENCE_MEDIUM)
            for hostname in machineInfo['hostnames']:
                hostnames.add(hostname)
                eiqtype = entity.OBSERVABLE_HOST
                classification = entity.CLASSIFICATION_UNKNOWN
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      hostname,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for ip in machineInfo['ips']:
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
            for threat in threats:
                eiqtype = entity.OBSERVABLE_MALWARE
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      threat,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for handle in handles:
                eiqtype = entity.OBSERVABLE_HANDLE
                classification = entity.CLASSIFICATION_UNKNOWN
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      threat,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for logonUser in logonUsers:
                for handle in logonUser['handle']:
                    handles.add(handle)
                    eiqtype = entity.OBSERVABLE_HANDLE
                    classification = entity.CLASSIFICATION_UNKNOWN
                    confidence = entity.CONFIDENCE_HIGH
                    link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                    entity.add_observable(eiqtype,
                                          handle,
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
                for email in logonUser['mail']:
                    eiqtype = entity.OBSERVABLE_EMAIL
                    classification = entity.CLASSIFICATION_UNKNOWN
                    confidence = entity.CONFIDENCE_HIGH
                    link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                    entity.add_observable(eiqtype,
                                          email,
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
                for number in logonUser['telephone']:
                    eiqtype = entity.OBSERVABLE_TELEPHONE
                    classification = entity.CLASSIFICATION_UNKNOWN
                    confidence = entity.CONFIDENCE_HIGH
                    link_type = entity.OBSERVABLE_LINK_OBSERVED
                    entity.add_observable(eiqtype,
                                          number.replace(' ', ''),
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
            if len(assignees) == 0:
                assignees.add('nobody')
            title = hostname + ': '
            if len(threats) > 0:
                title += 'Threats: ' + ', '.join(threats)
            else:
                threats.add('Potential malware')
                title += 'Potential malware'
            title += ' detected - ' + settings.TITLETAG
            entity.set_entity_title(title)
            description = '<h1>Description of ' + eventType + '</h1>'
            description += '<table style="border: 1px solid black;">'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'Threat(s)'
            description += '</th>'
            for threat in threats:
                description += '<tr>'
                description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
                description += 'padding: 4px; text-align: left;">'
                description += threat
                description += '</td></tr>'
            description += '</table>'
            description += '<br />'
            description += '<table style="border: 1px solid black;">'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'Detection Source(s)'
            description += '</th>'
            for detectionSource in detectionSources:
                description += '<tr>'
                description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
                description += 'padding: 4px; text-align: left;">'
                description += detectionSource
                description += '</td></tr>'
            description += '</table>'
            description += '<br />'
            description += '<table style="border: 1px solid black;">'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'Machine(s)'
            description += '</th>'
            for hostname in hostnames:
                description += '<tr>'
                description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
                description += 'padding: 4px; text-align: left;">'
                description += hostname
                description += '</td></tr>'
            description += '</table>'
            description += '<br />'
            description += '<table style="border: 1px solid black;">'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'System User(s)'
            description += '</th>'
            for handle in handles:
                description += '<tr>'
                description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
                description += 'padding: 4px; text-align: left;">'
                description += handle
                description += '</td></tr>'
            description += '</table>'
            description += '<br />'
            description += '<table style="border: 1px solid black;">'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'Investigator(s)'
            description += '</th>'
            for investigator in assignees:
                description += '<tr>'
                description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
                description += 'padding: 4px; text-align: left;">'
                description += investigator
                description += '</td></tr>'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'Investigation State(s)'
            description += '</th>'
            for investigationState in investigationStates:
                description += '<tr>'
                description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
                description += 'padding: 4px; text-align: left;">'
                description += investigationState
                description += '</td></tr>'
            description += '</table>'
            entity.set_entity_description(description)
            uuid = str(machineId) + str(entityTime) + '-DATP'
            entityList.append((entity, uuid))
    return(entityList)


def queryUser(email, options, GRAPHTOKEN):
    person = {'handle': set(),
              'mail': set(),
              'telephone': set()}
    emailuser, emaildomain = email.split('@')
    sslcontext = ssl.create_default_context()
    if not settings.GRAPHSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for Graph, " +
                  "this is not recommended!")
        sslcontext.check_hostname = False
        sslcontext.verify_mode = ssl.CERT_NONE
    uri = settings.GRAPHURL + '/users/%s' % email
    uri += '?$select=OnPremisesSamAccountName,'
    uri += 'mail,'
    uri += 'businessPhones,mobilePhone'
    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer %s' % GRAPHTOKEN,
    }
    request = urllib.request.Request(uri, headers=headers)
    response = urllib.request.urlopen(request, context=sslcontext)
    jsonResponse = json.loads(response.read().decode('utf-8'))
    if 'onPremisesSamAccountName' in jsonResponse:
        addomain = settings.DATPADMAPPING[emaildomain].lower()
        userName = jsonResponse['onPremisesSamAccountName'].lower()
        handle = addomain + '\\' + userName
        person['handle'].add(handle)
    if 'mail' in jsonResponse:
        person['mail'].add(jsonResponse['mail'])
    if 'businessPhones' in jsonResponse:
        if jsonResponse['businessPhones']:
            numbers = jsonResponse['businessPhones']
            if isinstance(numbers, list):
                for number in numbers:
                    person['telephone'].add(number)
            else:
                person['telephone'].add(numbers)
    if 'mobilePhone' in jsonResponse:
        if jsonResponse['mobilePhone']:
            numbers = jsonResponse['mobilePhone']
            if isinstance(numbers, list):
                for number in numbers:
                    person['telephone'].add(number)
            else:
                person['telephone'].add(numbers)
    return(person)
    '''
    Take the resulting DATP JSON objects and turn all alerts
    into a list of EIQ objects.
    '''

def queryLogonUsers(machineId, options, AADTOKEN, GRAPHTOKEN):
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
        users = []
        response = urllib.request.urlopen(req, context=sslcontext)
        jsonResponse = json.loads(response.read().decode('utf-8'))['value']
        if options.verbose:
            print("U) Got a DATP JSON response package:")
            pprint.pprint(jsonResponse)
        for logonUser in jsonResponse:
            accountName = logonUser['accountName'].lower()
            domainName = logonUser['accountDomain'].lower()
            for key in settings.DATPADMAPPING:
                addomain = settings.DATPADMAPPING[key]
                if domainName == addomain:
                    email = accountName + '@' + key
                    users.append(queryUser(email, options, GRAPHTOKEN))
        return(users)
    except:
        raise


def queryMachineInformation(machineId, options, AADTOKEN):
    '''
    Get the system information
    '''
    apiheaders = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + AADTOKEN
    }
    url = settings.DATPAPPIDURL + '/machines/' + machineId
    req = urllib.request.Request(url, headers=apiheaders)
    ips = set()
    machineInfo = {'ips': set(),
                   'hostnames': set(),
                   'firstSeen': 'unknown',
                   'lastSeen': 'unknown',
                   'isAadJoined': False,
                   'osInfo': 'unknown',
                   'machineId': machineId}
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
        jsonResponse = json.loads(response.read().decode('utf-8'))
        if options.verbose:
            print("U) Got a DATP JSON response package:")
            pprint.pprint(jsonResponse)
        if 'computerDnsName' in jsonResponse:
            machineInfo['hostnames'].add(jsonResponse['computerDnsName'])
        if 'lastIpAddress' in jsonResponse:
            machineInfo['ips'].add(jsonResponse['lastIpAddress'])
        if 'lastExternalIpAddress' in jsonResponse:
            machineInfo['ips'].add(jsonResponse['lastExternalIpAddress'])
        if 'isAadJoined' in jsonResponse:
            if jsonResponse['isAadJoined']:
                machineInfo['isAadJoined'] = True
        if 'firstSeen' in jsonResponse:
            machineInfo['firstSeen'] = jsonResponse['firstSeen']
        if 'lastSeen' in jsonResponse:
            machineInfo['lastSeen'] = jsonResponse['lastSeen']
        if 'osPlatform' in jsonResponse:
            if jsonResponse['osPlatform']:
                machineInfo['osInfo'] = 'OS: ' + str(jsonResponse['osPlatform'])
        if 'osBuild' in jsonResponse:
            if jsonResponse['osBuild']:
                machineInfo['osInfo'] += ', build: '+str(jsonResponse['osBuild'])
        if 'version' in jsonResponse:
            if jsonResponse['osVersion']:
                machineInfo['osInfo'] += ', version: '+str(jsonResponse['version'])
    except urllib.error.HTTPError:
        if options.verbose:
            print("U) Could not IP information for " + machineId + '!')
        raise
    return(machineInfo)


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
