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


def transform(alerts, options, DATPTOKEN, MSSCTOKEN, GRAPHTOKEN):
    '''
    First, merge all alerts from the time period of one machine
    into a single event
    '''
    if options.verbose:
        print("U) Processing DATP Events ...")
    if len(alerts) > 0:
        entityList = []
        machineNames = dict()
        for alert in alerts:
            alertId = alert['AlertId']
            machineName = alert['MachineName']
            if not machineName in machineNames:
                machineNames[machineName] = set()
            machineNames[machineName].add(alertId)
        for machineName in machineNames:
            entityTime = str(datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
            actors = set()
            hostnames = set()
            ipv4s = set()
            ipv6s = set()
            md5s = set()
            sha1s = set()
            sha256s = set()
            threatNames = set()
            urls = set()
            remediations = set()
            categories = set()
            severities = set()
            detectionSources = set()
            handles = set()
            files = set()
            logonUsers = set()
            titles = set()
            for alertId in machineNames[machineName]:
                for alert in alerts:
                    if alertId == alert['AlertId']:
                        if alert['Actor']:
                            actors.add(alert['Actor'])
                        if 'alertTime' in alert:
                            alertTime = alert['alertTime'].split('.')[0]
                            if alertTime < entityTime:
                                entityTime = alertTime
                        if alert['AlertTitle']:
                            titles.add(alert['AlertTitle'].lower())
                        if alert['Category']:
                            categories.add(alert['Category'].lower())
                        if alert['ComputerDnsName']:
                            hostnames.add(alert['ComputerDnsName'].lower())
                        '''
                        Currently no easy way to go from SAMname to email,
                        because Microsoft doesn't index OnPremisesSamAccountName

                        deviceid = alert['DeviceID']
                        logonUsers = queryLogonUsers(deviceid,
                                                     options,
                                                     MSSCTOKEN,
                                                     GRAPHTOKEN)
                        '''
                        if alert['InternalIPv4List']:
                            ips = alert['InternalIPv4List'].split(';')
                            if isinstance(ips, list):
                                for ipv4 in ips:
                                    ipv4s.add(ipv4)
                            else:
                                ipv4s.add(ips)
                        if alert['InternalIPv6List']:
                            ips = alert['InternalIPv6List'].split(';')
                            if isinstance(ips, list):
                                for ipv6 in ips:
                                    ipv6s.add(ipv6)
                            else:
                                ipv6s.add(ips)
                        if alert['IpAddress']:
                            ips = alert['IpAddress'].split(';')
                            if isinstance(ips, list):
                                for ip in ips:
                                    if ip != None:
                                        try:
                                            socket.inet_aton(ip)
                                            ipv4s.add(ip)
                                        except socket.error:
                                            pass
                                        try:
                                            socket.inet_pton(socket.AF_INET6, ip)
                                            ipv6s.add(ip)
                                        except socket.error:
                                            pass
                            else:
                                if ips != None:
                                    try:
                                        socket.inet_aton(ips)
                                        ipv4s.add(ips)
                                    except socket.error:
                                        pass
                                    try:
                                        socket.inet_pton(socket.AF_INET6, ips)
                                        ipv6s.add(ips)
                                    except socket.error:
                                        pass
                        if alert['Url']:
                            for url in alert['Url'].split(';'):
                                urls.add(url)
                        if alert['Md5']:
                            md5s.add(alert['Md5'])
                        if alert['Sha1']:
                            sha1s.add(alert['Sha1'])
                        if alert['Sha256']:
                            sha256s.add(alert['Sha256'])
                        if alert['RemediationAction']:
                            remediations.add(alert['RemediationAction']+'d')
                        if alert['Severity']:
                            severities.add(alert['Severity'].lower())
                        if alert['Source']:
                            detectionSources.add(alert['Source'])
                        if alert['ThreatName']:
                            threatNames.add(alert['ThreatName'])
                        if alert['LogOnUsers']:
                            handles.add(alert['LogOnUsers'].lower())
                        if alert['FileName'] and alert['FilePath']:
                            files.add(alert['FilePath']+'\\'+alert['FileName'])
            '''
            All machine information collected, now build the EclecticIQ
            entity with all relevant information
            '''
            entity = eiqjson.EIQEntity()
            if ('low' or 'medium' or 'high') in severities:
                entity.set_entity(entity.ENTITY_INCIDENT)
                eventType = 'Incident'
            else:
                entity.set_entity(entity.ENTITY_SIGHTING)
                eventType = 'Sighting'
            entity.set_entity_source(settings.EIQSOURCE)
            entity.set_entity_observed_time(entityTime + 'Z')
            entity.set_entity_confidence(entity.CONFIDENCE_HIGH)
            entity.set_entity_tlp('amber')
            for hostname in hostnames:
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
            for ip in ipv4s:
                eiqtype = entity.OBSERVABLE_IPV4
                classification = entity.CLASSIFICATION_UNKNOWN
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      ip,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for ip in ipv6s:
                eiqtype = entity.OBSERVABLE_IPV6
                classification = entity.CLASSIFICATION_UNKNOWN
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      ip,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for url in urls:
                eiqtype = entity.OBSERVABLE_URI
                classification = entity.CLASSIFICATION_UNKNOWN
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      url,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for md5 in md5s:
                eiqtype = entity.OBSERVABLE_MD5
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      md5,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for sha1 in sha1s:
                eiqtype = entity.OBSERVABLE_SHA1
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      sha1,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for sha256 in sha256s:
                eiqtype = entity.OBSERVABLE_SHA256
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      sha256,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for actor in actors:
                eiqtype = entity.OBSERVABLE_ACTOR
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_OBSERVED
                entity.add_observable(eiqtype,
                                      actor,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for threatName in threatNames:
                eiqtype = entity.OBSERVABLE_MALWARE
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_OBSERVED
                entity.add_observable(eiqtype,
                                      threatName,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for handle in handles:
                eiqtype = entity.OBSERVABLE_HANDLE
                classification = entity.CLASSIFICATION_UNKNOWN
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      handle,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            for file in files:
                eiqtype = entity.OBSERVABLE_FILE
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      file,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            if logonUsers:
                for handle in logonUsers:
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
            if len(handles) == 0:
                handles.add('unknown')
            title = hostname + ': '
            if len(threatNames) == 0:
                threatName = 'Behaviour'
            else:
                threatName = ', '.join(threatNames)
            title += threatName + ' - '
            allTitles = ', '.join(titles)
            if 'suspicious connection' in allTitles:
                title += 'suspicious connections - '
            if 'port scan' in allTitles:
                title += 'port scanning - '
            if len(remediations) == 0:
                status = 'detected'
            else:
                status = ', '.join(remediations)
            title += 'Status: ' + status + ' - ' + settings.TITLETAG
            entity.set_entity_title(title)
            description = '<h1>Description of ' + eventType + '</h1>'
            description += '<table style="border: 1px solid black;">'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'Threat(s)'
            description += '</th>'
            for threatName in threatNames:
                description += '<tr>'
                description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
                description += 'padding: 4px; text-align: left;">'
                description += threatName
                description += '</td></tr>'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'File(s)'
            description += '</th>'
            for file in files:
                description += '<tr>'
                description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
                description += 'padding: 4px; text-align: left;">'
                description += file
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
            description += 'Investigation State(s)'
            description += '</th>'
            for investigationState in remediations:
                description += '<tr>'
                description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
                description += 'padding: 4px; text-align: left;">'
                description += investigationState
                description += '</td></tr>'
            description += '</table>'
            entity.set_entity_description(description)
            uuid = str(machineName) + '-DATP'
            entityList.append((entity, uuid))
    return(entityList)


def queryLogonUsers(DeviceID, options, MSSCTOKEN, GRAPHTOKEN):
    '''
    Attempt to find the system
    '''
    apiheaders = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + MSSCTOKEN
    }
    url = settings.MSSCURL
    url += '/machines?$filter=id+eq+\'' + DeviceID + '\''
    if options.verbose:
        print("U) Contacting " + url + " ...")
    sslcontext = ssl.create_default_context()
    if not settings.MSSCSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for MSSC, " +
                  "this is not recommended!")
        sslcontext.check_hostname = False
        sslcontext.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=apiheaders)
    try:
        machineId = None
        response = urllib.request.urlopen(req, context=sslcontext)
        jsonResponse = json.loads(response.read().decode('utf-8'))['value']
        if options.verbose:
            print("U) Got a MSSC JSON response package:")
            pprint.pprint(jsonResponse)
        machineId = jsonResponse[0]['aadDeviceId']
    except urllib.error.HTTPError:
        pass
    if machineId:
        '''
        Attempt to find the users for the system
        '''
        apiheaders = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + MSSCTOKEN
        }
        url = settings.MSSCURL
        url += '/machines/' + machineId + '/logonusers'
        if options.verbose:
            print("U) Contacting " + url + " ...")
        sslcontext = ssl.create_default_context()
        if not settings.MSSCSSLVERIFY:
            if options.verbose:
                print("W) You have disabled SSL verification for MSSC, " +
                      "this is not recommended!")
            sslcontext.check_hostname = False
            sslcontext.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=apiheaders)
        try:
            users = []
            response = urllib.request.urlopen(req, context=sslcontext)
            jsonResponse = json.loads(response.read().decode('utf-8'))['value']
            if options.verbose:
                print("U) Got a MSSC JSON response package:")
                pprint.pprint(jsonResponse)
            for logonUser in jsonResponse:
                accountName = logonUser['accountName'].lower()
                domainName = logonUser['accountDomain'].lower()
                for key in settings.MSSCADMAPPING:
                    addomain = settings.MSSCADMAPPING[key]
                    if domainName == addomain:
                        email = accountName + '@' + key
                        users.append(queryUser(email, options, GRAPHTOKEN))
            return(users)
        except urllib.error.HTTPError:
            pass


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
        addomain = settings.MSSCADMAPPING[emaildomain].lower()
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
        return (jsonResponse, AADTOKEN)
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
    alerts, DATPTOKEN = download(args)
    if alerts:
        MSSCTOKEN = graph.generateMSSCToken(args, settings)
        GRAPHTOKEN = graph.generateGraphToken(args, settings)
        if MSSCTOKEN and GRAPHTOKEN:
            entities = transform(alerts, args, DATPTOKEN, MSSCTOKEN, GRAPHTOKEN)
            if entities:
                for entity, uuid in entities:
                    if args.verbose:
                        print("U) EIQ JSON entity generated:")
                        print(entity.get_as_json())
                    eiqIngest(entity.get_as_json(), uuid, args)


if __name__ == "__main__":
    main()
