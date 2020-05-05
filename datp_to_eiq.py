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
        for alert in alerts:
            actor = alert['Actor']
            alertTime = alert['AlertTime'].split('.')[0]
            alertTitle = alert['AlertTitle'].lower()
            category = alert['Category']
            hostnames = set()
            if alert['ComputerDnsName']:
                hostname = alert['ComputerDnsName']
            deviceid = alert['DeviceID']
            '''
            logonUsers = queryLogonUsers(deviceid,
                                         options,
                                         MSSCTOKEN,
                                         GRAPHTOKEN)
            '''
            machineId = alert['MachineName']
            ipv4 = alert['InternalIPv4List'].split(';')
            ipv6 = alert['InternalIPv6List'].split(';')
            ipaddresses = alert['IpAddress'].split(';')
            urls = alert['Url'].split(';')
            md5 = alert['Md5']
            sha1 = alert['Sha1']
            sha256 = alert['Sha256']
            remediations = set()
            if alert['RemediationAction']:
                remediations.add(alert['RemediationAction'])
            severity = alert['Severity'].lower()
            detectionSource = alert['Source']
            threatName = alert['ThreatName']
            handles = set()
            if alert['UserName']:
                userName = alert['UserName'].lower()
            if alert['UserDomain']:
                userDomain = alert['UserDomain'].lower()
            if userName and userDomain:
                handle = userDomain + '\\' + userName
                handles.add(handle)
            entity = eiqjson.EIQEntity()
            if 'informational' in severity:
                eventType = 'Sighting'
                entity.set_entity(entity.ENTITY_SIGHTING)
            else:
                eventType = 'Incident'
                entity.set_entity(entity.ENTITY_INCIDENT)
            entity.set_entity_tlp('amber')
            entity.set_entity_source(settings.EIQSOURCE)
            entity.set_entity_observed_time(alertTime + 'Z')
            entity.set_entity_confidence(entity.CONFIDENCE_HIGH)
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
            for ip in ipv4:
                    eiqtype = entity.OBSERVABLE_IPV4
                    classification = entity.CLASSIFICATION_UNKNOWN
                    confidence = entity.CONFIDENCE_HIGH
                    link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                    entity.add_observable(eiqtype,
                                          ip,
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
            for ip in ipv6:
                    eiqtype = entity.OBSERVABLE_IPV6
                    classification = entity.CLASSIFICATION_UNKNOWN
                    confidence = entity.CONFIDENCE_HIGH
                    link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                    entity.add_observable(eiqtype,
                                          ip,
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
            if md5:
                eiqtype = entity.OBSERVABLE_MD5
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      md5,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            if sha1:
                eiqtype = entity.OBSERVABLE_SHA1
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      sha1,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            if sha256:
                eiqtype = entity.OBSERVABLE_SHA256
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                entity.add_observable(eiqtype,
                                      sha256,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            if actor:
                eiqtype = entity.OBSERVABLE_ACTOR
                classification = entity.CLASSIFICATION_BAD
                confidence = entity.CONFIDENCE_HIGH
                link_type = entity.OBSERVABLE_LINK_OBSERVED
                entity.add_observable(eiqtype,
                                      actor,
                                      classification=classification,
                                      confidence=confidence,
                                      link_type=link_type)
            if threatName:
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
            '''
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
                '''
            if len(handles) == 0:
                handles.add('unknown')
            title = hostname + ': '
            if not threatName:
                threatName = 'Potential malware'
            title += threatName
            title += ' detected - ' + settings.TITLETAG
            entity.set_entity_title(title)
            description = '<h1>Description of ' + eventType + '</h1>'
            description += '<table style="border: 1px solid black;">'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'Threat(s)'
            description += '</th>'
            description += '<tr>'
            description += '<td style="border: 1px solid black; background-color: #ffffff; color: #000000; '
            description += 'padding: 4px; text-align: left;">'
            description += threatName
            description += '</td></tr>'
            description += '</table>'
            description += '<br />'
            description += '<table style="border: 1px solid black;">'
            description += '<tr><th style="border: 1px solid black; background-color: #000000; color: #ffffff; '
            description += 'padding: 4px; text-align: center; font-weight: bold;">'
            description += 'Detection Source(s)'
            description += '</th>'
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
            uuid = str(deviceid) + '-DATP'
            entityList.append((entity, uuid))
    return(entityList)


def queryLogonUsers(DeviceID, options, MSSCTOKEN, GRAPHTOKEN):
    '''
    Attempt to find the logonusers for the system
    '''
    apiheaders = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + MSSCTOKEN
    }
    url = settings.MSSCRESOURCEAPPIDURI + '/machines?$filter=id+eq+\'' + DeviceID + '\''
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
