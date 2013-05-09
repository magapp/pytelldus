#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, getopt, httplib, urllib, json, os
import oauth.oauth as oauth
from configobj import ConfigObj

PUBLIC_KEY = ''
PRIVATE_KEY = ''

TELLSTICK_TURNON = 1
TELLSTICK_TURNOFF = 2
TELLSTICK_BELL = 4
TELLSTICK_DIM = 16
TELLSTICK_UP = 128
TELLSTICK_DOWN = 256

SUPPORTED_METHODS = TELLSTICK_TURNON | TELLSTICK_TURNOFF | TELLSTICK_BELL | TELLSTICK_DIM | TELLSTICK_UP | TELLSTICK_DOWN;

def listDevices():
    response = doRequest('devices/list', {'supportedMethods': SUPPORTED_METHODS})
    print("Number of devices: %i" % len(response['device']));
    for device in response['device']:
        if (device['state'] == TELLSTICK_TURNON):
            state = 'ON'
        elif (device['state'] == TELLSTICK_TURNOFF):
            state = 'OFF'
        elif (device['state'] == TELLSTICK_DIM):
            state = "DIMMED"
        elif (device['state'] == TELLSTICK_UP):
            state = "UP"
        elif (device['state'] == TELLSTICK_DOWN):
            state = "DOWN"
        else:
            state = 'Unknown state'

        print("%s\t%s\t%s" % (device['id'], device['name'], state));

def doMethod(deviceId, methodId, methodValue = 0):
    response = doRequest('device/info', {'id': deviceId})

    if (methodId == TELLSTICK_TURNON):
        method = 'on'
    elif (methodId == TELLSTICK_TURNOFF):
        method = 'off'
    elif (methodId == TELLSTICK_BELL):
        method = 'bell'
    elif (methodId == TELLSTICK_UP):
        method = 'up'
    elif (methodId == TELLSTICK_DOWN):
        method = 'down'

    if ('error' in response):
        name = ''
        retString = response['error']
    else:
        name = response['name']
        response = doRequest('device/command', {'id': deviceId, 'method': methodId, 'value': methodValue})
        if ('error' in response):
            retString = response['error']
        else:
            retString = response['status']

    if (methodId in (TELLSTICK_TURNON, TELLSTICK_TURNOFF)):
        print("Turning %s device %s, %s - %s" % ( method, deviceId, name, retString));
    elif (methodId in (TELLSTICK_BELL, TELLSTICK_UP, TELLSTICK_DOWN)):
        print("Sending %s to: %s %s - %s" % (method, deviceId, name, retString))
    elif (methodId == TELLSTICK_DIM):
        print("Dimming device: %s %s to %s - %s" % (deviceId, name, methodValue, retString))


def doRequest(method, params):
    global config
    consumer = oauth.OAuthConsumer(PUBLIC_KEY, PRIVATE_KEY)
    token = oauth.OAuthToken(config['token'], config['tokenSecret'])

    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, token=token, http_method='GET', http_url="http://api.telldus.com/json/" + method, parameters=params)
    oauth_request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), consumer, token)
    headers = oauth_request.to_header()
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    conn = httplib.HTTPConnection("api.telldus.com:80")
    conn.request('GET', "/json/" + method + "?" + urllib.urlencode(params, True).replace('+', '%20'), headers=headers)

    response = conn.getresponse()
    return json.load(response)

def requestToken():
    global config
    consumer = oauth.OAuthConsumer(PUBLIC_KEY, PRIVATE_KEY)
    request = oauth.OAuthRequest.from_consumer_and_token(consumer, http_url='http://api.telldus.com/oauth/requestToken')
    request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), consumer, None)
    conn = httplib.HTTPConnection('api.telldus.com:80')
    conn.request(request.http_method, '/oauth/requestToken', headers=request.to_header())

    resp = conn.getresponse().read()
    token = oauth.OAuthToken.from_string(resp)
    print 'Open the following url in your webbrowser:\nhttp://api.telldus.com/oauth/authorize?oauth_token=%s\n' % token.key
    print 'After logging in and accepting to use this application run:\n%s --authenticate' % (sys.argv[0])
    config['requestToken'] = str(token.key)
    config['requestTokenSecret'] = str(token.secret)
    saveConfig()

def getAccessToken():
    global config
    consumer = oauth.OAuthConsumer(PUBLIC_KEY, PRIVATE_KEY)
    token = oauth.OAuthToken(config['requestToken'], config['requestTokenSecret'])
    request = oauth.OAuthRequest.from_consumer_and_token(consumer, token=token, http_method='GET', http_url='http://api.telldus.com/oauth/accessToken')
    request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), consumer, token)
    conn = httplib.HTTPConnection('api.telldus.com:80')
    conn.request(request.http_method, request.to_url(), headers=request.to_header())

    resp = conn.getresponse()
    if resp.status != 200:
        print 'Error retreiving access token, the server replied:\n%s' % resp.read()
        return
    token = oauth.OAuthToken.from_string(resp.read())
    config['requestToken'] = None
    config['requestTokenSecret'] = None
    config['token'] = str(token.key)
    config['tokenSecret'] = str(token.secret)
    print 'Authentication successful, you can now use tdtool'
    saveConfig()

def authenticate():
    try:
        opts, args = getopt.getopt(sys.argv[1:], '', ['authenticate'])
        for opt, arg in opts:
            if opt in ('--authenticate'):
                getAccessToken()
                return
    except getopt.GetoptError:
        pass
    requestToken()

def saveConfig():
    global config
    try:
        os.makedirs(os.environ['HOME'] + '/.config/Telldus')
    except:
        pass
    config.write()


if __name__ == "__main__":
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-l", "--list", action="store_true", help="List configured devices.")
    parser.add_option("-n", "--on", metavar="DEVICE_ID", help="Turn on device with id DEVICE_ID.")
    parser.add_option("-f", "--off", metavar="DEVICE_ID", help="Turn off device with id DEVICE_ID.")
    parser.add_option("-d", "--dim", metavar="DEVICE_ID", help="Dim device with id DEVICE_ID.  Used in combination with --dimlevel.")
    parser.add_option("-L", "--dimlevel", metavar="LEVEL", help="Set dim level. LEVEL is an integer between 0 and 255. Used in combination with --dim.")
    parser.add_option("--bell", metavar="DEVICE_ID", help="Sends bell command to device with id DEVICE_ID, if supported by the device.")
    parser.add_option("--up", metavar="DEVICE_ID", help="Sends up command to device with id DEVICE_ID, if supported by device.")
    parser.add_option("--down", metavar="DEVICE_ID", help="Sends down command to device with id DEVICE_ID, if supported by device.")
    parser.add_option("--public-key", help="Set the API public key.")
    parser.add_option("--private-key", help="Set the API public key.")

    (options, args) = parser.parse_args()
    PUBLIC_KEY = options.public_key
    PRIVATE_KEY = options.private_key


    global config
    config = ConfigObj(os.environ['HOME'] + '/.config/Telldus/tdtool.conf')

    if ('token' not in config or config['token'] == ''):
        authenticate()
        sys.exit(1)

    if options.list:
        listDevices()
    elif options.on:
        doMethod(options.on, TELLSTICK_TURNON)
    elif options.off:
        doMethod(options.off, TELLSTICK_TURNOFF)
    elif options.bell:
        doMethod(options.bell, TELLSTICK_BELL)
    elif options.dim:
        if not options.dimlevel:
            print >> sys.stderr, "Dim level must be specified with --dimlevel with --dim"
            sys.exit(1)
        doMethod(options.dim, TELLSTICK_DIM, options.dimlevel)
    elif options.up:
        doMethod(options.up, TELLSTICK_UP)
    elif options.down:
        doMethod(options.down, TELLSTICK_DOWN)

