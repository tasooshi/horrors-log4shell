#!/usr/bin/env python3

from horrors import (
    scenarios,
    services,
)


if __name__ == "__main__":
    story = scenarios.Scenario()
    httpd = services.HTTPCollector(story)
    httpd.add_route('/', ['GET'], '<html><head><title>horrors-log4shell</title></head><body><h1>Welcome</h1><hr></body></html>')
    httpd.add_route('/collect/', ['GET', 'POST'], httpd.collect)
    story.set_debug()
    story.play()
