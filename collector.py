#!/usr/bin/env python3

import io
import os

from flask import send_file
import requests

from horrors import scenarios
from horrors.services.utility import collector


if __name__ == "__main__":

    story = scenarios.Scenario()

    httpd = collector.HTTPCollector(story)
    httpd.add_route('/', ['GET'], '<html><head><title>horrors-log4shell</title></head><body><h1>Welcome</h1><hr></body></html>')
    httpd.add_route('/collect/', ['GET', 'POST'], httpd.collect)

    story.set_debug()
    story.play()
