from samson.hashes.md5 import MD5
import tempfile
import subprocess

import logging
log = logging.getLogger(__name__)



class HashClashCollider(object):
    def __init__(self, hash_clash_base_location):
        self.hash_clash_base_location = hash_clash_base_location
        self.hasher = MD5()
        self.hasher.pad_func = lambda x: x


    
    def find_collision(self, p1, p2):
        tmp_dir = tempfile.TemporaryDirectory()

        log.info('Creating new directory: {}'.format(tmp_dir))

        p1_tmp = tempfile.NamedTemporaryFile(dir=tmp_dir.name)
        p2_tmp = tempfile.NamedTemporaryFile(dir=tmp_dir.name)

        # Write chosen-prefixes to temp files
        with open(p1_tmp, 'wb') as f:
            f.write(p1)

        with open(p2_tmp, 'wb') as f:
            f.write(p1)

        command = 'cd {} && {}/scripts/cpc.sh {} {}'.format(tmp_dir.name, self.hash_clash_base_location, p1_tmp.name, p2_tmp.name)
        log.info('Executing: {}'.format(command))
        process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)

        for line in iter(process.stdout.readline, b''):
            log.debug(line)


        # Read crafted values from files
        with open(p1_tmp + '.coll', 'rb') as f:
            p1_suffix = f.read()[len(p1):]

        with open(p2_tmp + '.coll', 'rb') as f:
            p2_suffix = f.read()[len(p2):]


        return p1_suffix, p2_suffix, self.hasher.hash(p1 + p1_suffix)