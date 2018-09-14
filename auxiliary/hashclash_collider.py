# from watchdog.observers import Observer
# from watchdog.events import FileSystemEventHandler
from samson.primitives.md5 import MD5
# from asyncio import Event
import tempfile
import subprocess

import logging
log = logging.getLogger(__name__)


# class Handler(FileSystemEventHandler):
#     def __init__(self, event):
#         super(self)
#         self.event = event


#     @staticmethod
#     def on_created(event):
#         if event.is_directory:

#             event.src_path


# FileSystemEventHandler
class HashClashCollider(object):
    def __init__(self, hash_clash_base_location):
        self.hash_clash_base_location = hash_clash_base_location
        #self.observer = Observer()
        self.results = []
        #self.sync_primitive = Event()
        self.hasher = MD5()
        self.hasher.pad_func = lambda x: x


    # # @staticmethod
    # def on_created(self, event):
    #     if not event.is_directory and 'coll' in event.src_path:
    #         self.results.append(event.src_path)

    #         if len(self.results) == 2:
    #             self.sync_primitive.set()


    
    def find_collision(self, p1, p2):
        tmp_dir = tempfile.TemporaryDirectory()

        log.info('Creating new directory: {}'.format(tmp_dir))

        # self.observer.schedule(self, tmp_dir, recursive=True)
        # self.observer.start()

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

        # self.sync_primitive.wait()
        # self.sync_primitive = Event()

        # self.observer.join()