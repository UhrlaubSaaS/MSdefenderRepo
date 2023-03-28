import json
import os
import sys
import threading
import time
import traceback

if sys.version_info[0] < 3:
    import Queue as queue
else:
    import queue

__read_thread = None
__input_queue = None

win = sys.platform.startswith('win')
if win:
    __input_queue = queue.Queue()

# Compiled code cache
_compiled_code_cache = {}


def read_input_loop():
    global __input_queue
    while True:
        line = sys.stdin.readline()
        __input_queue.put(line)
        if line == '':
            break


def __readWhileAvailable():
    if win:
        # An ugly solution - just open a blocking thread to handle input
        global __input_queue
        global __read_thread
        if not __read_thread:
            __read_thread = threading.Thread(target=read_input_loop)
            __read_thread.daemon = True
            __read_thread.start()
        buff = ''
        # Now, read from the queue. First read we block and wait and then wait for timeout.
        buff += __input_queue.get()
        return buff
    else:
        # Wait for the first char from stdin
        buff = sys.stdin.readline()
        # While available, read all the other chars
        return buff


"""Demisto instance for scripts only"""

template_code = '''
from __future__ import print_function
import json
import uuid
import sys

SERVER_ERROR_MARKER = '[ERROR-fd5a7750-7182-4b38-90ba-091824478903]'

class Demisto:
    """Wrapper class to interface with the Demisto server via stdin, stdout"""

    def __init__(self, context):
        self.callingContext = context
        self.is_debug = False
        self._args = dict(self.callingContext.get(u'args', {}))
        if 'demisto_machine_learning_magic_key' in  self._args:
            import os
            os.environ['DEMISTO_MACHINE_LEARNING_MAGIC_KEY'] = self._args['demisto_machine_learning_magic_key']
        is_debug = self.callingContext.get('context', {}).get('IsDebug', False)
        if is_debug:
            self.is_debug = True
            self._args.pop('debug-mode', '')
        self.__stdout_lock = None
        self._stdout_lock_timeout = 60

    def enable_multithreading(self):
        from threading import Lock
        if self.__stdout_lock is None:
            self.__stdout_lock = Lock()

    def log(self, msg):
        self.__do_no_res({'type': 'entryLog', 'args': {'message': msg}})

    def investigation(self):
        return self.callingContext[u'context'][u'Inv']

    def incidents(self):
        return self.callingContext[u'context'][u'Incidents']

    def incident(self):
        return self.incidents()[0]

    def parentEntry(self):
        return self.callingContext[u'context'][u'ParentEntry']

    def context(self):
        return self.callingContext[u'context'][u'ExecutionContext']

    def args(self):
        return self._args

    def uniqueFile(self):
        return str(uuid.uuid4())

    def getFilePath(self, id):
        return self.__do({'type': 'getFileByEntryID', 'command': 'getFilePath', 'args': {'id': id}})

    def internalHttpRequest(self, method, uri, body = None):
        return self.__do({'type': 'executeCommand', 'command': 'internalHttpRequest', 'args': {'method': method, 'uri': uri, 'body': body}})

    def searchIndicators(self, value = None, query = None, size = None, page=None, fromDate = None, toDate = None, searchAfter = None, populateFields = None):
        return self.__do({'type': 'executeCommand', 'command': 'searchIndicators', 'args': {'value': value, 'query': query, 'size': size, 'page': page, 'fromDate': fromDate, 'searchAfter': searchAfter, 'toDate': toDate, 'populateFields': populateFields}})

    def getLicenseID(self):
        return self.__do({'type': 'executeCommand', 'command': 'getLicenseID', 'args': {}})['id']

    def get(self, obj, field, defaultParam=None):
        """ Get the field from the given dict using dot notation """
        parts = field.split('.')
        for part in parts:
            if obj and part in obj:
                obj = obj[part]
            else:
                return defaultParam
        return obj

    def gets(self, obj, field):
        return str(self.get(obj, field))

    def getArg(self, arg, defaultParam=None):
        return self.get(self.callingContext, 'args.' + arg, defaultParam)

    def execute(self, module, command, args):
        return self.__do({'type': 'execute', 'module': module, 'command': command.strip(), 'args': args})

    def executeCommand(self, command, args):
        return self.__do({'type': 'executeCommand', 'command': command.strip(), 'args': args})

    def demistoUrls(self):
        return self.__do({'type': 'demistoUrls'})

    def demistoVersion(self):
        return self.__do({'type': 'demistoVersion'})

    def info(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'info', 'args': argsObj})

    def error(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'error', 'args': argsObj})

    def exception(self, ex):
        return self.__do({'type': 'exception', 'command': 'exception', 'args': ex})

    def debug(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'debug', 'args': argsObj})

    def getAllSupportedCommands(self):
        return self.__do({'type': 'getAllModulesSupportedCmds'})

    def getModules(self):
        return self.__do({'type': 'getAllModules'})

    def setContext(self, name, value):
        return self.__do({'type': 'setContext', 'name': name, 'value': value})

    def dt(self, data, q):
        return self.__do({'type': 'dt', 'name': q, 'value': data})['result']

    def mapObject(self, sourceObject, mapper, mapperType=""):
        return self.__do({'type': 'executeCommand', 'command': 'mapObject', 'args': {'source': sourceObject, 'mapper': mapper, 'mapperType': mapperType}})

    def getAutoFocusApiKey(self):
       resObj = self.__do({'type': 'executeCommand', 'command': 'getLicenseCustomField', 'args': {'key': 'autofocus'}})
       if resObj != None:
           return resObj['value']

    def getLicenseCustomField(self, key):
       resObj = self.__do({'type': 'executeCommand', 'command': 'getLicenseCustomField', 'args': {'key': key}})
       if resObj != None:
           return resObj['value']

    def __do_lock(self, lock, timeout):
        if sys.version_info.major >= 3:
            return lock.acquire(timeout=timeout)
        else:
            # python 2 doesn't have timeout we use polling
            if timeout < 0:
                return lock.acquire()
            start = time.time()
            while (time.time() - start) < timeout:
                if lock.acquire(False):
                    return True
                time.sleep(0.1)
            # didn't get the lock
            return False

    def __do_no_res(self, cmd):
        lock = self.__stdout_lock
        if lock is not None:
            if not self.__do_lock(lock, self._stdout_lock_timeout):
                raise RuntimeError('Timeout acquiring stdout lock')
        try:
            json.dump(cmd, sys.stdout)
            sys.stdout.write('\\n')
            sys.stdout.flush()
        finally:
            if lock is not None:
                lock.release()

    def __do(self, cmd):
        lock = self.__stdout_lock
        if lock is not None:
            if not self.__do_lock(lock, self._stdout_lock_timeout):
                raise RuntimeError('Timeout acquiring stdout lock')
        try:
            # Watch out, there is a duplicate copy of this method
            json.dump(cmd, sys.stdout)
            sys.stdout.write('\\n')
            sys.stdout.flush()
            data = globals()['__readWhileAvailable']()
            error_index = data.find(SERVER_ERROR_MARKER)
            if error_index > -1:
                offset = error_index + len(SERVER_ERROR_MARKER)
                raise ValueError(data[offset:])
            return json.loads(data)
        finally:
            if lock is not None:
                lock.release()


    def convert(self, results):
        """ Convert whatever result into entry """
        if type(results) is dict:
            if 'Contents' in results and 'ContentsFormat' in results:
                return results
            else:
                return {'Type': 1, 'Contents': json.dumps(results), 'ContentsFormat': 'json'}
        if type(results) is list:
            res = []
            for r in results:
                res.append(self.convert(r))
            return res
        if sys.version_info.major >= 3 and type(results) is bytes:
            return {'Type': 1, 'Contents': results.decode('utf-8'), 'ContentsFormat': 'text'}
        return {'Type': 1, 'Contents': str(results), 'ContentsFormat': 'text'}


    def results(self, results):
        res = []
        converted = self.convert(results)
        if type(converted) is list:
            res = converted
        else:
            res.append(converted)

        self.__do_no_res({'type': 'result', 'results': res})

demisto = Demisto(context)

try:
    import __builtin__
    from StringIO import StringIO
except ImportError:
    # Python 3
    import builtins as __builtin__
    from io import StringIO

def demisto_print(*args):
    global demisto
    output = StringIO()
    __builtin__.print(*args, file=output)
    result = output.getvalue().strip()
    demisto.log(result)

print = demisto_print

###CODE_HERE###
'''

"""Demisto instance for integrations only"""

integ_template_code = '''
from __future__ import print_function
import json
import uuid
import sys

SERVER_ERROR_MARKER = '[ERROR-fd5a7750-7182-4b38-90ba-091824478903]'

class Demisto:
    """Wrapper class to interface with the Demisto server via stdin, stdout"""

    def __init__(self, context):
        self.callingContext = context
        self.is_debug = False
        self._args = dict(self.callingContext.get(u'args', {}))
        if 'demisto_machine_learning_magic_key' in  self._args:
            import os
            os.environ['DEMISTO_MACHINE_LEARNING_MAGIC_KEY'] = self._args['demisto_machine_learning_magic_key']
        is_debug = self.callingContext.get('context', {}).get('IsDebug', False)
        if is_debug:
            self.is_debug = True
            self._args.pop('debug-mode', '')
        self.__stdout_lock = None
        self._stdout_lock_timeout = 60
        self._heartbeat_enabled = False
        if context.get('command') == 'long-running-execution' and context.get('is_running_heartbeat'):
            self.long_running_heartbeat_thread()

    def enable_multithreading(self):
        from threading import Lock
        if self.__stdout_lock is None:
            self.__stdout_lock = Lock()

    def long_running_heartbeat_thread(self, enable=True):
        if self._heartbeat_enabled == enable:
            # nothing to do as state hasn't changed
            return
        self._heartbeat_enabled = enable
        if self._heartbeat_enabled:
            self.info("starting heartbeat thread")
            self.enable_multithreading()

            def send_heartbeat():
                import time
                counter = 0
                while True:
                    time.sleep(self.callingContext.get('heartbeat_interval', 30))
                    if not self._heartbeat_enabled:
                        self.info("heartbeat disabled. Existing heartbeat thread.")
                        return
                    self.heartbeat("heartbeat counter: " + str(counter))
                    counter += 1

            import threading
            self._heartbeat_thread = threading.Thread(target=send_heartbeat)
            self._heartbeat_thread.setDaemon(True)
            self._heartbeat_thread.start()

    def log(self, msg):
        self.__do_no_res({'type': 'entryLog', 'args': {'message': 'Integration log: ' + msg}})

    def investigation(self):
        return self.callingContext[u'context'][u'Inv']

    def get_incidents(self):
        return self.callingContext[u'context'][u'Incidents']

    def incident(self):
        return self.get_incidents()[0]

    def parentEntry(self):
        return self.callingContext[u'context'][u'ParentEntry']

    def context(self):
        return self.callingContext[u'context'][u'ExecutionContext']

    def integrationInstance(self):
        return self.callingContext[u'context'][u'IntegrationInstance']

    def args(self):
        return self._args

    def uniqueFile(self):
        return str(uuid.uuid4())

    def getFilePath(self, id):
        return self.__do({'type': 'getFileByEntryID', 'command': 'getFilePath', 'args': {'id': id}})

    def getLastRun(self):
        return self.__do({'type': 'executeCommand', 'command': 'getLastRun', 'args': {}})

    def setLastRun(self, value):
        return self.__do({'type': 'executeCommand', 'command': 'setLastRun', 'args': {'value': value}})

    def internalHttpRequest(self, method, uri, body = None):
        return self.__do({'type': 'executeCommand', 'command': 'internalHttpRequest', 'args': {'method': method, 'uri': uri, 'body': body}})

    def getIntegrationContext(self):
        resObj = self.__do({'type': 'executeCommand', 'command': 'getIntegrationContext', 'args': {'refresh': False}})
        return resObj['context']

    def setIntegrationContext(self, value):
        return self.__do({'type': 'executeCommand', 'command': 'setIntegrationContext', 'args': {'value': value, 'version': {"version":-1,"sequenceNumber":-1,"primaryTerm":-1}, 'sync': False}})

    def getIntegrationContextVersioned(self, refresh = False):
        return self.__do({'type': 'executeCommand', 'command': 'getIntegrationContext', 'args': {'refresh': refresh}})

    def setIntegrationContextVersioned(self, value, version, sync = False):
        return self.__do({'type': 'executeCommand', 'command': 'setIntegrationContext', 'args': {'value': value, 'version': version, 'sync': sync}})

    def getLicenseID(self):
            return self.__do({'type': 'executeCommand', 'command': 'getLicenseID', 'args': {}})['id']

    def createIncidents(self, incidents, lastRun = None, userID = None):
        return self.__do({'type': 'executeCommand', 'command': 'createIncidents', 'args': {'incidents': incidents, 'lastRun': lastRun, 'userID': userID}})

    def createIndicators(self, indicators, lastRun = None, noUpdate = False):
        return self.__do({'type': 'executeCommand', 'command': 'createIndicators', 'args': {'indicators': indicators, 'lastRun': lastRun, 'noUpdate': noUpdate}})

    def searchIndicators(self, value = None, query = None, size = None, page=None, fromDate = None, toDate = None, searchAfter = None, populateFields = None):
        return self.__do({'type': 'executeCommand', 'command': 'searchIndicators', 'args': {'value': value, 'query': query, 'size': size, 'page': page, 'fromDate': fromDate, 'searchAfter': searchAfter, 'toDate': toDate, 'populateFields': populateFields}})

    def getIndexHash(self):
            return self.__do({'type': 'executeCommand', 'command': 'getIndexHash'})

    def updateModuleHealth(self, err):
        return self.__do({'type': 'executeCommand', 'command': 'updateModuleHealth', 'args': {'err': err}})

    def addEntry(self, id, entry, username = None, email = None, footer = None):
        return self.__do({'type': 'executeCommand', 'command': 'addEntry', 'args': {'id': id, 'username': username,
                        'email': email, 'entry': entry, 'footer': footer}})

    def directMessage(self, message, username = None, email = None, anyoneCanOpenIncidents = None):
        tmp = self.__do({'type': 'executeCommand', 'command': 'directMessage', 'args': {'message': message,
                        'username': username, 'email': email, 'anyoneCanOpenIncidents': anyoneCanOpenIncidents}})
        if tmp != None:
            return tmp["res"]

    def mirrorInvestigation(self, id, mirrorType, autoClose = False):
        return self.__do({'type': 'executeCommand', 'command': 'mirrorInvestigation', 'args': {'id': id,
                        'mirrorType': mirrorType, 'autoClose': autoClose}})

    def findUser(self, username="", email=""):
            return self.__do({'type': 'executeCommand', 'command': 'findUser', 'args': {'username': username, 'email': email}})

    def handleEntitlementForUser(self, incidentID, guid, email, content, taskID=""):
        return self.__do({'type': 'executeCommand', 'command': 'handleEntitlementForUser', 'args': {'incidentID': incidentID, 'guid': guid, 'taskID': taskID, 'email': email, 'content': content}})

    def mapObject(self, sourceObject, mapper, mapperType=""):
        return self.__do({'type': 'executeCommand', 'command': 'mapObject', 'args': {'source': sourceObject, 'mapper': mapper, 'mapperType': mapperType}})

    def getAutoFocusApiKey(self):
       resObj = self.__do({'type': 'executeCommand', 'command': 'getLicenseCustomField', 'args': {'key': 'autofocus'}})
       if resObj != None:
           return resObj['value']

    def getLicenseCustomField(self, key):
       resObj = self.__do({'type': 'executeCommand', 'command': 'getLicenseCustomField', 'args': {'key': key}})
       if resObj != None:
           return resObj['value']

    def params(self):
        return self.callingContext.get(u'params', {})

    def command(self):
        return self.callingContext.get(u'command', '')

    def get(self, obj, field, defaultParam=None):
        """ Get the field from the given dict using dot notation """
        parts = field.split('.')
        for part in parts:
            if obj and part in obj:
                obj = obj[part]
            else:
                return defaultParam
        return obj

    def demistoUrls(self):
        return self.__do({'type': 'demistoUrls'})

    def demistoVersion(self):
        return self.__do({'type': 'demistoVersion'})

    def heartbeat(self, msg):
        return self.__do_no_res({'type': 'executeCommand', 'command': 'heartbeat', 'args': {'message': msg}})

    def info(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'info', 'args': argsObj})

    def error(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'error', 'args': argsObj})

    def debug(self, *args):
        argsObj = {}
        argsObj["args"] = list(args)
        self.__do({'type': 'log', 'command': 'debug', 'args': argsObj})

    def gets(self, obj, field):
        return str(self.get(obj, field))

    def getArg(self, arg, defaultParam=None):
        return self.get(self.callingContext, 'args.' + arg, defaultParam)

    def getParam(self, p):
        return self.get(self.callingContext, 'params.' + p)

    def dt(self, data, q):
        return self.__do({'type': 'dt', 'name': q, 'value': data})['result']

    def __do_lock(self, lock, timeout):
        if sys.version_info.major >= 3:
            return lock.acquire(timeout=timeout)
        else:
            # python 2 doesn't have timeout we use polling
            if timeout < 0:
                return lock.acquire()
            start = time.time()
            while (time.time() - start) < timeout:
                if lock.acquire(False):
                    return True
                time.sleep(0.1)
            # didn't get the lock
            return False

    def __do_no_res(self, cmd):
        lock = self.__stdout_lock
        if lock is not None:
            if not self.__do_lock(lock, self._stdout_lock_timeout):
                raise RuntimeError('Timeout acquiring stdout lock')
        try:
            json.dump(cmd, sys.stdout)
            sys.stdout.write('\\n')
            sys.stdout.flush()
        finally:
            if lock is not None:
                lock.release()

    def __do(self, cmd):
        lock = self.__stdout_lock
        if lock is not None:
            if not self.__do_lock(lock, self._stdout_lock_timeout):
                raise RuntimeError('Timeout acquiring stdout lock')
        try:
            # Watch out, there is a duplicate copy of this method
            json.dump(cmd, sys.stdout)
            sys.stdout.write('\\n')
            sys.stdout.flush()
            data = globals()['__readWhileAvailable']()
            error_index = data.find(SERVER_ERROR_MARKER)
            if error_index > -1:
                offset = error_index + len(SERVER_ERROR_MARKER)
                raise ValueError(data[offset:])
            return json.loads(data)
        finally:
            if lock is not None:
                lock.release()

    def __convert(self, results):
        """ Convert whatever result into entry """
        if type(results) is dict:
            if 'Contents' in results and 'ContentsFormat' in results:
                return results
            else:
                return {'Type': 1, 'Contents': json.dumps(results), 'ContentsFormat': 'json'}
        if type(results) is list:
            res = []
            for r in results:
                res.append(self.__convert(r))
            return res
        if sys.version_info.major >= 3 and type(results) is bytes:
            return {'Type': 1, 'Contents': results.decode('utf-8'), 'ContentsFormat': 'text'}
        return {'Type': 1, 'Contents': str(results), 'ContentsFormat': 'text'}

    def results(self, results):
        res = []
        converted = self.__convert(results)
        if type(converted) is list:
            res = converted
        else:
            res.append(converted)
        self.__do_no_res({'type': 'result', 'results': res})

    def incidents(self, incidents):
        self.results({'Type': 1, 'Contents': json.dumps(incidents), 'ContentsFormat': 'json'})

    def credentials(self, credentials):
        self.results({'Type': 1, 'Contents': json.dumps(credentials), 'ContentsFormat': 'json'})

demisto = Demisto(context)

try:
    import __builtin__
    from StringIO import StringIO
except ImportError:
    # Python 3
    import builtins as __builtin__
    from io import StringIO

def demisto_print(*args):
    global demisto
    output = StringIO()
    __builtin__.print(*args, file=output)
    result = output.getvalue().strip()
    demisto.log(result)

print = demisto_print

###CODE_HERE###
'''

# rollback file system to its previous state
# delete home dir and tmp dir


# notifies demisto server that the current executed script is completed
# and the process is ready to execute the next script
def send_script_completed():
    sys.stderr.flush()
    time.sleep(.0001)
    json.dump({'type': 'completed'}, sys.stdout)
    sys.stdout.write('\n')
    sys.stdout.flush()


def send_script_exception(exc_type, exc_value, exc_traceback):
    ex_string = traceback.format_exception(exc_type, exc_value, exc_traceback)
    if ex_string == 'None\n':
        ex_string = str(exc_value)

    json.dump({'type': 'exception', 'args': {'exception': ex_string}}, sys.stdout)
    sys.stdout.write('\n')
    sys.stdout.flush()


def send_pong():
    json.dump({'type': 'pong'}, sys.stdout)
    sys.stdout.write('\n')
    sys.stdout.flush()


# receives ping and sends back pong until we get something else
# the the function stopped and returns the received string
def do_ping_pong():
    while True:
        ping = __readWhileAvailable()
        if ping == 'ping\n':
            send_pong()  # return pong to server to indicate that everything is fine
        else:
            return ping


backup_env_vars = {}
for key in os.environ.keys():
    backup_env_vars[key] = os.environ[key]


def rollback_system():
    os.environ = {}
    for key in backup_env_vars.keys():
        os.environ[key] = backup_env_vars[key]


while True:
    contextString = do_ping_pong()
    if contextString == '':
        # finish executing python
        break

    contextJSON = json.loads(contextString)
    code_version = contextJSON.get('code_version')
    code = None
    code_string = contextJSON.pop('script', None)
    if code_version:
        code = _compiled_code_cache.get(code_version)
    if contextJSON.get('reset_code_cache'):
        _compiled_code_cache.clear()
    sub_globals = None
    try:
        if not code:
            if not code_string:
                raise ValueError("Missing script code for code_version: [{}]. Can't execute!!".format(code_version))
            is_integ_script = contextJSON['integration']
            complete_code = ''
            if is_integ_script:
                complete_code = integ_template_code.replace('###CODE_HERE###', code_string)
            else:
                complete_code = template_code.replace('###CODE_HERE###', code_string)
            code = compile(complete_code, '<string>', 'exec')
        if code_version:
            _compiled_code_cache[code_version] = code

        sub_globals = {
            '__readWhileAvailable': __readWhileAvailable,
            'context': contextJSON,
            'win': win,
            'exit': sys.exit,
            'quit': sys.exit
        }

        exec(code, sub_globals, sub_globals)

    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        send_script_exception(exc_type, exc_value, exc_traceback)
    except SystemExit:
        # print 'Will not stop on sys.exit(0)'
        pass

    # clear sub_globals so all objects are dereferenced and cleared from memory
    # follow the semantics of: https://docs.python.org/3/reference/datamodel.html#object.__del__
    # globals whose name begins with a single underscore are deleted before others
    if sub_globals:
        for k in list(sub_globals.keys()):
            if str(k).startswith('_') and not str(k).startswith('__'):
                sub_globals.pop(k, None)
        sub_globals.clear()

    rollback_system()

    # ping back to Demisto server that script is completed
    send_script_completed()

    # if the script running on native python then terminate the process after finished the script
    is_python_native = contextJSON['native']
    if is_python_native:
        break


if __read_thread:
    __read_thread.join(timeout=1)
