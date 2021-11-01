from celery import Celery, group
from celery.events.cursesmon import CursesMonitor, DisplayThread, capture_events
import dill
import curses
from itertools import count
from textwrap import wrap
import dill
import codecs

class SamsonMonitor(CursesMonitor):
    foreground = curses.COLOR_WHITE
    background = curses.COLOR_BLACK

    def selection_result(self):
        if not self.selected_task:
            return

        def alert_callback(my, mx, xs):
            y = count(xs)
            task = self.state.tasks[self.selected_task]
            if getattr(task, 'result', None):
                result = getattr(task, 'result', None)
                result = codecs.decode(result[2:-1].encode('utf-8'), 'hex_codec')
                result = str(dill.loads(result))
            else:
                result = getattr(task, 'exception', None)

            for line in wrap(result or '', mx - 2):
                self.win.addstr(next(y), 3, line)

        return self.alert(
            alert_callback,
            f'Task Result for {self.selected_task}',
        )


def evtop(app):  # pragma: no cover
    """Start curses monitor."""
    state = app.events.State()
    display = SamsonMonitor(state, app)
    display.init_screen()

    refresher = DisplayThread(display)
    refresher.start()
    try:
        capture_events(app, state, display)
    except Exception:
        refresher.shutdown = True
        refresher.join()
        display.resetscreen()
        raise
    except (KeyboardInterrupt, SystemExit):
        refresher.shutdown = True
        refresher.join()
        display.resetscreen()



def run(func, args, kwargs):
    func   = dill.loads(func)
    args   = dill.loads(args)
    kwargs = dill.loads(kwargs)
    return dill.dumps(func(*args, **kwargs))


class RPCClient(object):
    def __init__(self, broker: str, backend: str) -> None:
        self.app  = Celery('rpc', backend=backend, broker=broker)
        self._run = self.app.task()(run)

        self.app.conf.task_serializer   = 'pickle'
        self.app.conf.result_serializer = 'pickle'
        self.app.conf.accept_content    = ['pickle']


    def run_async(self, func, *args, **kwargs):
        func   = dill.dumps(func)
        args   = dill.dumps(args)
        kwargs = dill.dumps(kwargs)

        result = self._run.delay(func, args, kwargs)
        result._get = result.get
        result.get = lambda: dill.loads(result._get())
        return result


    def run(self, func, *args, **kwargs):
        return self.run_async(func, *args, **kwargs).get()


    def run_s(self, func, *args, **kwargs):
        func   = dill.dumps(func)
        args   = dill.dumps(args)
        kwargs = dill.dumps(kwargs)

        return self._run.s(func, args, kwargs)


    def distribute(self, func, arg_list):
        res = group(self.run_s(func, *args) for args in arg_list)()
        return [dill.loads(r) for r in res.get()]


    def start_worker(self, **kwargs):
        worker = self.app.Worker(**kwargs)
        worker.start()


    def evtop(self):
        evtop(self.app)
