import importlib
import os
from types import FunctionType


class HCat:
    def __init__(self):
        self.event_dict: dict[object][list[FunctionType]] = {}

    def event_handle(self, func):
        if len(func.__annotations__) > 1:
            raise 'unexpected arguments.'
        elif len(func.__annotations__) == 0:
            raise 'missing arguments'
        if list(func.__annotations__.values())[0] not in self.event_dict:
            self.event_dict[list(func.__annotations__.values())[0]] = []
        self.event_dict[list(func.__annotations__.values())[0]].append(func)

    def __call__(self, e):
        if type(e) in self.event_dict:
            for f in self.event_dict[type(e)]:
                f(e)

    def load_all_plugin(self):
        for i in os.listdir('plugins'):
            dir_path = os.path.join('plugins', i)
            if os.path.isdir(dir_path) and os.path.exists(os.path.join(dir_path, '__init__.py')):
                module_name = 'plugins.' + i

                module = importlib.import_module(module_name)
                if 'init' in dir(module):
                    getattr(module, 'init')(self)
