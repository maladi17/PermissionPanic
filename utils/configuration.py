
import json


class Configuration:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Configuration, cls).__new__(cls)
            cls._instance._config = cls._instance._load_config(kwargs.get('filename', 'conf.json'))
        return cls._instance

    def _load_config(self, filename):
        try:
            with open(filename, 'r') as file:
                config = json.load(file)
            return config
        except FileNotFoundError:
            print("Config file not found!")
            return {}

    def get_config(self):
        return self._config    

