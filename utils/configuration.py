
import json

class Configuration:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None or kwargs and kwargs["filename"]:
            filename = kwargs.get('filename', 'conf.json')  # Get filename from kwargs
            cls._instance = super(Configuration, cls).__new__(cls)
            cls._instance._config = cls._instance._load_config(filename)

        return cls._instance

    def _load_config(self, filename):
        try:
            with open(filename, 'r') as file:
                config = json.load(file)
                return config
        except FileNotFoundError:
            print("Config file not found!")
            exit(-1)

    def get_config(self):
        return self._config    

