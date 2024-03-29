
import json


def readConf(filename):
    f = open(filename)
    data = json.load(f)
    return data