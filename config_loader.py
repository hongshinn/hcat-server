import json


class Config:
    def __init__(self, file='config.json'):
        config = json.load(open(file, 'r', encoding='utf8'))
        self.IP = config['IP']
        self.Port = config['Port']
        self.GCTime = config['GCTime']
        self.MainPageContent = config['MainPageContent']
