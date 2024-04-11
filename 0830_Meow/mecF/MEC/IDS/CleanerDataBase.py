import time
import json

class JsonFile() : 
    def __init__(self , file_path) : 
        self.FilePath = file_path
        self.IsModify = False
        self.Cleaners  = None

        with open(self.FilePath) as file : 
            print("INININININ")
            dict = json.load(file)
            self.Cleaners = dict['Cleaners']
            print(self.Cleaners)
    




    def Read(self) : 
        with open(self.FilePath) as file : 
            dict = json.load(file)

            self.IsModify = dict['IsModify']

            if self.IsModify : 
                self.Cleaners = dict['Cleaner']
                print(f'Loaded Cleaner<{self.FilePath}> Successfully\n\n\n')
            
            time.sleep(1.0)
            return