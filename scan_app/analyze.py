import json
from pprint import pprint


class Analyze:
    def __init__(self, results_file):
        self.results_file = results_file
        self.results = self.load_json()

        self.checkMatch()

    def load_json(self):
        with open(self.results_file) as json_file:
            return json.load(json_file)

    def checkMatch(self):
        for IP in self.results:
            for run in self.results[IP]['Results']:
                if run['GoMatch'] is not run['Censored']:
                    pprint(run)









if __name__ == '__main__':
    Analyze('results/AS_50_results.json')