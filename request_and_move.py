import os
import wget
import pandas as pd
import csv
import json 
from constants import *
import os
from itertools import islice

exist_file_list = []
API_KEY = open("api.txt").read().strip()
DATASET_URL = "https://androzoo.uni.lu/api/download?apikey=" + API_KEY + "&sha256="
X_combined = json.loads(open(os.path.join(DATA_DIR, "drebin-combined-meta.json")).read())
Y = json.loads(open(os.path.join(DATA_DIR, "drebin-combined-Y.json")).read())

os.makedirs(BENIGN_DIR, exist_ok=True)
os.makedirs(MALICIOUS_DIR, exist_ok=True)

with open(os.path.join(DATA_DIR, "tong.csv"), encoding='utf-8-sig') as f:
    reader = csv.reader(f)

    for row in islice(reader, 1, None):
        print(row)
        if not row:
            continue
        name = row[1]
        url = DATASET_URL+name
        path = './'+name+'.apk'
        name_temp = name+'.apk'
        if name_temp not in exist_file_list:
            wget.download(url,path)
        else:
            print("exist")
        
        idx = 0

        for i in range(len(X_combined)):
            if X_combined[i]['sha256'] == name:
                idx = i
                break
        
        if Y[idx] == 1:
            os.rename(path, os.path.join(MALICIOUS_DIR, name_temp))
        else:
            os.rename(path, os.path.join(BENIGN_DIR, name_temp))
