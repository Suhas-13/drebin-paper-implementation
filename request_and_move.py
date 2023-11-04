import os
import wget
import pandas as pd
import csv
import json 
import argparse
from itertools import islice

def read_api_key(api_file):
    with open(api_file, 'r') as f:
        api_key = f.read().strip()
    return api_key

def download_apks(csv_file, dataset_url, benign_dir, malicious_dir, labels_file=None):
    exist_file_list = os.listdir(benign_dir) + os.listdir(malicious_dir)

    # Read labels from labels_file
    if labels_file:
        with open(labels_file, 'r') as f:
            labels = json.load(f)
    else:
        labels = None

    with open(csv_file, encoding='utf-8-sig') as f:
        reader = csv.reader(f)

        for row in islice(reader, 1, None):
            print(row)
            if not row:
                continue
            name = row[1]
            url = dataset_url + name
            # Determine whether the APK is benign or malicious based on labels_file
            if not labels:
                apk_label = "unknown"
            else:
                apk_label = 'benign' if labels[name] == 0 else 'malicious'

            path = os.path.join(benign_dir if apk_label == 'benign' else malicious_dir if apk_label == 'malicious' else 'unknown', name + '.apk')
            if name + '.apk' not in exist_file_list:
                wget.download(url, path)
            else:
                print("exist")
