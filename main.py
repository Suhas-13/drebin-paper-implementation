import os
import argparse
import json
import joblib
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction import DictVectorizer
from request_and_move import download_apks, read_api_key
from evaluate import evaluate_model, plot_pr_curve, plot_roc_curve
from train import train
from features import extract_features_from_apk

def get_app_paths(directory):
    app_paths = []
    for filename in os.listdir(directory):
        if filename.endswith('.apk'):
            app_paths.append(os.path.join(directory, filename))
    return app_paths

def extract_features_and_labels(benign_apps, malicious_apps):
    all_apps = benign_apps + malicious_apps
    all_features = [extract_features_from_apk(app) for app in all_apps]
    all_labels = [0] * len(benign_apps) + [1] * len(malicious_apps)
    return all_features, all_labels

def read_features_and_labels(json_file, labels_file):
    with open(json_file, 'r') as f:
        all_features = json.load(f)
    with open(labels_file, 'r') as f:
        all_labels = json.load(f)
    return all_features, all_labels


def test_model(model_file, X_test):
    model = joblib.load(model_file)
    predictions = model.predict(X_test)
    return predictions

def main():
    parser = argparse.ArgumentParser(description='Train and evaluate a model on APK data.')
    parser.add_argument('--train', action='store_true', help='Train the model')
    parser.add_argument('--test', action='store_true', help='Test the model')
    parser.add_argument('--api_file', type=str, default='api.txt', help='File containing API key')
    parser.add_argument('--extract', action='store_true', help='Extract features')
    parser.add_argument('--download', action='store_true', help='Download APKs')
    parser.add_argument('--evaluate', action='store_true', help='Evaluate the model')
    parser.add_argument('--read', action='store_true', help='Read features from JSON file')
    parser.add_argument('--json_file', type=str, default='features.json', help='JSON file to read/write features')
    parser.add_argument('--model_file', type=str, default='model.pkl', help='Model file to save/load')
    parser.add_argument('--benign_dir', type=str, default='benign', help='Directory of benign apps')
    parser.add_argument('--malicious_dir', type=str, default='malicious', help='Directory of malicious apps')
    parser.add_argument('--unknown_dir', type=str, default='unknown', help='Directory of unknown apps')
    parser.add_argument('--labels_file', type=str, default=None, help='JSON file to read/write labels')
    parser.add_argument('--csv_file', type=str, default='data/app_dataset.csv', help='CSV file containing APK names and labels')

    args = parser.parse_args()

    if args.download:
        os.makedirs(args.benign_dir, exist_ok=True)
        os.makedirs(args.malicious_dir, exist_ok=True)
        os.makedirs(args.unknown_dir, exist_ok=True)
        
        api_key = read_api_key(args.api_file)

        dataset_url = "https://androzoo.uni.lu/api/download?apikey=" + api_key + "&sha256="
        download_apks(args.csv_file, dataset_url, args.benign_dir, args.malicious_dir, args.labels_file)
        
    if args.extract:
        benign_apps = get_app_paths(args.benign_dir)
        malicious_apps = get_app_paths(args.malicious_dir)

        all_features, all_labels = extract_features_and_labels(benign_apps, malicious_apps)
        with open(args.json_file, 'w') as f:
            json.dump(all_features, f)
        with open(args.labels_file, 'w') as f:
            json.dump(all_labels, f)

    if args.read:
        all_features, all_labels = read_features_and_labels(args.json_file, args.labels_file)

    if args.train:
        X_test, y_test = train(all_features, all_labels, args.model_file)

    if args.evaluate:
        tpr_at_fpr1, precision, recall, fpr, tpr = evaluate_model(args.model_file, X_test, y_test)
        plot_pr_curve(precision, recall)
        plot_roc_curve(fpr, tpr, tpr_at_fpr1)

if __name__ == "__main__":
    main()