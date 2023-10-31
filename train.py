import os
from androguard.core.bytecodes import apk, dvm
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction import DictVectorizer
import re
from utils import *

benign_apps = []
for filename in os.listdir(BENIGN_DIR):
    if filename.endswith('.apk'):
        benign_apps.append(os.path.join(BENIGN_DIR, filename))

malicious_apps = []
for filename in os.listdir(MALICIOUS_DIR):
    if filename.endswith('.apk'):
        malicious_apps.append(os.path.join(MALICIOUS_DIR, filename))

all_apps = benign_apps + malicious_apps
all_labels = [0] * len(benign_apps) + [1] * len(malicious_apps)

all_features = [extract_features_from_apk(app) for app in all_apps]
vec = DictVectorizer()
feature_matrix = vec.fit_transform(all_features).toarray()

X_train, X_test, y_train, y_test = train_test_split(feature_matrix, all_labels, test_size=0.33)
clf = svm.SVC(kernel='linear')
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))