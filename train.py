import os
from androguard.core.bytecodes import apk, dvm
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction import DictVectorizer
import re
from features import *


def train(all_apps, all_labels):
    all_features = [extract_features_from_apk(app) for app in all_apps]
    vec = DictVectorizer()
    feature_matrix = vec.fit_transform(all_features).toarray()

    X_train, X_test, y_train, y_test = train_test_split(feature_matrix, all_labels, test_size=0.33)
    clf = svm.SVC(kernel='linear')
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))