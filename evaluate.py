import os
from androguard.core.bytecodes import apk, dvm
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction import DictVectorizer
import re
from features import *
from sklearn.metrics import roc_curve, auc, precision_recall_curve
import matplotlib.pyplot as plt
from scipy.interpolate import interp1d


def evaluate_model(clf, X_test, y_test):
    y_score = clf.decision_function(X_test)

    fpr, tpr, _ = roc_curve(y_test, y_score)

    # 1% FPR
    f = interp1d(fpr, tpr)
    tpr_at_fpr1 = f(0.01)

    # Precision-Recall curve
    precision, recall, _ = precision_recall_curve(y_test, y_score)

    return tpr_at_fpr1, precision, recall, fpr, tpr

def plot_pr_curve(precision, recall):
    plt.figure()
    plt.plot(recall, precision, color='b', alpha=0.2, label='PR curve')
    plt.fill_between(recall, precision, step='post', alpha=0.2, color='b')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.ylim([0.0, 1.05])
    plt.xlim([0.0, 1.0])
    plt.title('Precision-Recall curve')
    plt.legend(loc="lower right")
    plt.show()


def plot_roc_curve(fpr, tpr, tpr_at_fpr1):
    plt.figure()
    plt.plot(fpr, tpr, color='b', alpha=0.2, label='ROC curve (AUC = %0.2f)' % auc(fpr, tpr))
    plt.plot([0, 1], [0, 1], linestyle='--', lw=2, color='r', label='Chance', alpha=.8)
    plt.plot([0.01, 0.01], [0, tpr_at_fpr1], linestyle='--', lw=2, color='g', label='FPR = 0.01', alpha=.8)
    plt.xlim([-0.05, 1.05])
    plt.ylim([-0.05, 1.05])
    plt.xlabel('False Positive Rate (FPR)')
    plt.ylabel('True Positive Rate (TPR)')
    plt.title('Receiver operating characteristic (ROC) curve')
    plt.legend(loc="lower right")
    plt.show()