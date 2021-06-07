import pyshark
import os
import csv
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import dbase
import time
import datetime
import intrusion_detection
from joblib import dump,load
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.tree import plot_tree
import pydot
import time

#Database connection
conn = None

#List of devices for calculating accuracies in predictions
device_list = {"38:8b:59:65:d3:13":"iot", 
               "34:69:87:57:e5:ed":"smartphone", 
               "48:60:5f:83:fb:47":"smartphone", 
               "9c:b6:d0:e3:65:77":"computer", 
               "80:32:53:f1:4b:5e":"computer", 
               "18:3a:2d:d3:40:8e":"smartphone",
               "30:07:4d:1d:d8:62":"smartphone",
               "52:54:00:12:34:56":"smartphone",
               "50:dc:e7:ae:c7:40":"iot",
               "9c:b6:d0:98:bf:43":"computer"}

#List of only new devices for calculating accuracies in new predictions
new_devices = {"52:54:00:12:34:56":"smartphone",
               "9c:b6:d0:98:bf:43":"computer"}

#Creates new classifiers
def create_classifiers():
    classifiers = {
        RandomForestClassifier(n_estimators=1000, random_state=42):"random_forest",
        KNeighborsClassifier(5):"k_neighbour",
        DecisionTreeClassifier(max_depth=15):"decision_tree",
        GaussianNB():"gaussian_NB"
    }
    return classifiers
    
#Trains classifiers in approach 1
def approach_one_train():
    print("\nImporting data from database...")
    dataframe = dbase.get_approach_1_training()
    train_labels = np.array(dataframe['classification'])
    train_data = dataframe.drop('classification',axis=1)
    train_data = np.array(train_data)
    print("Data imported.")
    print("Training Classifiers...\n")
    classifiers = create_classifiers()
    for classifier in classifiers:
       train_classifier(train_data=train_data,train_labels=train_labels,approach=1,classifier=classifier,classifier_name=classifiers[classifier]) 

#Tests approach 1
def approach_one_test():  
    dataframe = dbase.get_approach_1_testing(mac=None, new=False)
    test_labels = np.array(dataframe['classification'])
    test_data = dataframe.drop('classification',axis=1)
    test_data = np.array(test_data)
    
    for filename in os.listdir("./classifiers"):
        if "_1" in filename:
            clf = load('./classifiers/' + filename)
            test_classifier(test_data=test_data, test_labels=test_labels, classifier=clf, classifier_name=filename.split('.')[0])

#Trains Classifiers On Approach 2
def approach_two_train():
    dataframe = dbase.get_approach_2_training()
    train_labels = np.array(dataframe['classification'])
    train_data = dataframe.drop('classification',axis=1)
    train_data = np.array(train_data)
    print("Data imported.")
    print("Training Classifiers...\n")
    classifiers = create_classifiers()
    for classifier in classifiers:
        train_classifier(train_data=train_data,train_labels=train_labels,approach=2,classifier=classifier,classifier_name=classifiers[classifier])

#Tests Approach 2
def approach_two_test():
    dataframe = dbase.get_approach_2_testing(mac=None, new=False)
    test_labels = np.array(dataframe['classification'])
    test_data = dataframe.drop('classification',axis=1)
    test_data = np.array(test_data)
    
    for filename in os.listdir("./classifiers"):
        if "_2" in filename:
            clf = load('./classifiers/' + filename)
            test_classifier(test_data=test_data, test_labels=test_labels, classifier=clf, classifier_name=filename.split('.')[0])

#Classify a group of individual devices and perform analysis on the results
def classify_individual_devices(list, detailed, new):
    if list == None:
        list = device_list
    approach_1_results = []
    approach_2_results = []
    dbase.clear_table("results")
    for mac in list:
        if detailed:
            print("\nClassifying " + mac + "\n")
        approach_1_results += [classify_device_test(mac, 1, detailed, new)]
        approach_2_results += [classify_device_test(mac, 2, detailed, new)]
    dbase.analyse_results_from_db()

#Classifies a specific device using all saved classifiers
def classify_device_test(mac, approach, detailed, new):
    total_confidence = 0
    classifier_count = 0
    incorrect_classifications = 0
    #If looking for pre-trained devices
    if not new:
        dataframe = dbase.get_approach_1_testing(mac, False) if approach == 1 else dbase.get_approach_2_testing(mac, False)
    #If looking for new devices
    else:
        dataframe = dbase.get_approach_1_testing(mac, True) if approach == 1 else dbase.get_approach_2_testing(mac, True)
    if dataframe.empty:
        return
    data = dataframe.drop('classification',axis=1)
    data = np.array(data)
    for filename in os.listdir("./classifiers"):
        #Get classifier name for information output
        classifier_name = filename.split('.')[0]
        split = classifier_name.split('_')
        classifier_name = split[0] + " " + split[1]
        #Ignore classifiers that are not part of this approach
        if str(approach) not in filename:
            continue        
        classifier_count += 1
        clf = load('./classifiers/' + filename)
        predictions = clf.predict(data)
        counts = {}
        for prediction in predictions:
            if(prediction in counts):
                counts[prediction] += 1
            else:
                counts[prediction] = 1
        maxCount = 0
        maxCategory = ''
        for category in counts:
            if(counts[category] > maxCount):
                maxCount = counts[category]
                maxCategory = category
                confidence = maxCount / len(predictions)
                total_confidence += confidence
        correct = "Y"
        if maxCategory != device_list[mac]:
            correct = "N"  
        
        dbase.write_result_to_db(approach = approach, classifier = classifier_name, correct=correct,confidence=confidence)
        if detailed:
            print("{}: {} with confidence {}".format(filename, maxCategory, round(confidence,3)))

#Classifies a specific device using a specified classifier
def classify_device(mac,classifier):
    conn = dbase.conn
    dataframe_test = dbase.get_approach_1_testing(mac, True)  
    if dataframe_test.empty:
        return
    data = dataframe_test.drop('classification',axis=1)
    feature_list = list(data.columns)
    data = np.array(data)
    clf = load('./classifiers/{}.joblib'.format(classifier))
    predictions = clf.predict(data)
    counts = {}
    for prediction in predictions:
        if(prediction in counts):
            counts[prediction] += 1
        else:
            counts[prediction] = 1
    maxCount = 0
    maxCategory = ''
    for category in counts:
        if(counts[category] > maxCount):
            maxCount = counts[category]
            maxCategory = category
            confidence = maxCount / len(predictions)
    return (maxCategory,confidence)

#Trains a classifier from provided data
def train_classifier(train_data, train_labels, approach, classifier, classifier_name):
    print("Training " + classifier_name + " classifier...")
    trained = classifier.fit(train_data, train_labels)
    dump(trained, "./classifiers/" + classifier_name + "_" + str(approach) + ".joblib")
    print("Classifier trained.\n")

#Tests a specified classifer from provided data
def test_classifier(test_data, test_labels, classifier, classifier_name):
    print("Testing " + classifier_name + " classifier...")
    predictions = classifier.predict(test_data)
    correct = 0
    total = len(predictions)
    for i in range(0, len(predictions)):
        if(predictions[i] == test_labels[i]):
            correct += 1
    print("Accuracy: " + str(round(correct / total, 3)))

def main():
    #dbase.create_connection()
    global conn
    conn = dbase.get_connection()
    #dbase.setup_approach_two("approach_2_packets","approach_2",20)
    approach_one_train()
    approach_one_test()
    #approach_two_train()
    #approach_two_test()

    #classify_individual_devices(device_list,True,False)
    #classify_individual_devices(new_devices, True, True)

    dbase.close_connection()

if __name__ == '__main__':
    main()

conn = dbase.conn



