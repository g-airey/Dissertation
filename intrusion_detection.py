import pyshark
import dbase
import classifier
import os

classifications = {}

ignore_list = {"ae:b6:d0:e3:65:77",
               "18:62:2c:30:89:2a" 
                }

test_list = {"ec:08:6b:0c:0a:e4",
                "38:8b:59:65:d3:13",
                "34:69:87:57:e5:ed",
                "48:60:5f:83:fb:47",
                "80:32:53:f1:4b:5e",
                "9c:b6:d0:e3:65:77",
                "18:3a:2d:d3:40:8e",
                "30:07:4d:1d:d8:62"}

macs_categories = {}

def load_macs():
    global classifications
    classifications = dbase.get_macs_classifications_from_db()
    return(dbase.get_new_macs())

#Classifies All Mac Addresses in provided list from test database
def identify_macs(verify_list):
    for device in verify_list:
        if device not in classifications:
            new_device(device)
            continue
        device_info = classifications[device]
        classification,confidence = classifier.classify_device(device,'random_forest_1')
        #If classifying device for the first time
        if device_info[0] == 'unknown':
            dbase.update_classification(device, [classification,confidence,1])
            device_info = [classification, confidence, 1]
            print("Device: {} has been classified as {} ( {} confidence)".format(device, classification, confidence))
        #If device has been seen before
        else:
            #If classifications don't match and confidence is high
            if classification != device_info[0] and confidence > 0.7:
                print("Device: {} has been classified as {} - Previous classification was {}, verify this classification!".format(device, classification, device_info[0]))
                dbase.update_classification(device,['unknown','100',0])
            #If confidence of classification is low
            elif(device_info[1] - confidence > 0.2):
                print("Device: {} is behaving abnormally ({} confidence of prediction)".format(device,confidence))
            #If confident, just update average confidence
            else:
                current_confidence = device_info[1] * device_info[2]
                #Recalculate new average
                current_confidence = (current_confidence + confidence) / (device_info[2] + 1)
                dbase.update_classification(device, [classification, current_confidence, device_info[2] + 1])

#Handle adding a new device
def new_device(mac):
    print("New Device {} detected. Attempting to classify...".format(mac))
    (classification,confidence) = classifier.classify_device(mac = mac, classifier = "random_forest_1")
    print("Classifier has predicted {} with {} confidence\n".format(classification, round(confidence,3)))
    dbase.add_mac_to_db(mac)
    dbase.update_classification(mac, (classification, confidence, 1))

#go through new packets, get new devices, identify new devices

def main():
    #Load new mac addresses from database
    new_list = load_macs()
    #Identify mac addresses 
    identify_macs(new_list)
    dbase.close_connection()



if __name__ == '__main__':
    main()