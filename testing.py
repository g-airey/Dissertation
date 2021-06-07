import intrusion_detection, classifier, dbase


device_list = {"38:8b:59:65:d3:13":"iot", 
               "34:69:87:57:e5:ed":"smartphone", 
               "48:60:5f:83:fb:47":"smartphone", 
               "9c:b6:d0:e3:65:77":"computer", 
               "80:32:53:f1:4b:5e":"computer", 
               "18:3a:2d:d3:40:8e":"smartphone",
               "30:07:4d:1d:d8:62":"smartphone",
               "50:dc:e7:ae:c7:40":"iot"}

def test_split_data():
    print("\nApproach 1 Tests: ")
    classifier.approach_one_test()
    print("\nApproach 2 Tests: ")
    classifier.approach_two_test()  

def test_seen_devices():
    classifier.classify_individual_devices(device_list, False, False)

def test_new_devices():
    dbase.clear_table("approach_1_test")
    dbase.execute_query("insert into approach_1_test select * from ids_test_1")
    new_list = dbase.get_new_macs()
    classifier.classify_individual_devices(new_list, True, True)

def test_ids_1():
    dbase.clear_table("approach_1_test")
    dbase.execute_query("insert into approach_1_test select * from ids_test_1")
    new_list = dbase.get_new_macs()
    intrusion_detection.identify_macs(new_list)

def test_ids_2():
    dbase.clear_table("approach_1_test")
    dbase.execute_query("insert into approach_1_test select * from ids_test_2")
    new_list = dbase.get_new_macs()
    intrusion_detection.identify_macs(new_list)

def test_ids_3():
    dbase.clear_table("approach_1_test")
    dbase.execute_query("insert into approach_1_test select * from ids_test_3")
    new_list = dbase.get_new_macs()
    intrusion_detection.identify_macs(new_list
    )

def main():
    #Import mac addresses into ids system
    intrusion_detection.load_macs()
    print("\n===================\nTESTING CLASSIFIERS AND APPROACHES ON TRAIN/TEST DATA...\n")
    test_split_data()

    print("\n===================\nTESTING CLASSIFIERS AND APPROACHES ON INDIVIDUAL PREVIOUSLY SEEN DEVICES...")
    test_seen_devices()

    print("\n===================\nTESTING CLASSIFIERS AND APPROACHES ON INDIVIDUAL UNSEEN DEVICES...")
    test_new_devices()

    print("\n===================\nTESTING IDS NEW DEVICE RECOGNITION...")
    test_ids_1()

    print("\n===================\nTESTING IDS CHANGED CLASSIFICATION RECOGNITION...")
    test_ids_2()

    print("\n===================\nTESTING IDS IRREGULAR BEHAVIOUR RECOGNITION...")
    test_ids_3()

if __name__ == '__main__':
    main()
    

