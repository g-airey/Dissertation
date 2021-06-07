import os, datetime, pyshark, sqlite3
import pandas as pd

conn = None

#MAC address of the router so that it is not added to the database
router = "ae:b6:d0:e3:65:77"

#List of devices, used for training the classifiers
device_list = {"38:8b:59:65:d3:13":"iot", 
               "34:69:87:57:e5:ed":"smartphone", 
               "48:60:5f:83:fb:47":"smartphone", 
               "80:32:53:f1:4b:62":"computer",
               "9c:b6:d0:e3:65:77":"computer",
               "18:3a:2d:d3:40:8e":"smartphone",
               "30:07:4d:1d:d8:62":"smartphone",
               "52:54:00:12:34:56":"smartphone",
               "50:dc:e7:ae:c7:40":"iot",
               "9c:b6:d0:98:bf:43":"computer"}

#List of classifiers used to gather results
classifier_list=("decision tree",
                 "random forest",
                 "gaussian NB",
                 "k neighbour")

#Creates sqlite connection to database
def create_connection():
    try:
        global conn
        conn = sqlite3.connect("ids", isolation_level='DEFERRED')
        print(sqlite3.version)
    except sqlite3.Error as e:
        print(e)

#Closes sqlite connection to database
def close_connection():
    global conn
    if(conn):
        conn.close()

#Creates indexes used for searching
def create_indexes():
    cur = conn.cursor()

    conn.commit()

#Drops indexes used for searching
def drop_indexes():
    cur = conn.cursor()

    conn.commit()

#Splits data into training and testing data
def split_data():
    cur = conn.cursor()
    #Delete data from tables
    tablenames = ["approach_1_training","approach_1_testing","approach_2_training","approach_2_testing"]
    for name in tablenames:
        clear_table(name)
    cur.execute('INSERT INTO approach_1_training SELECT * FROM approach_1 WHERE rowID % 20 != 0')
    cur.execute('INSERT INTO approach_1_testing SELECT * FROM approach_1 WHERE rowID % 20 = 0')
    cur.execute('INSERT INTO approach_2_training SELECT * FROM approach_2 WHERE rowID % 20 != 0')
    cur.execute('INSERT INTO approach_2_testing SELECT * FROM approach_2 WHERE rowID % 20 = 0')
    conn.commit()

#Adds training data to the database
def add_training_data():
    sql_approach_1 = '''INSERT INTO approach_1(mac, length, sourceport, destport, direction, classification) VALUES (?,?,?,?,?,?)'''
    sql_approach_2 = '''INSERT INTO approach_2_packets(mac, length, time, direction) VALUES (?,?,?,?)'''

    for filename in os.listdir("./caps"):
        count = 0
        approach_1_data = []
        approach_2_data = []
        if "cap" not in filename:
            continue
        print("Adding packets from " + filename)
        file = pyshark.FileCapture('./caps/' + filename)
        for packet in file:
            count += 1
            if(count % 1000 == 0):
                print(count)
            approach_1_output = add_training_packets_approach_1(packet, background_traffic= False)
            if approach_1_output != None:
                approach_1_data += [approach_1_output]
            approach_2_data += add_training_packets_approach_2(packet)
                
        cur = conn.cursor()
        cur.execute("begin")
        cur.executemany(sql_approach_1,approach_1_data)
        cur.executemany(sql_approach_2,approach_2_data)
        cur.execute("commit")
        
        file.close()
        os.rename("./caps/" + filename, "./caps/Used/" + filename)
    #Once all files have been imported, split the data    
    split_data()

#Extracts features from a packet for approach 1
def add_training_packets_approach_1(packet, background_traffic):
    #If source device is one that we already know
    if packet.eth.src in device_list:
        #If we are not investigating background traffic ignore any packets between 2 devices on the network
        if background_traffic == False and packet.eth.dst in device_list:
            return
        mac = packet.eth.src
        direction = 1
        classification = device_list[packet.eth.src]
    #If destination device is one that we already know
    elif packet.eth.dst in device_list:
        #If we are not investigating background traffic ignore any packets between 2 devices on the network
        if background_traffic == False and packet.eth.src in device_list:
            return
        mac = packet.eth.dst
        direction = 0
        classification = device_list[packet.eth.dst]
    #Otherwise we have a new device, which for training purposes we ignore
    else:
        return
    if(hasattr(packet,'tcp')):
        sourceport = packet.tcp.srcport
        destport = packet.tcp.dstport
    elif(hasattr(packet, 'udp')):
        sourceport = packet.udp.srcport
        destport = packet.udp.dstport
    else:
        return
    data = (mac, packet.length, sourceport, destport, direction, classification)
    return data

#Extracts features from a packet for approach 2
def add_training_packets_approach_2(packet):
    data = []
    if packet.eth.src in device_list:
        direction = 'outbound'
        data += [(packet.eth.src, packet.length, packet.sniff_time, direction)]
    if packet.eth.dst in device_list:
        direction = 'inbound'
        data += [(packet.eth.dst, packet.length, packet.sniff_time, direction)]
    return data


#Splits packets into time segments and inserts them into database
def setup_approach_two(input_table, output_table,interval):
    clear_table(output_table)
    cur = conn.cursor()
    sql = '''INSERT INTO {}(mac, avg_length, outbound, inbound, count, classification) VALUES (?,?,?,?,?,?)'''.format(output_table)
    for device in device_list:
        current_time = None
        total_length = 0
        count = 0
        inbound = 0
        outbound = 0
        to_db = []
        for row in get_device_info_from_table(device, input_table):
            try:
                element = datetime.datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                continue
            timestamp = datetime.datetime.timestamp(element)
            if(current_time == None):
                current_time = timestamp
            elif(timestamp - current_time > interval):
                #finished with that segment, add packets to database and add classification before resetting
                output = (row[0], (total_length / count), outbound, inbound, count, device_list[device])
                to_db += [output]
                total_length = 0
                outbound = 0
                count = 0
                inbound = 0
                current_time = timestamp
            if(row[3] == 'outbound'):
                outbound += 1
            else:
                inbound += 1
            total_length += row[1]
            count += 1
        cur.executemany(sql, to_db)
        conn.commit()
        split_data()



#Adds a new mac address to the devices table
def add_mac_to_db(mac):
    information = (mac,)
    sql = '''INSERT OR IGNORE INTO DEVICES(mac) VALUES(?)'''
    cur = conn.cursor()
    cur.execute(sql,information)
    conn.commit()
    
#Updates the ip of a device within the database
def update_ip(mac, ip):
    information = (ip, mac)
    sql = '''UPDATE DEVICES SET IP = ? WHERE MAC = ?'''
    cur = conn.cursor()
    cur.execute(sql,information)
    conn.commit()

#Gets a list of ips for a device
def get_ips(mac):
    mac = (mac,)
    
    cur = conn.cursor()
    sql = ("SELECT DISTINCT ip_source FROM PACKETS WHERE mac_source = ?")
    cur.execute(sql, mac)
    rows = cur.fetchall()
    ips = []

    for row in rows:
        ips += [row[0]]
    return ips
    
#Gets a list of all mac addresses and their classifications from the device table
def get_macs_classifications_from_db():
    information = {}
    cur = conn.cursor()
    cur.execute("SELECT mac, classification,confidence,classification_count FROM DEVICES")

    rows = cur.fetchall()

    for row in rows:
        #Output = mac, classification,average confidence, count
        information[row[0]] = [row[1],row[2],row[3]]
    return information

#Clears data from a specified table
def clear_table(table_name):
    cur = conn.cursor()
    cur.execute("DELETE FROM {}".format(table_name))
    conn.commit()

#Gets packets for a specified device from a specified table
def get_device_info_from_table(device, table_name):
    sql = '''SELECT * FROM {} WHERE mac = ?'''.format(table_name)
    information = (device, )
    cur = conn.cursor()
    cur.execute(sql, information)
    rows = cur.fetchall()
    return rows

#Updates the classification of a device
def update_classification(device, information):
    cur = conn.cursor()
    sql = 'UPDATE DEVICES SET classification = ?, confidence = ?, classification_count = ? where mac = "' + device + '"'
    cur.execute(sql, information)
    conn.commit()

#Writes a test result to the database
def write_result_to_db(approach, classifier, correct, confidence):
    cur = conn.cursor()
    information = (approach, classifier, correct, confidence)
    sql = 'INSERT INTO RESULTS VALUES (?,?,?,?)'
    cur.execute(sql,information)
    conn.commit()

#Adds an unseen device to the new device testing datbases
def add_new_devices_to_db(filename):
    file = pyshark.FileCapture('./caps/test/{}'.format(filename))
    sql_approach_1 = '''INSERT INTO ids_test_1(mac, length, sourceport, destport, direction, classification) VALUES (?,?,?,?,?,?)'''
    sql_approach_2 = '''INSERT INTO approach_2_packets_test(mac, length, time, direction) VALUES (?,?,?,?)'''
    approach_1_data = []
    approach_2_data = []
    count = 0
    for packet in file:
        count += 1
        if count % 1000 == 0:
            print(count)
        approach_1_output = add_training_packets_approach_1(packet, background_traffic= False)
        if approach_1_output != None:
            approach_1_data += [add_training_packets_approach_1(packet, background_traffic= False)]
        approach_2_data += add_training_packets_approach_2(packet)
    cur = conn.cursor()
    cur.execute("begin")
    cur.executemany(sql_approach_1,approach_1_data)
    cur.executemany(sql_approach_2,approach_2_data)
    cur.execute("commit")
        
    file.close()

#Analyses results from the results database table
def analyse_results_from_db():
    #print("\n\n======RESULTS======\n\n")
    cur = conn.cursor()
    for approach in (1,2):
        total_confidence = 0
        total_incorrect = 0
        count = 0
        cur.execute("SELECT * FROM results WHERE approach = {}".format(approach))
        for row in cur.fetchall():
            count += 1
            if(row[2] == "N"):
                total_incorrect += 1
            total_confidence += row[3]
        avg_confidence = total_confidence / count
        print("Approach {}: {} average confidence with {} incorrect results".format(approach, round(avg_confidence,3), total_incorrect))

    print("\n")
    for classifier in classifier_list:
        for approach in (1,2):
            total_confidence = 0
            total_incorrect = 0
            count = 0
            cur.execute("SELECT * FROM results WHERE classifier = '{}' AND approach = {}".format(classifier, approach))
            for row in cur.fetchall():
                count += 1
                if(row[2] == "N"):
                    total_incorrect += 1
                total_confidence += row[3]
            avg_confidence = total_confidence / count
            print("Classifier {} using Approach {}: {} average confidence with {} incorrect results".format(classifier, approach, round(avg_confidence,3), total_incorrect))
        



#Gets Approach 1 Training data 
def get_approach_1_training():
    return pd.read_sql_query("SELECT length, sourceport, destport, direction, classification FROM approach_1_training", conn)

#Gets Approach 1 Testing data
def get_approach_1_testing(mac, new):
    if mac == None:
        return pd.read_sql_query("SELECT length, sourceport, destport, direction, classification FROM approach_1_testing", conn)
    else: 
        if not new:
            return pd.read_sql_query("SELECT length, sourceport, destport, direction, classification FROM approach_1_testing where mac = '{}'".format(mac), conn)
        else:
            return pd.read_sql_query("SELECT length, sourceport, destport, direction, classification FROM approach_1_test where mac = '{}'".format(mac), conn)
#Gets Approach 2 Training data
def get_approach_2_training():
    return pd.read_sql_query("SELECT avg_length,outbound,inbound,count,classification FROM approach_2_training", conn)

#Gets Approach 2 Training data
def get_approach_2_testing(mac, new):
    if mac == None:
        return pd.read_sql_query("SELECT avg_length,outbound,inbound,count,classification FROM approach_2_testing", conn)
    else:
        if not new:
            return pd.read_sql_query("SELECT avg_length,outbound,inbound,count,classification FROM approach_2_testing where mac = '{}'".format(mac), conn)
        else:
            return pd.read_sql_query("SELECT avg_length,outbound,inbound,count,classification FROM approach_2_test where mac = '{}'".format(mac), conn)

#Gets the packets for a new device from the database
def get_new_device(mac):
    return pd.read_sql_query("SELECT length, sourceport, destport, direction, classification FROM approach_1_test where mac = '{}".format(mac), conn)

#Gets new devices from the database
def get_new_macs():
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT mac from approach_1_test")
    rows = cur.fetchall()
    macs = []
    for row in rows:
        macs += [row[0]]
    return macs

#Gets the connection to the database
def get_connection():
    global conn
    return conn

#Executes a specified query in the database
def execute_query(query):
    cur = conn.cursor()
    cur.execute(query)

def main():
    #add_training_data()
    #setup_approach_two("approach_2_packets","approach_2")
    #split_data()
    #analyse_results_from_db()
    add_new_devices_to_db('new_comp.pcap')
    #setup_approach_two("approach_2_packets_test","approach_2_test",20)
    close_connection()

#When started, create connection
create_connection()
if __name__ == "__main__":
    main()

