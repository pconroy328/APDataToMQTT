# sudo apt-get install python-dev
# sudo pip install psutil or sudo apt-get install python3-psutil
# pip3 install paho-mqtt
# pip3 install zeroconf


from datetime import timedelta
import socket
from subprocess import check_output
import json
import datetime
from collections import OrderedDict
import os
import psutil
import paho.mqtt.client as mqtt
import logging
import time
import sys
import subprocess
import re
import csv


# ----------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------
class NetworkInterfaces(object):
    version = "0.1 ()"

    # ------------------------------------------------------------------------------------------------------------------
    def get_ip_addresses(self,family):
        for interface, snics in psutil.net_if_addrs().items():
            for snic in snics:
                if snic.family == family:
                    yield (interface, snic.address)
    
    # ------------------------------------------------------------------------------------------------------------------
    def get_connected_client_data(self, interface):
        signal_avg = None
        expected_thruput = None
        connect_time_secs = None
        mac_addr = None
        num_stations = 0

        # Dictionary to store station details
        stations = {}
        
        try:
            command = "iw dev " + interface + " station dump"
            output = subprocess.check_output(command, shell=True).decode('utf-8')
            ## Station 0c:8b:95:aa:b8:f0 (on wlx00c140510104)
            ## 	inactive time:	9752 ms
            ## 		rx bytes:	6074902
            ## 		rx packets:	113023
            ## 		tx bytes:	2142543
            ## 		tx packets:	25806
            ## 		tx retries:	29099
            ## 		tx failed:	262
            ## 		rx drop misc:	1954
            ## 		signal:  	-33 dBm
            ## 		signal avg:	-38 dBm
            ## 		tx bitrate:	72.2 MBit/s MCS 7 short GI
            ## 		tx duration:	0 us
            ## 		rx bitrate:	1.0 MBit/s
            ## 		rx duration:	0 us
            ## 		expected throughput:	21.240Mbps
            ## 		authorized:	yes
            ## 		authenticated:	yes
            ## 		associated:	yes
            ## 		preamble:	short
            ## 		WMM/WME:	yes
            ## 		MFP:		no
            ## 		TDLS peer:	no
            ## 		DTIM period:	2
            ## 		beacon interval:100
            ## 		short slot time:yes
            ## 		connected time:	170543 seconds
            ## 		associated at [boottime]:	1048.269s
            ## 		associated at:	1711234188512 ms
            ## 		current time:	1711404731309 ms


            # Split the output into sections for each station
            sections = output.strip().split('Station')
            
            # Process each section
            for section in sections[1:]:  # Skip the first empty section
                ##print( ">>> Section:", section )
                lines = section.strip().split('\n')

                ##print( ">>> lines", lines )
                # Extract MAC address
                mac_match = re.match(r'\s*([\w:]+)\s', lines[0])
                if mac_match:
                    mac_addr = mac_match.group(1)

                for a_line in lines:
                    if 'signal avg:' in a_line:
                        signal_avg = a_line.split("signal avg:")[1].split("\n")[0].strip()

                    if 'expected throughput:' in a_line:
                        expected_thruput = a_line.split("expected throughput:")[1].split("\n")[0].strip()

                    if 'connected time:' in a_line:
                        connect_time_secs = a_line.split("connected time:")[1].split("\n")[0].strip()

                stations[mac_addr] = ( {"mac": mac_addr, "avg_signal": signal_avg, "exp_thruput": expected_thruput, "connect_time": connect_time_secs } )
                num_stations += 1
                ##print( stations[mac_addr])


        except subprocess.CalledProcessError:
            logging.error("Error running 'iw' command. Make sure the 'iw' tool is installed and the wireless interface is correct.")

        return num_stations, stations

    # ------------------------------------------------------------------------------------------------
    def get_type_ssid_mac(self, interface):
        ssid = ""
        itype = None
        mac_addr = None
        
        try:
            # Run the 'iw' command to get information about the wireless interface
            command = "iw dev " + interface + " info"
            ##Interface wlx00c140510104
            ##	    ifindex 7
            ##		wdev 0x300000001
            ##		addr 00:c1:40:51:01:04
            ##		ssid CONROY31FK
            ##		type AP
            ##		wiphy 3
            ##		channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
            ##		txpower 30.00 dBm
            ##		multicast TXQ:
            ##			qsz-byt	qsz-pkt	flows	drops	marks	overlmt	hashcol	tx-bytes	tx-packets
            ##			0	0	1894	0	0	0	0	121774		1894

            output = subprocess.check_output(command, shell=True)
            output_str = output.decode('utf-8')

            # Extract SSID, MAC address, and type
            if 'ssid' in output_str:
                ssid = output_str.split("ssid ")[1].split("\n")[0].strip()
            if 'addr' in output_str:
                mac_addr = output_str.split("addr ")[1].split("\n")[0].strip()
            if 'type' in output_str:
                itype = output_str.split("type ")[1].split("\n")[0].strip()

        except subprocess.CalledProcessError:
            logging.error("Error running 'iw' command. Make sure the 'iw' tool is installed and the wireless interface is correct.")

        return itype, ssid, mac_addr

    # ---------------------------------------------------------------
    def parse_arp_table(self,interface):
        arp_output = subprocess.check_output(['arp', '-a', '-i', interface]).decode('utf-8')
        ##arp_entries = []
        arp_entries = []

        for line in arp_output.split('\n'):
            # Extract hostname from the first line of the arp output
            first_line_match = re.match(r'(\S+)\s+', line)
            hostname = first_line_match.group(1) if first_line_match else None

            if line.strip():
                # Use regular expressions to extract IP address, MAC address, and interface
                match = re.match(r'\S+\s+\((.*?)\)\s+at\s+([^\s]+)\s+\[ether\]\s+on\s+(\S+)', line)
                if match:
                    ip_address = match.group(1)
                    mac_address = match.group(2)
                    interface = match.group(3)
                    #arp_entries.append((hostname, ip_address, mac_address, interface))
                    arp_entries.append( {"host": hostname, "ip":ip_address, "mac":mac_address, "interface":interface})

        ##print(json.dumps(arp_entries))
        return arp_entries

    # Example usage:
    #arp_entries = parse_arp_table()
    #for entry in arp_entries:
        #print(f"IP Address: {entry[0]}, MAC Address: {entry[1]}, Interface: {entry[2]}")    # 

    # ---------------------------------------------------------------
    def get_interface_data(self):
        global master_host_dict

        data = []

        network_interfaces = list(self.get_ip_addresses(socket.AF_INET))

        for item in network_interfaces:
            if (item[0][:3] == "wlx") or (item[0][:3] == "wla"):
                itype, ssid, mac_addr = self.get_type_ssid_mac(item[0])
                if (itype == "AP"):
                    num_clients, station_data = self.get_connected_client_data(item[0])
                    ##
                    ## station_data comes back as a dictionary
                    ## key = client mac address, value = {'mac': '0c:8b:95:aa:b8:f0', 'avg_signal': '-38 dBm', 'exp_thruput': '26.91Mbps', 'connect_time': '170891 seconds'}

                    arp_data = self.parse_arp_table(item[0])

                    ##
                    ## arp_data comes back as a list of dictionaries
                    ## [{'host': '?', 'ip': '10.42.0.185', 'mac': '0c:8b:95:aa:b8:f0', 'interface': 'wlx00c140510104'}, 
                    ##  {'host': '?', 'ip': '10.42.0.197', 'mac': 'b0:a7:32:30:08:90', 'interface': 'wlx00c140510104'}, 
                    ##  {'host': '?', 'ip': '10.42.0.110', 'mac': 'd8:3a:dd:ec:80:f0', 'interface': 'wlx00c140510104'}]
                    ##print( "11111111111 ",  num_clients )
                    ##print( "22222222222 ", station_data )
                    ##print( "33333333333 ", arp_data )

                    ##
                    ## we're going to merge the two tables, we'll loop thru the station data and augment it with arp data
                    for a_station in station_data.values():
                        ## {'mac': '0c:8b:95:aa:b8:f0', 'avg_signal': '-38 dBm', 'exp_thruput': '26.91Mbps', 'connect_time': '170891 seconds'},
                        station_host = "--"
                        station_ip_addr = "x.x.x.x"
                        station_mac_str = a_station['mac']
                        station_signal = int(a_station['avg_signal'].split('dBm')[0])
                        station_thruput = float(a_station['exp_thruput'].split('Mbps')[0])
                        station_connect_secs = int(a_station['connect_time'].split('sec')[0])

                        ##
                        ## Now find that mac address in the arp data
                        for arp_entry in arp_data:
                            host = arp_entry['host']
                            ip_addr = arp_entry['ip']
                            arp_mac_str = arp_entry['mac']
                            if (station_mac_str == arp_mac_str):
                                station_host = host
                                station_ip_addr = ip_addr
                                break
                        
                        if (station_host == '?'):
                            #print( "looking", master_host_dict)
                            try:
                                station_host = master_host_dict[station_mac_str]
                            except:
                                logging.warn( "unable to find a host name for mac address " + mac_addr )

                        ##print( ">>>>>>>>>>>>>>> " + station_mac_str + "   " , station_signal, station_thruput, station_connect_secs, station_host, station_ip_addr )

                        a_dict = { 
                                    "hostname": station_host, "ip": station_ip_addr, "connect_secs": station_connect_secs, 
                                    "avg_signal": station_signal, "exp_thruput": station_thruput, "mac": station_mac_str 
                                  }
                        data.append( a_dict )
                else:
                    #wireless is not an ap
                    pass
            else:
                # not a wireless interface
                pass 

        return data

    # ------------------------------------------------------------------------------------------------
    def get_hostname(self):
        return os.uname()[1]

    # ------------------------------------------------------------------------------------------------
    def asJSON(self):
        myDict = OrderedDict({
            "topic": 'AP',
            "version": '1.0',
            "dateTime": datetime.datetime.now().replace(microsecond=0).isoformat(),
            "host": self.get_hostname(),
            "clients": self.get_interface_data(),
        })
        
        ##print( json.dumps(myDict))
        return json.dumps(myDict)

# ----------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------
class MessageHandler(object):
    def __init__(self, broker_address="mqtt.local"):
        # self.local_broker_address = ''
        self.broker_address = broker_address
        self.client = mqtt.Client(client_id="", clean_session=True, userdata=None)

    # ---------------------------------------------------------------------
    def on_connect(self, client, userdata, flags, rc):
        logging.info('Connected to the MQTT broker!')
        pass

    # ---------------------------------------------------------------------
    def on_message(self, client, userdata, message):
        logging.warning('Not expecting inbound messages')

    def start(self):
        logging.info('Message handling start - v1')
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        logging.info('Start - connecting to ' + self.broker_address)
        self.client.connect(self.broker_address)
        self.client.loop_start()

    def cleanup(self):
        self.client.disconnect()
        self.client.loop_stop()

    def send_ap_data(self):
        #logging.DEBUG('Sending Access Point data!')
        data = {}
        data['topic'] = 'APDATA'
        data['datetime'] = datetime.datetime.now().replace(microsecond=0).isoformat()
        json_data = NetworkInterfaces().asJSON()
        ##print(json_data)
        self.client.publish('APDATA', json_data, qos=0)


def discover_mqtt_host():
    from zeroconf import ServiceBrowser, Zeroconf
    host = None
    info = None

    def on_service_state_change(zeroconf, service_type, name, state_change):
        pass

    zeroconf = Zeroconf()
    browser = ServiceBrowser(zeroconf, "_mqtt._tcp.local.",
                             handlers=[on_service_state_change])
    i = 0
    while not host:
        time.sleep(0.1)
        if browser.services:
            service = list(browser.services.values())[0]
            info = zeroconf.get_service_info(service.name, service.alias)
            ##print('info', info)
            ##print('info.server', info.server)
            host = socket.inet_ntoa(info.address)
        i += 1
        if i > 50:
            break
    zeroconf.close()
    try:
        return info.server, host
    except AttributeError:
        return None


##print(SystemStats.version)
##logging.basicConfig(filename='/tmp/apdata.log', level=logging.INFO)
time_format = "%d%b%Y %H:%M:%S"
logging.basicConfig(format='%(asctime)s:%(levelname)s: %(message)s', datefmt=time_format, filename='/tmp/apdata.log', level=logging.INFO)

logging.info('AccessPointData v1.0 [new interfaces]')
logging.info('Version:' + NetworkInterfaces.version )
logging.debug('Attempting to find mqtt broker via mDNS')

try:
   host = sys.argv[1]
   mqtt_broker_address = sys.argv[1]
except:
   logging.warn( 'No host passed in on command line. Trying mDNS' )
   
   host = discover_mqtt_host()
   if (host is not None):
       mqtt_broker_address = host[0]
       logging.info( 'Found MQTT Broker using mDNS on {}.{}'.format(host[0], host[1]))
   else:
       logging.warning('Unable to locate MQTT Broker using DNS')
       try:
           mqtt_broker_address = sys.argv[1]
       except:
           logging.critical('mDNS failed and no MQTT Broker address passed in via command line. Exiting')
           sys.exit(1)

logging.debug('Connecting to {}'.format(mqtt_broker_address))
m = MessageHandler(broker_address=mqtt_broker_address)
m.start()


master_host_dict = {}
filename = 'hosts.csv'
logging.info( "Attempting to read hosts.csv file" )
with open(filename, mode ='r') as file:
  csvFile = csv.reader(file)
  for a_row in csvFile:
      if len(a_row) == 2:
          mac_addr = a_row[0].strip()
          ip_addr = a_row[1].strip()

          master_host_dict[mac_addr] = ip_addr

logging.info( "After loading csv file")
logging.info( master_host_dict )

while True:
    m.send_ap_data()
    time.sleep(60)
