#/usr/bin/python

import argparse
import json
import os
import requests
import time

from requests.adapters import HTTPAdapter

instance_list = []
ip_list = []
instance_and_ip_list = []
instance_skip_list = []
failure_list_with_reason = {}

class Auth:

    auth_url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    auth_headers = {'Content-type': 'application/json'}

    def __init__(self, user, api_key):
        self.user = user
        self.api_key = api_key

    def auth_call(self):
        self.auth_data = json.dumps({"auth": {'RAX-KSKEY:apiKeyCredentials': {'username': self.user, 'apiKey': self.api_key}}})
        self.auth_request = requests.post(self.auth_url, data=self.auth_data, headers=self.auth_headers)
        self.token_raw = self.auth_request.json()['access']['token']['id']
        self.token = str(self.token_raw)
        return self.token
        
class Subnet:

    def __init__(self, region, network_uuid, token):
        self.region = region
        self.network_uuid = network_uuid
        self.token = token

    def subnet_call(self):
        self.subnet_headers = {'X-Auth-Token': self.token}
        self.subnet_url = "https://%s.networks.api.rackspacecloud.com/v2.0/subnets" % self.region
        self.subnet_request = requests.get(self.subnet_url, headers=self.subnet_headers)
        self.subnet_return = self.subnet_request.text
        self.subnets = json.loads(self.subnet_return)['subnets']
        for networks_json in self.subnets:
            if self.network_uuid in networks_json['network_id']:
                self.subnet_id = networks_json['id']
        if self.subnet_id == "":
            print "\nUnable to find network based on provided UUID"
            quit()
        return self.subnet_id
        
#RETRY CLASS TO IMPLEMENT RETRY LOGIC ON PORT AND VIRTUAL INTERFACE DELETE/CREATE
class RetryHTTPAdapter(HTTPAdapter):

    SECONDS_BETWEEN_RETRIES = 10

    def __init__(self, retry_time=120, *args, **kwargs):
        self.retry_time = retry_time
        super(RetryHTTPAdapter, self).__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        for _ in range(int(self.retry_time / self.SECONDS_BETWEEN_RETRIES)):
            response = super(RetryHTTPAdapter, self).send(*args, **kwargs)
            if response.status_code in (200, 201, 202, 203, 204):
                break
            time.sleep(self.SECONDS_BETWEEN_RETRIES)
        return response

s = requests.Session()
s.mount('http://', RetryHTTPAdapter(retry_time=60))
s.mount('https://', RetryHTTPAdapter(retry_time=60))

#EXAMPLE USAGE
#s.get('http://example.com')

#This will list all ports for a datacenter and grab the instance UUIDs based on source network ID
def find_instances_nofile(region,token,src_network,ddi,dst_network):
    #Need to implement a CIDR check to make sure both networks are viable for transfer
    network_url = 'https://%s.servers.api.rackspacecloud.com/v2/%s/os-networksv2/%s' % (region, ddi, src_network)
    network_headers = {'X-Auth-Token': token}
    network_request = s.get(network_url, headers=network_headers)
    src_cidr = network_request.json()['network']['cidr']
    
    network_url = 'https://%s.servers.api.rackspacecloud.com/v2/%s/os-networksv2/%s' % (region, ddi, dst_network)
    network_request = s.get(network_url, headers=network_headers)
    dst_cidr = network_request.json()['network']['cidr']
    
    if str(src_cidr) != str(dst_cidr):
        print "\nThe source and destination networks appear to be different. Please ensure that both networks are the exact same."
        print "\nQuitting..."
        quit()
    
    port_url = 'https://%s.networks.api.rackspacecloud.com/v2.0/ports' % region
    port_headers = {'X-Auth-Token': token}
    port_request = s.get(port_url, headers=port_headers)
    for port in port_request.json()['ports']:
        if port['network_id'] == src_network:
            instance_list.append(port['device_id'])
    
    #If the port query returns a "next" URL then there is more than 100 ports and we need to loop through them
    if port_request.json()['ports_links'][0]['rel'] == 'next':
        query_url = port_request.json()['ports_links'][0]['href'].split("?")[1]
        port_url = 'https://%s.networks.api.rackspacecloud.com/v2.0/ports?%s' % (region, query_url)
        port_request = s.get(port_url, headers=port_headers)
        for port in port_request.json()['ports']:
            if port['network_id'] == src_network:
                instance_list.append(port['device_id'])

    #Find the IPs associated with the instance UUIDs I gather previously
    for uuid in instance_list:
        servers_endpoint = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2' % (region, ddi, uuid)
        servers_headers = {'Accept': 'application/json','Content-Type': 'application/json','X-Auth-Token': token}
        servers_request = s.get(servers_endpoint, headers=servers_headers)
        servers_return = servers_request.text
        if servers_request.status_code not in (201, 200):
            print "\nVirtual Interface List failed, skipping instance : " + str(uuid)
            print "\nError Returned :\n"
            instance_list.remove(uuid)
            print servers_return
            failure_list_with_reason[uuid] = servers_request.text
            continue
        virtual_interfaces = json.loads(servers_return)['virtual_interfaces']
        for network in virtual_interfaces:
            ip_addresses = network['ip_addresses']
            for ip in ip_addresses:
                if ip['network_id'] == src_network:
                    ip_list.append(ip['address'])

    if test_ip_match == True:
        print "\nTest mode detected, printing Instance and IP list..."
        print "\nInstance and IP list"
        print zip(instance_list, ip_list)
        print "\nQuitting..."
        quit()

#For loop through instance list and find out the associated IPs for the defined network
def identify_current_networks(user,region,token,src_network,instance_file, dst_network):
    if os.path.isfile(instance_file) == True:
        with open(instance_file) as file:
            content = [x.strip('\n') for x in file.readlines()]
            for uuid in content:
                instance_list.append(uuid)
    else:
        print "\nInstance file not found! Quitting..."
        quit()
        
    if len(instance_list[0]) != 36:
        print "\nThe first variable in the instance list doesn't appear to be 36 characters, did you use the instance file option instead of the instanceipfile option?"
        print "\nQuitting..."
        quit()
        
    #CIDR check to make sure both networks are viable for transfer
    network_url = 'https://%s.servers.api.rackspacecloud.com/v2/%s/os-networksv2/%s' % (region, ddi, src_network)
    network_headers = {'X-Auth-Token': token}
    network_request = s.get(network_url, headers=network_headers)
    src_cidr = network_request.json()['network']['cidr']
    
    network_url = 'https://%s.servers.api.rackspacecloud.com/v2/%s/os-networksv2/%s' % (region, ddi, dst_network)
    network_request = s.get(network_url, headers=network_headers)
    dst_cidr = network_request.json()['network']['cidr']
    
    if str(src_cidr) != str(dst_cidr):
        print "\nThe source and destination networks appear to be different. Please ensure that both networks are the exact same."
        print "\nQuitting..."
        quit()
    
    for uuid in instance_list:
        servers_endpoint = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2' % (region, ddi, uuid)
        servers_headers = {'Accept': 'application/json','Content-Type': 'application/json','X-Auth-Token': token}
        #servers_request = requests.get(servers_endpoint, headers=servers_headers)
        servers_request = s.get(servers_endpoint, headers=servers_headers)
        servers_return = servers_request.text
        if servers_request.status_code not in (201, 200):
            print "\nVirtual Interface List failed, skipping instance : " + str(uuid)
            print "\nError Returned :\n"
            instance_list.remove(uuid)
            print servers_return
            failure_list_with_reason[uuid] = servers_request.text
            continue
        virtual_interfaces = json.loads(servers_return)['virtual_interfaces']
        for network in virtual_interfaces:
            ip_addresses = network['ip_addresses']
            for ip in ip_addresses:
                if ip['network_id'] == src_network:
                    ip_list.append(ip['address'])

#Logic check to ensure we were able to pull all the IPs for each server    
    if len(instance_list) != len(ip_list):
        print "\nNumber of instances and number of IPs the script pulled does not match. Something went wrong..."
        print "\nInstance List : " + str(instance_list)
        print "\nIP List : " + str(ip_list)
        print "\nQuitting..."
        quit()
    
    if test_ip_match == True:
        print "\nTest mode detected, printing Instance and IP list..."
        print "\nInstance and IP list"
        print zip(instance_list, ip_list)
        print "\nQuitting..."
        quit()
    
def identify_current_networks_with_ip_list(user,region,token,src_network,instance_ip_file,dst_network):
    if os.path.isfile(instance_ip_file) == True:
        with open(instance_ip_file) as inf:
            for line in inf:
                parts = line.split()
                if len(parts) > 1:
                    instance_list.append(parts[0])
                    ip_list.append(parts[1])
                    
    else:
        print "Instance and IP file not found! Quitting..."
        quit()

    if len(ip_list) == 0:
        print "\nCouldn't find any IPs in the file provided! Are you sure you meant to use instanceipfile and not instancefile?"
        print "\nQuitting..."
        quit()

    #CIDR check to make sure both networks are viable for transfer
    network_url = 'https://%s.servers.api.rackspacecloud.com/v2/%s/os-networksv2/%s' % (region, ddi, src_network)
    network_headers = {'X-Auth-Token': token}
    network_request = s.get(network_url, headers=network_headers)
    src_cidr = network_request.json()['network']['cidr']
    
    network_url = 'https://%s.servers.api.rackspacecloud.com/v2/%s/os-networksv2/%s' % (region, ddi, dst_network)
    network_request = s.get(network_url, headers=network_headers)
    dst_cidr = network_request.json()['network']['cidr']
    
    if str(src_cidr) != str(dst_cidr):
        print "\nThe source and destination networks appear to be different. Please ensure that both networks are the exact same."
        print "\nQuitting..."
        quit()

    instance_and_ip_list = zip(instance_list, ip_list)

    #verify that the IP matches what was given
    for uuid_ip in instance_and_ip_list:
        servers_endpoint = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2' % (region, ddi, uuid_ip[0])
        servers_headers = {'Accept': 'application/json','Content-Type': 'application/json','X-Auth-Token': token}
        #servers_request = requests.get(servers_endpoint, headers=servers_headers)
        servers_request = s.get(servers_endpoint, headers=servers_headers)
        servers_return = servers_request.text
        if servers_request.status_code not in (201, 200):
            print "\nVirtual Interface List failed, skipping instance : " + str(uuid_ip[0])
            print "\nError Returned :\n"
            print servers_return
            instance_skip_list.append(uuid_ip)
            failure_list_with_reason[uuid_ip[0]] = servers_request.text
            continue
        virtual_interfaces = json.loads(servers_return)['virtual_interfaces']
        for network in virtual_interfaces:
            ip_addresses = network['ip_addresses']
            for ip in ip_addresses:
                if ip['network_id'] == src_network:
                    if ip['address'] == uuid_ip[1]:
                        continue
                    else:
                        print "\nIP provided in file does not match what the script found in Neutron for instance UUID : " + str(uuid_ip[0])
                        print "\nThis instance will not be removed from the network and must be checked manually"
                        instance_skip_list.append(uuid_ip)
                        failure_list_with_reason[uuid_ip[0]] = 'IP provided in file does not match what the script found in Neutron for this instance'
    
    if test_ip_match == True:
        print "\nTest mode detected, printing Instance and IP list..."
        print "\nInstance and IP list"
        print zip(instance_list, ip_list)
        print "\nQuitting..."
        quit()

#Now we need to delete the current virtual interface and add the new port and virtual interface    
def remove_and_add_network(user,region,token,src_network,dst_network, dst_subnet_id,ddi,instance_and_ip_list):
    #If the instance and ip list was provided use this
    if len(instance_and_ip_list) > 0:
        
        #Remove skipped instances
        if len(instance_skip_list) > 0:
            instance_and_ip_list = [(x,y) for (x,y) in instance_and_ip_list if (x,y) not in instance_skip_list]
            
        #Delete the virtual interface to get rid of all the Cloud Networks components then add new port and virtual interface
        for uuid_ip in instance_and_ip_list:
            
            #Add port to Neutron
            port_url = 'https://%s.networks.api.rackspacecloud.com/v2.0/ports' % region
            port_data = json.dumps({"port":{"admin_state_up": "true","device_id": uuid_ip[0],"name": "","fixed_ips": [{"ip_address": uuid_ip[1],"subnet_id": dst_subnet_id},"network_id": dst_network]}})
            port_headers = {'Content-Type': 'application/json','Accept': 'application/json','X-Auth-Token': token}
            port_request = s.post(port_url, headers=port_headers, data=port_data)
            #port_request = requests.post(port_url, headers=port_headers, data=port_data)
            port_return = port_request.text
            print "\nPort Create Response: \n" + str(port_return)
            if port_request.status_code not in (201, 200):
                print "\nPort Create Failed With Response Code : " + str(port_request.status_code)
                print "\nSkipping port Deletion and Virtual Interface Create for Instance : " + str(uuid_ip[0])
                failure_list_with_reason[uuid_ip[0]] = port_request.text
                time.sleep(5)
                continue

            time.sleep(5)
            
            #Delete the virtual interface
            virtual_interface_id = ''
            servers_endpoint = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2' % (region, ddi, uuid_ip[0])
            servers_headers = {'Accept': 'application/json','Content-Type': 'application/json','X-Auth-Token': token}
            #servers_request = requests.get(servers_endpoint, headers=servers_headers)
            servers_request = s.get(servers_endpoint, headers=servers_headers)
            servers_return = servers_request.text
            virtual_interfaces = json.loads(servers_return)['virtual_interfaces']
            for interface in virtual_interfaces:
                ip_addresses = interface['ip_addresses']
                for ip in ip_addresses:
                    if ip['network_id'] == src_network:
                        virtual_interface_id = interface['id']

            servers_endpoint = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2/%s' % (region, ddi, uuid_ip[0], virtual_interface_id)
            servers_request = requests.delete(servers_endpoint, headers=servers_headers)
            servers_response = servers_request.text
            print "\nDelete virtual interface response : \n" + str(servers_response)

            #While loop should start here
            #Verify that the network is gone
            print "\nVerifying network has been removed..."

            while True:
                servers_endpoint = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2' % (region, ddi, uuid_ip[0])
                servers_headers = {'Accept': 'application/json','Content-Type': 'application/json','X-Auth-Token': token}
                #servers_request = requests.get(servers_endpoint, headers=servers_headers)
                servers_request = s.get(servers_endpoint, headers=servers_headers)
                servers_return = servers_request.text
                virtual_interfaces = json.loads(servers_return)['virtual_interfaces']
                network_id_list = []
                for interface in virtual_interfaces:
                    ip_addresses = interface['ip_addresses']
                    for ip in ip_addresses:
                        network_id_list.append(ip['network_id'])
                if src_network not in network_id_list:
                    break
                else:
                    print "\nNetwork still detected in virtual interface list... waiting 5 seconds and checking again"
                time.sleep(5)

            
            #Add Virtual Interface through Nova
            virt_url = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2' % (region, ddi, uuid_ip[0])
            virt_data = json.dumps({'virtual_interface': {'network_id': dst_network}})
            virt_headers = {'Accept': 'application/json','Content-Type': 'application/json','X-Auth-Token': token}
            virt_request = s.post(virt_url, headers=virt_headers, data=virt_data)
            #virt_request = requests.post(virt_url, headers=virt_headers, data=virt_data)
            virt_return = virt_request.text
            print "\nVirtual Interface Create Response: \n" + str(virt_return)
            if virt_request.status_code not in (201, 200):
                print "\nVirtual Interface creation failed with status code : " + str(virt_request.status_code)
                print "\nInstance : " +str(uuid_ip[0]) + " needs to have a virtual interface created for it manually"
                failure_list_with_reason[uuid_ip[0]] = virt_request.text
            
            #Check virtual interface create for success and add retry and failure logic
            #Place holder for retry and check logic
            
            time.sleep(2)

        if len(failure_list_with_reason) > 0:
            print "\nDictionary of servers that failed and their error codes : \n" + str(failure_list_with_reason)

    else:
        #IP file not provided, have to use the IP list generated from identify_current_networks_with_ip_list function
        instance_and_ip_list = zip(instance_list, ip_list)
        
        if len(instance_skip_list) > 0:
            instance_and_ip_list = [(x,y) for (x,y) in instance_and_ip_list if (x,y) not in instance_skip_list]
        
        if len(instance_and_ip_list) == 0:
            print "\nInstance and IP list empty, Quitting..."
            quit()
        #Delete the virtual interface to get rid of all the Cloud Networks components and add the new Port and Virtual Interface
        for uuid_ip in instance_and_ip_list:
            
            #Add port to Neutron
            port_url = 'https://%s.networks.api.rackspacecloud.com/v2.0/ports' % region
            port_data = json.dumps({"port":{"admin_state_up": "true","device_id": uuid_ip[0],"name": "","fixed_ips": [{"ip_address": uuid_ip[1],"subnet_id": dst_subnet_id}],"network_id": dst_network}})
            port_headers = {'Content-Type': 'application/json','Accept': 'application/json','X-Auth-Token': token}
            port_request = s.post(port_url, headers=port_headers, data=port_data)
            #port_request = requests.post(port_url, headers=port_headers, data=port_data)
            port_return = port_request.text
            print "\nPort Create Response: \n" + str(port_return)
            if port_request.status_code not in (201, 200):
                print "\nPort Create Failed With Response Code : " + str(port_request.status_code)
                print "\nSkipping port Deletion and Virtual Interface Create for Instance : " + str(uuid_ip[0])
                failure_list_with_reason[uuid_ip[0]] = port_request.text
                time.sleep(5)
                continue

            time.sleep(5)
            
            virtual_interface_id = ''
            servers_endpoint = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2' % (region, ddi, uuid_ip[0])
            servers_headers = {'Accept': 'application/json','Content-Type': 'application/json','X-Auth-Token': token}
            #servers_request = requests.get(servers_endpoint, headers=servers_headers)
            servers_request = s.get(servers_endpoint, headers=servers_headers)
            servers_return = servers_request.text
            virtual_interfaces = json.loads(servers_return)['virtual_interfaces']
            for interface in virtual_interfaces:
                ip_addresses = interface['ip_addresses']
                for ip in ip_addresses:
                    if ip['network_id'] == src_network:
                        virtual_interface_id = interface['id']

            servers_endpoint = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2/%s' % (region, ddi, uuid_ip[0], virtual_interface_id)
            servers_request = requests.delete(servers_endpoint, headers=servers_headers)
            servers_response = servers_request.text
            print "\nDelete virtual interface response : \n" + str(servers_response)

            #While loop should start here
            #Verify that the network is gone
            print "\nVerifying network has been removed..."

            while True:
                servers_endpoint = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2' % (region, ddi, uuid_ip[0])
                servers_headers = {'Accept': 'application/json','Content-Type': 'application/json','X-Auth-Token': token}
                #servers_request = requests.get(servers_endpoint, headers=servers_headers)
                servers_request = s.get(servers_endpoint, headers=servers_headers)
                servers_return = servers_request.text
                virtual_interfaces = json.loads(servers_return)['virtual_interfaces']
                network_id_list = []
                for interface in virtual_interfaces:
                    ip_addresses = interface['ip_addresses']
                    for ip in ip_addresses:
                        network_id_list.append(ip['network_id'])
                if src_network not in network_id_list:
                    break
                else:
                    print "\nNetwork still detected in virtual interface list... waiting 5 seconds and checking again"
                time.sleep(5)
    
            #Add Virtual Interface through Nova
            virt_url = 'https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2' % (region, ddi, uuid_ip[0])
            virt_data = json.dumps({'virtual_interface': {'network_id': dst_network}})
            virt_headers = {'Accept': 'application/json','Content-Type': 'application/json','X-Auth-Token': token}
            virt_request = s.post(virt_url, headers=virt_headers, data=virt_data)
            #virt_request = requests.post(virt_url, headers=virt_headers, data=virt_data)
            virt_return = virt_request.text
            print "\nVirtual Interface Create Response: \n" + str(virt_return)
            if virt_request.status_code not in (201, 200):
                print "\nVirtual Interface creation failed with status code : " + str(virt_request.status_code)
                print "\nInstance : " +str(uuid_ip[0]) + " needs to have a virtual interface created for it manually"
                failure_list_with_reason[uuid_ip[0]] = virt_request.text
            
            #Check virtual interface create for success and add retry and failure logic
            #Place holder for retry and check logic

            time.sleep(2)
            
        if len(failure_list_with_reason) > 0:
            print "\nDictionary of servers that failed and their error codes : \n" + str(failure_list_with_reason)

parser = argparse.ArgumentParser()

parser.add_argument('--ddi',
required=True,
default=None,
help='The account number or DDI')

parser.add_argument('--instanceipfile',
required=False,
default=None,
help='The file containing the server UUIDS and IPs side by side seperated by white space')

parser.add_argument('--instancefile',
required=False,
default=None,
help='The file containing the server UUIDs we are moving to the new network')

parser.add_argument('--user',
required=True,
default=None,
help='The primary user for the account')

parser.add_argument('--apikey',
required=True,
default=None,
help='Account apikey')

parser.add_argument('--srcnetwork',
required=True,
default=None,
help='The source network we are moving IPs from')

parser.add_argument('--dstnetwork',
required=True,
default=None,
help='The destination network we are moving IPs to')

parser.add_argument('--region',
required=True,
default=None,
help='The region the cloud networks are in')

parser.add_argument('--test',
required=False,
default=None,
action='store_true',
help='Test the IP and instance match logic and see what servers will attempt to move')

args = parser.parse_args()

region = args.region
src_network = args.srcnetwork
dst_network = args.dstnetwork
api_key = args.apikey
user = args.user
ddi = args.ddi
instance_file = args.instancefile
instance_ip_file = args.instanceipfile
test_ip_match = args.test

token_return = Auth(user,api_key)
token = token_return.auth_call()

network_uuid = src_network
subnet_return = Subnet(region, network_uuid, token)
src_subnet_id = subnet_return.subnet_call()

network_uuid = dst_network
subnet_return = Subnet(region, network_uuid, token)
dst_subnet_id = subnet_return.subnet_call()

if __name__ == '__main__':
    if instance_ip_file:
        print "\nInstance and IPs mode detected..."
        identify_current_networks_with_ip_list(user,region,token,src_network,instance_ip_file,dst_network)
        remove_and_add_network(user,region,token,src_network,dst_network, dst_subnet_id,ddi,instance_and_ip_list)
    elif instance_file:
        print "\nInstance UUID only mode detected..."
        identify_current_networks(user,region,token,src_network,instance_file,dst_network)
        remove_and_add_network(user,region,token,src_network,dst_network, dst_subnet_id,ddi,instance_and_ip_list)
        
    else:
        print "\nNo file provided, will transfer all instances on source network to destination..."
        find_instances_nofile(region,token,src_network,ddi,dst_network)
        remove_and_add_network(user,region,token,src_network,dst_network, dst_subnet_id,ddi,instance_and_ip_list)
