
import logging
import os

import sys

import time
import json
from ipaddress import IPv4Network, ip_network
import traceback
import copy
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('=> %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

import azure.functions as func

import subprocess


credentials, compute_client, network_client = None, None, None

def waitfor(seconds=2, reason=None):
    if reason is not None:
        logger.info(f"Waiting for {seconds} seconds. Reason: {reason}")
    else:
        logger.info("Waiting for {seconds} seconds")
    time.sleep(seconds)


class HTTPNitro:
    def __init__(self, nsip, nsuser="nsroot", nspass="nsroot"):
        self.nsip = nsip
        self.nsuser = nsuser
        self.nspass = nspass
        self.timeout = (5, 60)

        self.headers = {}
        self.headers["Content-Type"] = "application/json"
        self.headers["X-NITRO-USER"] = self.nsuser
        self.headers["X-NITRO-PASS"] = self.nspass

    def construct_url(self, resource, id=None, action=None):
        # Construct basic get url
        url = f"http://{self.nsip}/nitro/v1/config/{resource}"

        # Append resource id
        if id is not None:
            url = f"{url}/{id}"

        # Append action
        if action is not None:
            url = f"{url}?action={action}"

        return url

    def hide_sensitive_data(self, data):
        for k, v in data.items():
            if k in ["password", "new_password"]:
                data[k] = "********"
            elif isinstance(v, dict):
                self.hide_sensitive_data(v)

    def do_request(self, resource, method, id=None, action=None, data=None, retries=3, headers=None):
        url = self.construct_url(resource, id, action)
        data_dump = copy.deepcopy(data)
        if data_dump: 
            self.hide_sensitive_data(data_dump)
        logger.debug(f"do_request method={method}  url={url}  data={data_dump}  retries={retries}")
        error = ""
        for attempt in range(retries+1):
            if attempt:
                waitfor(seconds=pow(2,attempt), reason="Waiting before retrying http request")
            try:
                import requests
                response = requests.request(method, url=url, json=data, headers=headers, timeout=self.timeout)
                logger.debug(f"response status={response.status_code}  text={response.text} attempt={attempt}")
                if response.ok:
                    if not response.text:
                        return None
                    try:
                        result = json.loads(response.text)
                        return result
                    except json.decoder.JSONDecodeError:
                        logger.error(f"do_request method={method}  url={url}  data={data_dump} response={response.text} attempt={attempt} failed. Reason: JSONDecodeError")
                        error = "JSONDecodeError"
                        pass
                else:
                    logger.error(f"do_request method={method}  url={url}  data={data_dump} response={response.text} status={response.status_code} attempt={attempt} failed.")
                    error = response.text
            except Exception as e:
                logger.error(f"do_request method={method}  url={url}  data={data_dump} attempt={attempt} failed. Reason: {str(e)}")
                error = str(e)
                pass
        raise ValueError(f"request url={url} method={method} failed. Reason: {error}")

    def change_default_password(self, new_pass):
        logger.info("Changing the default password")
        headers = {"Content-Type": "application/json"}
        payload = {
            "login": {
                "username": self.nsuser,
                "password": self.nspass,
                "new_password": new_pass
            }
        }
        self.do_request(resource="login", method="POST", data=payload, headers=headers, retries=5)
        self.nspass = new_pass
        self.headers["X-NITRO-PASS"] = self.nspass
        logger.info("Successfully changed default password")

    def check_connection(self):
        logger.info(f"Checking connection to {self.nsip}")
        headers = {"Content-Type": "application/json"}
        payload = {"login": {"username": self.nsuser, "password": self.nspass}}
        try:
            self.do_request(resource="login", method="POST", data=payload, headers=headers, retries=0)
            logger.info(f"Connection to {self.nsip} successful")
            return True
        except Exception as e:
            logger.error(f"Node {self.nsip} is not reachable. Reason:{str(e)}")
            return False
        
    def do_get(self, resource, id=None, action=None):
        return self.do_request(resource=resource, method="GET", id=id, action=action, headers=self.headers)

    def do_post(self, resource, data, id=None, action=None):
        return self.do_request(resource=resource, method="POST", id=id, action=action, data=data, headers=self.headers)

    def do_put(self, resource, data, id=None, action=None):
        return self.do_request(resource=resource, method="PUT", id=id, action=action, data=data, headers=self.headers)

    def do_delete(self, resource, id=None, action=None):
        return self.do_request(resource=resource, method="DELETE", id=id, action=action, headers=self.headers)

    def wait_for_reachability(self, max_time=120):
        logger.info(f"Waiting for {self.nsip} to be reachable")
        attempts = int(max_time / 5)

        url = self.construct_url(resource="login")

        headers = {}
        headers["Content-Type"] = "application/json"
        payload = {"login": {"username": self.nsuser, "password": self.nspass}}
        for i in range(attempts):
            try:
                import requests
                logger.debug(f"request: URL={url}")
                r = requests.post(url=url, headers=headers, json=payload, timeout=(5, 5))
                logger.debug(f"response status:{r.status_code} text:{r.text}")
                response = r.json()

                if (response["severity"] != "ERROR"
                    or "ForcePasswordChange is enabled" in response["message"]):
                    logger.info(f"{self.nsip} is now reachable")
                    return
                waitfor(5, "Waiting to make sure the packet engine is UP")
            except Exception as e:
                logger.error(f"Node {self.nsip} is not yet reachable. Reason:{str(e)}")
        raise ValueError(f"{self.nsip} is not reachable")
        
class CitrixADC(HTTPNitro):
    def __init__(self, nsip, nsuser="nsroot", nspass="nsroot"):
        super().__init__(nsip=nsip, nsuser=nsuser, nspass=nspass)

    def get_clip(self):
        logger.info(f"Trying to get the CLIP of the cluster from node {self.nsip}")
        try:
            result = self.do_get(resource="nsip?filter=type:CLIP")
            for ip_dict in result["nsip"]:
                if ip_dict["type"] == "CLIP":
                    logger.info(f"Successfully fetched CLIP {ip_dict['ipaddress']} from {self.nsip}")
                    return ip_dict["ipaddress"]
            logger.error(f"Could not fetch the CLIP of the cluster from node {self.nsip}")
            return False
        except Exception as e:
            logger.error(f"Could not fetch the CLIP of the cluster from node {self.nsip}. Reason: {str(e)}")
            return False

    def get_cluster_nodes(self):
        logger.info(f"Getting the nodes in the cluster")
        try:
            result = self.do_get(resource="clusternode")
            logger.info(f"Fetched cluster nodes: {result['clusternode']}")
            return result["clusternode"]
        except Exception as e:
            logger.error(f"Failed to fetch the clsuternodes. Reason: {str(e)}")
            return []
  
    def get_cluster_node_id(self, node_ip=None):
        if not node_ip:
            node_ip = self.nsip
        logger.info(f"Trying to get the cluster node-id of {node_ip}")
        try:
            result = self.do_get(resource="clusternode")
            nodes = result["clusternode"]
            for node in nodes:
                if node["ipaddress"] == node_ip:
                    logger.info(f"Successfully fetched cluster node id {node['nodeid']}")
                    return node["nodeid"]
            logger.error(f"Cloud not fetch the cluster node-id")
            return -1
        except Exception as e:
            logger.error(f"Faied to fetch the cluster node-id. Reason {str(e)}")
            return -1

    def add_cluster_instance(self, instID):
        logger.info(f"Adding cluster instance {instID} on node {self.nsip}")
        data = {
            "clusterinstance": {
                "clid": str(instID),
            }
        }
        self.do_post(resource="clusterinstance", data=data)
        logger.info(f"Successfully added cluster instance {instID} on {self.nsip}")
        
    def enable_cluster_instance(self, instID):
        logger.info(f"Enabling cluster instance {instID} on {self.nsip}")
        data = {
            "clusterinstance": {
                "clid": str(instID),
            }
        }
        self.do_post(resource="clusterinstance", data=data, action="enable")
        logger.info(f"Successfully enabled cluster instance {instID} on {self.nsip}")

    def add_cluster_node(self, nodeID, nodeIP, backplane, tunnelmode, state):
        logger.info(f"Adding cluster node {nodeID}/{nodeIP}")
        data = {
            "clusternode": {
                "nodeid": str(nodeID),
                "ipaddress": nodeIP,
                "state": state,
                "backplane": backplane,
                "tunnelmode": tunnelmode,
            }
        }
        self.do_post(resource="clusternode", data=data)
        logger.info(f"Successfully added cluster node with ID:{nodeID} and nodeIP:{nodeIP}")

    def set_cluster_node(self, nodeID, state):
        logger.info(f"Setting cluster state to {state} on node {nodeID}")
        data = {
            "clusternode": {
                "nodeid": str(nodeID),
                "state": state,
            }
        }
        self.do_put(resource="clusternode", data=data)
        logger.info(f"Successfully set cluster node {nodeID} to state {state}")

    def remove_cluster_node(self, nodeID):
        logger.info(f"Removing cluster node {nodeID}")
        try:
            self.do_delete(resource="clusternode", id=str(nodeID))
            logger.info(f"Successfully removed cluster node {nodeID}")
        except Exception as e:
            logger.error(f"Failed to remove cluster node. Reason: {str(e)}")
   
    def enable_feature(self, features_list):
        logger.info(f"Enabling features {features_list} in {self.nsip}")
        data = {"nsfeature": {"feature": features_list}}
        self.do_post(resource="nsfeature", data=data, action="enable")
        logger.info(f"Successfully enabled features {features_list}")

    def configure_dns(self, nameserver):
        logger.info(f"Configuring {nameserver} as the DNS server on {self.nsip}")
        configs = [
          {"service": {"name": "awslbdnsservice0", "ip": nameserver, "servicetype":"DNS", "port":"53", "healthmonitor": "NO"}},
          {"lbvserver": {"name": "awslbdnsvserver", "servicetype": "DNS"}},
          {"lbvserver_service_binding": {"name": "awslbdnsvserver", "servicename": "awslbdnsservice0"}},
          {"dnsnameserver": {"dnsvservername": "awslbdnsvserver"}}
        ]

        for config in configs:
            self.do_post(resource=list(config.keys())[0], data=config)
        logger.info(f"Successfully configured {nameserver} as dns server")

    def add_ipset(self):
        logger.info(f"Adding ipset 'ipset1'")
        data = {"ipset": {"name":"ipset1"}}
        self.do_post(resource="ipset", data=data)
        logger.info("Successfully added ipset 'ipset1'")

    def bind_ipset(self, ipaddr):
        logger.info(f"Binding {ipaddr} to ipset1")
        data = {"ipset_nsip_binding": {"name": "ipset1", "ipaddress":ipaddr}}
        self.do_post(resource="ipset_nsip_binding", data=data)
        logger.info(f"Successfully bound IP {ipaddr} to ipset 'ipset1'")


    def unbind_ipset(self, ipaddr):
        logger.info(f"Unbinding {ipaddr} from ipset1")
        data = {"ipset_nsip_binding": {"name": "ipset1", "ipaddress":ipaddr}}
        binding_id="ipset1?args=ipaddress:"+ipaddr
        try:
            self.do_delete(resource="ipset_nsip_binding", id=binding_id)
            logger.info(f"Successfully unbound IP {ipaddr} from ipset 'ipset1'")
        except Exception as e:
            logger.error(f"Failed to unbinf ip from ipset. Reason: {str(e)}")
            
    def get_ipset_bindings(self):
        logger.info(f"Getting IPs bound to ipset 'ipset1")
        try:
            result = self.do_get(resource="ipset_nsip_binding", id="ipset1")
            logger.info(f"Successfully fetched ipset bindings: {result['ipset_nsip_binding']}")
            return result['ipset_nsip_binding']
        except Exception as e:
            logger.error(f"Failed to get ip set bindings. Reason:{str(e)}")
            return []

    def join_cluster(self, clip, password):
        logger.info(f"Joining node {self.nsip} to cluster with CLIP {clip}")
        data = {"cluster": {"clip": clip, "password": password}}
        self.do_post(resource="cluster", data=data, action="join")
        logger.info(f"Successfully joined cluster node {self.nsip}")

    def add_nsip(self, ip, netmask, ip_type, owner_node=-1):
        logger.info(f"Adding nsip {ip}/{netmask} type {ip_type} owner {owner_node}")
        data = {"nsip": {"ipaddress": ip, "netmask": netmask, "type": ip_type}}
        if owner_node != -1:
            data["nsip"]["ownernode"] = owner_node
        self.do_post(resource="nsip", data=data)
        logger.info(f"Successfully added NSIP {ip} with type {ip_type}")

    def del_nsip(self, ip):
        logger.info(f"Deleting ip {ip}")
        try:
            self.do_delete(resource="nsip", id=ip)
            logger.info(f"Successfully deleted IP {ip}")
        except Exception as e:
            logger.error(f"Failed to delete ip. Reason: {str(e)}")

    def save_config(self):
        logger.info(f"Saving the configuration")
        data = {"nsconfig": {}}
        self.do_post(resource="nsconfig", data=data, action="save")
        logger.info("Successfully saved nsconfig of {}".format(self.nsip))

    def reboot(self, warm=True):
        logger.info("Rebooting the netscaler")
        data = {"reboot": {"warm": warm}}
        self.do_post(resource="reboot", data=data)
        logger.info(f"Successfully accepted reboot request - {self.nsip}")
        
class Cluster(CitrixADC):
    def __init__(self, clip, nspass, nameserver="", vip_netmask="", mgmt_netmask="", server_netmask="", backplane="1/2", tunnelmode="GRE"):
        super().__init__(nsip=clip, nsuser="nsroot", nspass=nspass)
        self.clip = clip
        self.backplane = backplane
        self.tunnelmode = tunnelmode
        self.nameserver = nameserver
        self.vip_netmask = vip_netmask
        self.mgmt_netmask = mgmt_netmask
        self.server_netmask = server_netmask
   
    def wait_until_node_active(self, node_id):
        self.wait_for_reachability()
        logger.info(f"Waiting for node {node_id} to become ACTIVE")
        for _ in range(20):
            result = self.do_get(resource="clusternode", id=node_id)
            clusternode = result["clusternode"][0]
            if clusternode["masterstate"] == "ACTIVE":
                logger.info(f"Node {node_id} is now ACTIVE")
                return
            waitfor(10, f"Waiting for node id:{node_id} ip:{clusternode['ipaddress']} to become active")
        raise ValueError (f"Node {node_id} did not become ACTIVE")


    def add_first_node(self, nodeip, vip, mgmt_snip, server_snip):
        logger.info(f"Adding first node {nodeip} to cluster")
        nodeID = 0  
        backplane = f"{nodeID}/{self.backplane}"
        state = "ACTIVE"
        clusterInstanceID = 1

        node = CitrixADC(nsip=nodeip, nspass=self.nspass)
        node.wait_for_reachability()
        node.add_cluster_instance(clusterInstanceID)
        node.add_cluster_node(nodeID, nodeip, self.backplane, self.tunnelmode, state)
        node.add_nsip(self.clip, "255.255.255.255", "CLIP")
        node.add_nsip(vip, self.vip_netmask, "VIP")
        node.add_nsip(mgmt_snip, self.mgmt_netmask, "SNIP", owner_node=nodeID)
        node.add_nsip(server_snip, self.server_netmask, "SNIP", owner_node=nodeID)
        node.enable_feature(["LB", "CS", "SSL"])
        # TBD Check if NameServer is required
        # node.configure_dns(self.nameserver)
        node.add_ipset()
        node.bind_ipset(vip)
        node.enable_cluster_instance(clusterInstanceID)
        node.save_config()
        node.reboot()
        waitfor(30, reason="Waiting for first node to reboot")
        node.wait_for_reachability()
        self.wait_until_node_active(0)
        logger.info(f"Successfully created a 1 node cluster with node-id:{nodeID} ip:{nodeip}")
    
    def get_available_node_id(self):
        logger.info("Getting an available node id")
        self.wait_for_reachability()
        result = self.do_get(resource="clusternode")
        nodes = result["clusternode"]
        ids = set([int(node["nodeid"]) for node in nodes])
        for i in range(32):
            if i not in ids:
                logger.info(f"Fetched available node id {i}")
                return i
        raise ValueError("No available node ID")

    def add_node(self, node_ip, vip, mgmt_snip, server_snip):
        logger.info(f"Adding node {node_ip} to cluster with clip {self.clip}")
        node_id = -1
        for _ in range(30):
            node_id = self.get_available_node_id()
            node_backplane = f"{node_id}/{self.backplane}"
            try:
                self.add_cluster_node(node_id, node_ip, node_backplane, self.tunnelmode, "ACTIVE")
                break
            except Exception as e:
                if "Resource already exists" in str(e):
                    logger.info("Node-id {node_id} taken up by another node. Will try again")
                    waitfor(seconds=1)
                else:
                    raise
        try:
            self.add_nsip(vip, self.vip_netmask, "VIP")
            self.add_nsip(mgmt_snip, self.mgmt_netmask, "SNIP", owner_node=node_id)
            self.add_nsip(server_snip, self.server_netmask, "SNIP", owner_node=node_id)
            self.bind_ipset(vip)
            self.save_config()
            node = CitrixADC(node_ip, nspass=self.nspass)
            node.join_cluster(self.clip, self.nspass)
            node.save_config()
            node.reboot()
            waitfor(20, "Waiting for new node to reboot")
            node.wait_for_reachability()
            self.wait_until_node_active(node_id)
        except Exception as e:
            logger.error(f"Failed to add node ip:{node_ip} to cluster")
            self.remove_node(node_id, vip)
            raise e
        logger.info(f"Successfully added node id:{node_id} ip:{node_ip} to cluster")

    def remove_node(self, node_id, node_vip=None):
        logger.info(f"Removing node id:{node_id} vip:{node_vip} from clip {self.clip}")
        self.wait_for_reachability()
        self.remove_cluster_node(node_id)
        if node_vip:
            self.unbind_ipset(node_vip)
            self.del_nsip(node_vip)
        logger.info(f"Node {node_id} clean up done")
        
    def cleanup_stale_nodes(self, valid_node_ips, valid_node_vips):
        logger.info(f"Cleaning up the cluster of stale nodes. Valid node-ips:{valid_node_ips}  node-vips:{valid_node_vips}")
        self.wait_for_reachability()
        nodes = self.get_cluster_nodes()
        vips = self.get_ipset_bindings()
        for node in nodes:
            if node['ipaddress'] not in valid_node_ips:
                self.remove_node(node['nodeid'])
        for vip in vips:
            if vip['ipaddress'] not in valid_node_vips:
                self.unbind_ipset(vip['ipaddress'])
                self.del_nsip(vip['ipaddress'])

def get_cluster_ip(mgmt_ips, nspass):
    for nsip in mgmt_ips:
        nodeObj = CitrixADC(nsip=nsip, nspass=nspass)
        if not nodeObj.check_connection():
            continue
        cluster_ip = nodeObj.get_clip()
        if cluster_ip:
            return cluster_ip
    return ""

def cidr_to_netmask(cidr):
    # Convert CIDR to subnet mask
    _, subnet_mask_len = cidr.split('/')
    subnet_mask_len = int(subnet_mask_len)
    subnet_mask = (0xffffffff << (32 - subnet_mask_len)) & 0xffffffff
    return ".".join(str((subnet_mask >> (8 * i)) & 255) for i in range(3, -1, -1))

def get_vmss_name(vm_name):
    # Find the last underscore in the VM name
    last_underscore_index = vm_name.rfind('_')

    # Extract the VMSS name from the VM name
    vmss_name = vm_name[:last_underscore_index]

    return vmss_name

def get_cluster_ip_from_lbpool(mgmt_interface_ip_configuration, zone):
    try:
        cluster_ip = None
        ip_configuration = mgmt_interface_ip_configuration
        if ip_configuration.load_balancer_backend_address_pools:
            for be_pool in ip_configuration.load_balancer_backend_address_pools:
                # Get lb identification from backend pool
                lb_pool_id = be_pool.id
                resource_parts = lb_pool_id.split("/")
                lb_rg = resource_parts[resource_parts.index("resourceGroups") + 1]
                lb_name = resource_parts[resource_parts.index("loadBalancers") + 1]

                if "-pvt-lb" not in lb_name:
                    # Should have been public lb for source NAT purposes
                    continue

                # Get the list of front end IPs for the specified Load Balancer
                load_balancer = network_client.load_balancers.get(lb_rg, lb_name)
                front_end_ips = load_balancer.frontend_ip_configurations

                # Find the first front end IP that meets the criteria (name containing 'clusterip' and zone match)
                for ip in front_end_ips:
                    if 'clusterip' in ip.name.lower() and zone in ip.zones:
                        return ip.private_ip_address
        return cluster_ip

    except Exception as e:
        logger.debug(f"exception {e}")
        # Handle any exceptions here
        return None

def get_subnet_mask(network_interface_info):
  subnet_id = network_interface_info.ip_configurations[0].subnet.id
  resource_parts = subnet_id.split("/")
  subnet_rg = resource_parts[resource_parts.index("resourceGroups") + 1]
  subnet_vnet = resource_parts[resource_parts.index("virtualNetworks") + 1]

  # Get the subnet by ID to fetch the address prefix (CIDR) 
  subnet = network_client.subnets.get(subnet_rg, subnet_vnet, os.path.basename(subnet_id))

  # Convert the CIDR to subnet mask
  subnet_cidr = subnet.address_prefix
  subnet_mask = cidr_to_netmask(subnet_cidr)

  return subnet_mask

def get_vmss_instances(subscription_id, resource_group_name, vmss_name):
    return compute_client.virtual_machine_scale_set_vms.list(resource_group_name, vmss_name)


def get_ips(subscription_id, resourcegroup, virtualmachine, required_interfaces = range(3), find_cluster_ip=True):

    # Array to store interface IPs, subnet masks, and subnet IDs
    ips = {}

    # Get the virtual machine by resource group and name
    vm = compute_client.virtual_machines.get(resourcegroup, virtualmachine)
    vm_zone = vm.zones[0]

    cluster_ip = None

    # Loop through the network interfaces to get IP configurations
    for index, network_interface in enumerate(vm.network_profile.network_interfaces):
        if index % 3 not in required_interfaces:
            continue

        interface_name = os.path.basename(network_interface.id)
        network_interface_info = network_client.network_interfaces.get(resourcegroup, interface_name)

        # Initialize IP lists for primary and secondary IPs
        interface_ips_info = {
            'primary_ips': [],
            'secondary_ips': [],
        }

        # Search for cluster ip only in management interface's context
        # Only mgmt interface is loadbalanced by private lb
        search_cluster_ip = find_cluster_ip if index % 3 == 0 else False

        for ip_configuration in network_interface_info.ip_configurations:
            if search_cluster_ip and cluster_ip == None:
                # Get cluster_ip from pvt lb's clusterip frontend
                cluster_ip = get_cluster_ip_from_lbpool(ip_configuration, vm_zone)
            # Get primary and secondary IPs based on the 'primary' property
            ip_address = ip_configuration.private_ip_address
            if ip_configuration.primary:
                interface_ips_info["primary_ips"].append(ip_address)
            else:
                interface_ips_info["secondary_ips"].append(ip_address)

        if index % 3 == 0:
            ips["cluster_ip"] = cluster_ip
            interface_ips_info["subnet_mask"] = get_subnet_mask(network_interface_info)
            ips["mgmt"] = interface_ips_info
        elif index % 3 == 1:
            ips["client"] = interface_ips_info
        else:
            interface_ips_info["subnet_mask"] = get_subnet_mask(network_interface_info)
            ips["server"] = interface_ips_info

    return ips

def get_vmss_ips(subscription_id, resource_group_name, vmss_instances):

    mgmt_ips, client_ips = [], []
    cluster_ip = None

    for instance in vmss_instances:
        ips = get_ips(subscription_id, resource_group_name, instance.name, [0,1], cluster_ip == None)
        mgmt_ips.append(ips["mgmt"]["primary_ips"][0])
        client_ips.append(ips["client"]["primary_ips"][0])
        cluster_ip = ips["cluster_ip"] if cluster_ip == None else cluster_ip

    return cluster_ip, mgmt_ips, client_ips

def process_event_grid_notification(event_type, event_data):

    logger.debug(f"processing event_type {event_type}")

    nspass = "Freebsd123$%^"

    operation_name = "default"
    try:
        resource_uri = event_data["resourceUri"]
        operation_name = event_data["operationName"]
        logger.debug(f"==> operationName {operation_name} resourceUri {resource_uri}")
    except:
        logger.debug("==> opname exception")
        pass

    if "Microsoft.Compute/virtualMachines" in operation_name:
        # Get the virtual machine resource group and name from resourceUri
        resource_uri = event_data["resourceUri"]
        logger.debug(f"Processing VM resourceUri is {resource_uri} {operation_name}")
        resource_parts = resource_uri.split("/")
        subscription_index = resource_parts.index("subscriptions") + 1
        subscription_id = resource_parts[subscription_index]
        rg_index = resource_parts.index("resourcegroups") + 1
        vm_rg = resource_parts[rg_index]
        vm_name = resource_parts[-1]

        from azure.identity import ManagedIdentityCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient

        global credentials, compute_client, network_client
        # Create a ManagedIdentityCredential object to authenticate with Azure
        credentials = ManagedIdentityCredential()

        # Create a ComputeManagementClient to interact with the Compute service
        compute_client = ComputeManagementClient(credentials, subscription_id=subscription_id)

        # Create a NetworkManagementClient to interact with the Network service
        network_client = NetworkManagementClient(credentials, subscription_id=subscription_id)

        vmss_name = get_vmss_name(vm_name)
        #TBD if vmss name cannot be found return.

        vmss_instances = get_vmss_instances(subscription_id, vm_rg, vmss_name)

        # Check if the operation is VirtualMachineWrite
        if event_type == "Microsoft.Resources.ResourceWriteSuccess" and event_data["operationName"] == "Microsoft.Compute/virtualMachines/write":
            first = len(list(vmss_instances)) == 1
            ips = get_ips(subscription_id, vm_rg, vm_name)
            logger.debug(f"all ips for {vm_name} is '{ips}'")
            clip = ips["cluster_ip"]
            cluster = Cluster(clip=clip, nspass=nspass, nameserver=None, vip_netmask="255.255.255.0", mgmt_netmask=ips["mgmt"]["subnet_mask"], server_netmask=ips["server"]["subnet_mask"])
            nsip, mgmt_snip =ips["mgmt"]["primary_ips"][0], ips["mgmt"]["secondary_ips"][0]
            vip =ips["client"]["primary_ips"][0]
            server_snip=ips["server"]["primary_ips"][0]
            if first:
                #first node of the cluster. So cluster needs to be formed.
                cluster.add_first_node(nodeip=nsip, vip=vip, mgmt_snip=mgmt_snip, server_snip=server_snip)
            else:
                cluster.add_node(node_ip=nsip, vip=vip, mgmt_snip=mgmt_snip, server_snip=server_snip)

            # Return the interface_ips or perform additional processing, if needed
            return ips
        elif event_type == "Microsoft.Resources.ResourceDeleteSuccess":
            logger.debug(f"Inside delete of instance")
            # Return None or an empty response if the operation was not VirtualMachineWrite
            clip, mgmt_ips, client_ips = get_vmss_ips(subscription_id, vm_rg, vmss_instances)
            logger.debug(f"clip {clip} nsips {mgmt_ips} vips {client_ips}")
            cluster = Cluster(clip=clip, nspass=nspass)
            cluster.cleanup_stale_nodes(mgmt_ips, client_ips)
        else:
            logger.debug(f"Unknown event {event_data}")

        return None


def main(myTimer: func.TimerRequest) -> None:

    logger.debug(f"Timer Event occurred")

    try:
        event_data ={
            "operationName" : "Microsoft.Compute/virtualMachines/write",
            "resourceUri" : "/subscriptions/4fc50510-428a-4492-90e7-1c0aa1535830/resourcegroups/vj-env18-findadclb-az2/providers/Microsoft.Compute/virtualMachines/vj-env18-findadclb-az2_c7bd0ee7"
        }

        event_type = "Microsoft.Resources.ResourceWriteSuccess"
        process_event_grid_notification(event_type, event_data)
    except Exception as e:
        logger.error(f"Exception hit while processing instance-launch: {str(e)}")
        tb = traceback.format_exc()
        logger.error(f"Exception backtrace: {tb}")

# main(None)
'''
def main(event: func.EventGridEvent):
    logger.debug(f"library loaded using subprocess {event.event_type}")

    try:
        process_event_grid_notification(event.event_type, event.get_json())
    except Exception as e:
        logger.error(f"Exception hit while processing instance-launch: {str(e)}")
        tb = traceback.format_exc()
        logger.error(f"Exception backtrace: {tb}")
'''
# # Test function to simulate Event Grid notification and call the event processing function
# def test_event_processing():
#     # Simulate Event Grid notification payload
#     event_payload = {
#         "eventType": "Microsoft.Resources.ResourceWriteSuccess",
#         "data": {
#             "operationName": "Microsoft.Compute/virtualMachines/delete",
#             "resourceUri": "/subscriptions/4fc50510-428a-4492-90e7-1c0aa1535830/resourcegroups/vj-env14-vmssfunction-az2/providers/Microsoft.Compute/virtualMachines/vj-env14-autocluster-az2_dcaec063"
#         }
#     }

#     # Convert the payload to JSON format
#     # Call the event processing function with the test payload
#     result = process_event_grid_notification("Microsoft.Resources.ResourceWriteSuccess", event_payload[data])

# # test_event_processing()

