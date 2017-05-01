# VM-Network-Transfer
 
The vm_network_transfer.py script will take a list of server UUIDs or UUIDs paired with IP addresses and move them from one network to another assigning the same IP address. Additionally it can be run without a list and it will systematically find all VMs associated with a network and transfer them.
 
Usage Example WITH FILE:
 
python vm_network_transfer.py --ddi \<tenant_id\> --instanceipfile \<file location\> --user \<username\> --apikey \<apikey\> --srcnetwork \<source network\> --dstnetwork \<destination network\> --region \<region\>
 
Real Example WITH FILE:
 
python vm_network_transfer.py --ddi 123456 --instanceipfile instance-file.txt --user adminuser --apikey REDACTED --srcnetwork c733cf07-d599-402b-bc46-7c84f42c9ce1 --dstnetwork c22f8f9d-58b8-4b6e-8d37-27834bf44b9a --region dfw
 
Real Example WITHOUT FILE:
 
python vm_network_transfer.py --ddi 123456 --user adminuser --apikey REDACTED --srcnetwork 12345678-d3e2-4c52-8701-8993ed607485 --dstnetwork 12345678-7715-439a-8425-e8588846d4ab --region dfw
 
The format for the instance / instanceIP file must follow this format
 
Instance file by itself:
 
8ab1a867-a9d3-4f19-9b27-14cc05318adc <br />
10a3c727-0d15-414b-a189-4dae69563c4a <br />
b84d7431-628d-495a-8f46-7c3487eae1ec <br />
 
InstanceIP file:
 
8ab1a867-a9d3-4f19-9b27-14cc05318adc 192.168.10.40 <br />
10a3c727-0d15-414b-a189-4dae69563c4a 192.168.10.50 <br />
b84d7431-628d-495a-8f46-7c3487eae1ec 192.168.10.60 <br />
