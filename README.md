# sddc
Software Defined Datacenter Code

This code is written for updating the security tags on virtual machines hosted inside software defined data center inside vmware cloud on AWS.
The API call uses token key for authenticating to VMC environment and generates the session based access_token
The access_token is then used for authenticating against sddc environment, and we copy NSX policy manager url
