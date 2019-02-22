#########################################################################################################################################
##                              Code purpose:   Code to pull the list of VMs in VMC SDDCs and update their tags                        ##
##                              Code Written By: Ravindra Singh                                                                        ##
##                              Code State : Production                                                                                ##
##                              Last Prod Run : 02/21/2019                                                                             ##
#########################################################################################################################################



#!/ur/bin/python


import requests
import json, time


# Global Variable used:
# vmInfo is global and it gets build during virtualMachines() call, this will be used in POST operation for calling correct ext_id 
# vmTag is global and it gets build during the CreateTag() call, this will be used to hold vm and Tag
# nsxPm is global and it gets build during the sddcFunction() call, this will be used to store the nsx-policy-manager urls

vmInfo = {}  
vmTag = {}
nsxPm = []   


# 1.) Login function generate the token for authenticating the sddc environment 
def login():
	key = "xxxxxxxxxxx"
	BaseUrl = "https://console.cloud.vmware.com/csp/gateway"
	uri = '/am/api/auth/api-tokens/authorize'
	headers = {'Content-Type':'application/json'}
	payload = {'refresh_token': key}
	r = requests.post((BaseUrl+uri), headers = headers, params = payload)
	# pprint.pprint(r.headers)
	if r.status_code != 200:
	    print('Unsuccessful Login Attmept. Error code {}'.format(r.status_code))
	else:
	    print('Login successful to VMC. ')
	    auth_json = r.json()['access_token']
	    auth_Header = {'Content-Type':'application/json','csp-auth-token':auth_json}
        return auth_Header


# 2.) sddcFunction Function generates the nsx policy manager uri of available SDDCs
def sddcFunction():
	r = requests.get("https://vmc.vmware.com/vmc/api/orgs", headers = auth_header)
	OrgsID = r.json()[0]["id"]
	resp = requests.get("https://vmc.vmware.com/vmc/api/orgs/"+OrgsID+"/sddcs", headers = auth_header)
	# checking the available SDDCs and printing their id, name and nsx policy manager
	print("\nDisplaying the list of SDDCs in VMC\n")
	if resp.status_code!=200:
		print('Something went wrong here, Error code is : {}'.format(resp.status_code)+"\nuri passed was: {}".format(resp.url))
	else:
		for sddcList in resp.json():

			# Print statement to test the content of sddc requests response
			# print ("SDDC Name : ", sddcList['name'])
			# print ("SDDC id : ", sddcList['id'])
			# print ("SDDC Provider : ", sddcList['provider'])
			print ("SDDC NSXPolicy Manager : ", sddcList['resource_config']['nsx_api_public_endpoint_url'])
			# appending the nsx urls to nsxPm list.
			nsxPm.append(str(sddcList['resource_config']['nsx_api_public_endpoint_url']))



# 3.) virtualMachines function uses the nsxpm uri and list all the available virtual machines and stores them into vmInfo 
def virtualMachines():
	# nsxPm has both Non-Prod and LAB sddc NSX Manager information, ['NonProd','LAB-SDDC']

	NsxUrl = nsxPm[0]
	req = requests.get(NsxUrl+"/policy/api/v1/infra/deployment-zones/default/enforcement-points", headers = auth_header)

	# Extracting EnforcementPoint ID 
	enfID = req.json()['results'][0]['id']
	VirtualServer = NsxUrl+"/policy/api/v1/infra/realized-state/enforcement-points/"+enfID+"/virtual-machines"
	NSGroups = NsxUrl+"/policy/api/v1/infra/realized-state/enforcement-points/"+enfID+"/groups/nsgroups"
	VSreq = requests.get(VirtualServer,headers=auth_header)
	vmData = json.loads(VSreq.text)
	
	# Display vm,ext_id and write vmInfo.
	for vm in vmData['results']:
		# print vm['display_name']," : ",vm['external_id']
		vmInfo[str(vm['display_name'])] = str(vm['external_id'])



'''	 
TAG Naming Standard:
PDT.<TLA>.<FUN>.<ENV>

Server Naming Standard:
https://teams.microsoft.com/_/docx/viewer/teams/https:~2F~2Finfocorp365.sharepoint.com~2Fsites~2FProjectOrion~2FShared%20Documents~2FVMC%20Infrastructure%20Offering~2FServer%20Naming%20Standards.docx?threadId=19:52a10b3e54014e1babc7f4b26672d622@thread.skype&baseUrl=https:~2F~2Finfocorp365.sharepoint.com~2Fsites~2FProjectOrion&fileId=CEB5F964-090F-4D68-AFB8-5B5F941CFDFC&ctx=files&viewerAction=view
'''


# 4.) CreateTag Function generates the tags, based on the VM name.
def CreateTag():
	tag = 'PDT.'
	count = 0
	for vm,ext_id in vmInfo.items():
		vm = vm.strip()
		if len(vm) > 14:
			# print("\nskipping the vm: {} because it doesn't folllow the naming standard.".format(vm))
			pass
		elif len(vm) < 13:
			# print("\nskipping the vm: {} because it doesn't folllow the naming standard.".format(vm))
			 pass
		else:
						
			# print "Geo Location: ",vm[:4].upper()
			Environment = vm[4].upper()
			# print "Environment: ", Environment
			# print "OS Type: ",vm[5].upper()
			Group = vm[6:9].upper()
			# print "Group: ",Group 
			Function = vm[9:-2].upper()
			# print "Function: ", Function
			# print "Cluster Number: ", vm[-2:].upper()

			# Adding Group to tag, group is BU unit name
			tag = "PDT."+Group

			# Adding Function to tag, Function is either Web, App, or DB server.  
			if Function == 'SQL' or Function == 'ORC' or Function == 'RDB':
				tag = tag+".DB"
			elif Function == 'WWW':
				tag = tag+".WEB"
			else:
				tag = tag+"."+Function
			
			# Adding Env to tag, Env is to signify the VM belongs in Prod,QA,UAT,DEV,Etc. 
			if Environment == 'P':
				tag = tag+".PROD"
			elif Environment == 'D':
				tag = tag+".DEV"
			elif Environment == 'Q':
				tag = tag+".QA"
			elif Environment == 'U':
				tag = tag+".UAT"
			elif Environment == 'S':
				tag = tag+".STG"
			elif Environment == 'L':
				tag = tag+".LAB"
			else:
				pass

			# At this checks we are making sure that only those machine tag are stored which match most accurate data, this is 90% accurate based on PDT.<TLA>.<FUN>.<ENV>.
			if len(tag) < 13:
				pass
			else:
				vmTag[vm] =  tag
				count += 1
				print("ext_id : {} 	VirtualMachine : {}	Tag : {}".format(ext_id,vm,tag)) 

	print("\nTotal Vitual Machine Tag Generated: {}".format(count))


# 5.) updateTag() Function will push the tag to their corresponding virtual machine.
def updateTag():

	for vm,tag in vmTag.items():
		ext_id = vmInfo[vm]
		time.sleep(0.5)

		base = nsxPm[0]+"/policy/api/v1/infra/realized-state/enforcement-points/vmc-enforcementpoint/virtual-machines?action=update_tags"
		data = {

		    "virtual_machine_id" : ext_id,
		    'tags' : [ {
		      "scope" : "",
		      "tag" : tag
		    } ]
		  }

		resp = requests.post(base, data = json.dumps(data), headers=auth_header)
		
		if resp.status_code == 204 :
			print ("Successfully updated.... VirtualMachine : {} 	ext_id : {} 	Tag : {}".format(vm,ext_id,tag)) 
		else:
			print("Error....VirtualMachine : {} 	ext_id : {} 	Tag : {}".format(vm,ext_id,tag))




# 1.) Login function generate the token for authenticating the sddc environment 
auth_header = login()    
# print auth_header

# 2.) sddcFunction call generates the nsx policy manager uri of available SDDCs
sddcFunction()

# 3.) virtualMachines function uses the nsxpm uri and list all the available virtual machines and stores them into csv  
virtualMachines()

# 4.) CreateTag call generates the tags, based on the VM name.
CreateTag()

# 5.) updateTag() call will push the tag to their specific vm
# updateTag()


print("\n\nScript execution complete!!\n")