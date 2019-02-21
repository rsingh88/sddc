#########################################################################################################################################
##                              Code purpose:   Code to pull the list of VMs in VMC SDDCs and update their tags                        ##
##                              Code Written By: Ravindra Singh                                                                        ##
##                              Code State : Development                                                                               ##
#########################################################################################################################################



#!/bin/python




import requests
import json, time


# vmInfo is global and it gets build during virtualMachines() call, this will be used in POST operation for calling correct ext_id 
# vmTag is global and it gets build during the CreateTag() call, this will be used to hold vm and Tag
# nsxPm is global and This is used to store the nsx-policy-manager urls

vmInfo = {}  
vmTag = {}
nsxPm = []   

def login():
	key = "xxxxxxxxxxxxxx"
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




def virtualMachines():
	# nsxPm has both Non-Prod and LAB sddc NSX Manager information, ['NonProd','LAB-SDDC']

	NsxUrl = nsxPm[1]
	req = requests.get(NsxUrl+"/policy/api/v1/infra/deployment-zones/default/enforcement-points", headers = auth_header)

	# Extracting EnforcementPoint ID 
	enfID = req.json()['results'][0]['id']
	VirtualServer = NsxUrl+"/policy/api/v1/infra/realized-state/enforcement-points/"+enfID+"/virtual-machines"
	NSGroups = NsxUrl+"/policy/api/v1/infra/realized-state/enforcement-points/"+enfID+"/groups/nsgroups"
	VSreq = requests.get(VirtualServer,headers=auth_header)
	vmData = json.loads(VSreq.text)
	
	# Display vm,ext_id and write csv.
	for vm in vmData['results']:
		# print vm['display_name']," : ",vm['external_id']
		vmInfo[str(vm['display_name'])] = str(vm['external_id'])



'''	 
TAG Naming Standard:
PDT.<TLA>.<FUN>.<ENV>

Server Naming Standard:
https://teams.microsoft.com/_/docx/viewer/teams/https:~2F~2Finfocorp365.sharepoint.com~2Fsites~2FProjectOrion~2FShared%20Documents~2FVMC%20Infrastructure%20Offering~2FServer%20Naming%20Standards.docx?threadId=19:52a10b3e54014e1babc7f4b26672d622@thread.skype&baseUrl=https:~2F~2Finfocorp365.sharepoint.com~2Fsites~2FProjectOrion&fileId=CEB5F964-090F-4D68-AFB8-5B5F941CFDFC&ctx=files&viewerAction=view
'''



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
				# print("vm: {}   Tag: {}".format(vm,tag))

	print("\nTotal Vitual Machine Tag Generated: {}".format(count))

vmTag = {
"LOV1P2VRAISM02":"5029f093-0527-9a8b-a3f8-878fc087346f",
"lov1d1gitem001":"502971aa-01ab-8fab-6c43-9267dcc23991",
"LOV1P2MKAADS02":"5029798f-a990-05d0-5efc-8af81fc2c333",
"lov1p9vcsvrm01":"502908cc-0eee-4625-a833-924200ef99ca",
"LOV1P2MKAADS01":"5029a9eb-0466-7ba5-0e37-ef125d53b4df",
"LOV1P2IFOADS02":"5029da82-b6e9-5f54-2299-d816b7b0bc05",
"lov1q2msftfs01":"502964ca-741b-64c6-7220-75c435970502",
"LOV1P2MKPSMS01":"502980e4-184a-670e-d9c2-204930c23f41",
"LOV1P2VRAPSS01":"5029f68e-323e-7434-ae68-d8605178331d",
"LOV1P2VRAPSS02":"5029d888-16b1-d44c-b561-ece3c1471e31",
"LOV1P2VRAMGR01":"5029cf14-6802-1c38-2dd9-53db07ecb18a",
"LOV1P2VRAMGR02":"5029cd89-c5b5-f26f-2053-7ab438cf5c57",
"lov1q2msfmts01":"50292f01-581a-4d5c-8a7f-89b3b9645aec",
"lov1q2msfftp02":"5029d7c4-9218-78c8-a844-3263989df88f",
"LOV1P2VRAISM01":"50297efa-1d42-5cd2-9cb2-4a63747427ff",
"LOV1P2MKPADS01":"50298972-d5fe-b8d1-199a-9793933fac3e",
"LNP6LBVCSVCP03":"500ddb16-51a2-02d6-a807-b43e3dd0804d",
"LOV1P2STGADS01":"50293024-4281-3cee-c2fd-bdf69e7122f9",
"LOV1P2MKPADS02":"50298bef-73de-c905-d791-8dd7cd29bb5e",
"LOV1P2STGADS02":"50293d58-197d-71b0-d711-f68590c43f1e",
"LOV1P2VRAIDS01":"5029605e-0793-d744-358d-bfc9102b83e2",
"LOV1P2VRAIDS02":"502917ff-e6b1-b8f9-1b2f-0b908e85f70a",
"LOV1P2PRDADS01":"502928f3-9e38-f31e-9203-0d8c201b8146",
"LOV1P2PRDADS02":"5029d02e-4ea2-bd71-bbab-18cf84fde762",
"lov1q2msfftp01":"502974f1-f5de-c7ad-7fda-7704fbed4503",
"LOV1P0VRAAPP01":"50292d51-3121-c26f-1a0d-c1c196e14277",
"LOV1P0VRAAPP02":"502972ad-bb1e-0baf-a63a-663f5be5d884",
"LOV1P2MKAFS01":"50290ada-2cba-1e26-f0aa-952682a23e40",}


def updateTag():

	for vm,ext_id in vmTag.items():
		time.sleep(0.5)

		base = nsxPm[0]+"/policy/api/v1/infra/realized-state/enforcement-points/vmc-enforcementpoint/virtual-machines?action=update_tags"
		data = {

		    "virtual_machine_id" : ext_id,
		    'tags' : [ {
		      "scope" : "",
		      "tag" : ""
		    } ]
		  }

		resp = requests.post(base, data = json.dumps(data), headers=auth_header)
		
		if resp.status_code == 204 :
			print ("Successfully updated.... VirtualMachine : {} 	ext_id : {} 	Tag : ".format(vm,ext_id)) 
		else:
			print("Error....VirtualMachine : {} 	ext_id : {} 	Tag : ".format(vm,ext_id))




print("\n\nScript execution complete!!\n\n")