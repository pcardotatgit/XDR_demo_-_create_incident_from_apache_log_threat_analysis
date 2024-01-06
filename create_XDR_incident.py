'''
    create new XDR incident
'''
import json, sys
from datetime import datetime, date, timedelta
import time
import hashlib
from crayons import *
import json
import sys
import requests

# Set global variable
description ='**Description:** Malicious IP addresses Attacked a Company Web Server'
incident_title='Malicious Public IP address detected'
method="config.txt"  # for futur use :  must be either config.txt or ../key  or database  or vault or environment variable
host = ""
host_for_token=""
ctr_client_id=""
ctr_client_password=""
SecureX_Webhook_url=""
BOT_ACCESS_TOKEN=""
DESTINATION_ROOM_ID=""
# Get the current date/time
dateTime = datetime.now()

discover_method=["Agent Disclosure","Antivirus","Audit","Customer","External - Fraud Detection","Financial Audit","HIPS","IT Audit","Incident Response","Internal - Fraud Detection","Law Enforcement"]

categories=["Denial of Service","Exercise/Network Defense Testing","Improper Usage","Investigation","Malicious Code","Scans/Probes/Attempted Access","Unauthorized Access"]

def parse_config(text_content):
    text_lines=text_content.split('\n')
    conf_result=['','','','','','','']
    for line in text_lines:
        print(green(line,bold=True))
        if 'ctr_client_id' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[0]=line.split('=')[1]
                conf_result[0]=conf_result[0].replace('"','')
                conf_result[0]=conf_result[0].replace("'","")
            else:
                conf_result[0]=""
        elif 'ctr_client_password' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[1]=line.split('=')[1]
                conf_result[1]=conf_result[1].replace('"','')
                conf_result[1]=conf_result[1].replace("'","")
            else:
                conf_result[1]=""        
        elif '.eu.amp.cisco.com' in line:
            conf_result[2]="https://private.intel.eu.amp.cisco.com" 
            conf_result[6]="https://visibility.eu.amp.cisco.com"
        elif '.intel.amp.cisco.com' in line:
            conf_result[2]="https://private.intel.amp.cisco.com"   
            conf_result[6]="https://visibility.amp.cisco.com"
        elif '.apjc.amp.cisco.com' in line:
            conf_result[2]="https://private.intel.apjc.amp.cisco.com"
            conf_result[6]="https://visibility.apjc.amp.cisco.com"
        elif 'SecureX_Webhook_url' in line:
            words=line.split('=')
            if len(words)==2:        
                print(yellow(words))        
                conf_result[3]=words[1]
                conf_result[3]=conf_result[3].replace('"','')
                conf_result[3]=conf_result[3].replace("'","")                
            else:
                conf_result[3]=""
        elif 'webex_bot_token' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[5]=line.split('=')[1]
                conf_result[5]=conf_result[5].replace('"','')
                conf_result[5]=conf_result[5].replace("'","")
            else:
                conf_result[5]=""        
        elif 'webex_room_id' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[4]=line.split('=')[1]
                conf_result[4]=conf_result[4].replace('"','')
                conf_result[4]=conf_result[4].replace("'","")
            else:
                conf_result[4]=""        
    print(yellow(conf_result))
    return conf_result

def read_api_keys(service):   
    # read API credentials from an external file on this laptop ( API keys are not shared with the flask application )
    if service=="ctr":
        if ctr_client_id=='paste_CTR_client_ID_here':
            with open('../keys/ctr_api_keys.txt') as creds:
                text=creds.read()
                cles=text.split('\n')
                client_id=cles[0].split('=')[1]
                client_password=cles[1].split('=')[1]
                #access_token = get_token()
                #print(access_token) 
        else:
            client_id=ctr_client_id
            client_password=ctr_client_password
        return(client_id,client_password)

def get_ctr_token(host_for_token,ctr_client_id,ctr_client_password):
    print(yellow('Asking for new CTR token',bold=True))
    url = f'{host_for_token}/iroh/oauth2/token'
    print()
    print(url)
    print()    
    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    payload = {'grant_type':'client_credentials'}
    print()
    print('ctr_client_id : ',green(ctr_client_id,bold=True))
    print('ctr_client_password : ',green(ctr_client_password,bold=True))
    response = requests.post(url, headers=headers, auth=(ctr_client_id, ctr_client_password), data=payload)
    #print(response.json())
    reponse_list=response.text.split('","')
    token=reponse_list[0].split('":"')
    print('token = ',token[1])
    if 'invalid_client' in token[1]:
        print(red('Error = bad client_id or client_password !',bold=True))
        return 0
    else:        
        fa = open("ctr_token.txt", "w")
        fa.write(token[1])
        fa.close()
        return (token[1])
    
def get(host,access_token,url,offset,limit):    
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    url = f"{host}{url}?source=XDR Demo&limit={limit}&offset={offset}"
    response = requests.get(url, headers=headers)
    return response
    
def check_ctr_token(host,host_for_token,ctr_client_id,ctr_client_password):
    '''
        check current ctr and if this one is not valid then generate a new one
    '''
    fa = open("ctr_token.txt", "r")
    access_token = fa.readline()
    fa.close() 
    url = "/ctia/incident/search"
    offset=0
    limit=1
    response = get(host,access_token,url,offset,limit)
    payload = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
    print(payload) 
    if response.status_code==401:
        print("Asking for a Token") 
        access_token=get_ctr_token(host_for_token,ctr_client_id,ctr_client_password)
    elif response.status_code!=200:
        print(red(response.status_code,bold=True)) 
        print()         
        print(red("Error !",bold=True))    
        print(response.json())  
        print()        
    else:
        print("Ok Token Is valid : ",green(response.status_code,bold=True))                 
        print()             
    return(access_token)

def create_incident_xid():
    hash_strings = [ "some_string to put here" + str(time.time())]
    hash_input = "|".join(hash_strings)
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    incident_xid = 'transient:sxo-incident-' + hash_value
    print("  - Incident External ID : ",cyan(incident_xid,bold=True))
    return incident_xid

def create_incident_json():
    print(yellow("- > Step 1.1 create_incident_xid",bold=True))
    # Build the incident objects
    #xid="transient:"+create_incident_xid() DEBUG PATRIKC
    xid=create_incident_xid()
    incident_object = {}
    incident_object["description"] = description
    incident_object["schema_version"] = "1.3.9"
    incident_object["type"] = "incident"
    incident_object["source"] = "XDR Demo"
    incident_object["short_description"] = incident_title
    incident_object["title"] = incident_title
    incident_object["incident_time"] = { "discovered": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "opened": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ") }
    incident_object["status"] = "New"
    incident_object["tlp"] = "amber"
    incident_object["confidence"] = "High"
    incident_object["severity"] = "High"
    incident_object["id"] = xid
    incident_object["techniques"] = ["T1036"]
    incident_object["tactics"] = ["TA0002","TA0005"]
    incident_object["categories"]:[categories[3]]
    incident_object["discovery_method"]:discover_method[2]
    incident_object["promotion_method"]:promotion_method    
    incident_object["scores"]={}
    incident_object["scores"]["asset"]=10
    incident_object["scores"]["ttp"]=100
    incident_object["scores"]["global"]=1000    
    incident_json = json.dumps(incident_object)
    print()
    print(' Incidents JSON :\n',cyan(incident_json,bold=True))
    return(incident_json,xid)

def create_sighting_xid(sighting_title):
    d = datetime.now()
    current_time = d.strftime("%d/%m/%Y %H:%M:%S")
    hash_strings = [sighting_title, current_time]
    hash_input = "|".join(hash_strings)
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    sighting_xid = "sxo-sighting-" + hash_value
    print("  - Sighting External ID : ",cyan(sighting_xid,bold=True))
    return sighting_xid

def today():
    d = date.today()
    return d.strftime("%Y-%m-%d")

def create_sighting_object(xid,title,observables,targets,observable_relationships,confidence,description,source,tlp,severity):
    #start_date = dateTime.strftime("%Y-%m-%dT%H:%M:%SZ")
    sighting_obj_json = {}
    sighting_obj_json["confidence"] = "High"
    print("   - Get Observables and add them into sighting definition")
    sighting_obj_json["observables"] = observables
    print("   - Get Targets and add them into sighting definition")
    sighting_obj_json["targets"] = targets
    sighting_obj_json["external_ids"] = [xid]
    sighting_obj_json["id"] ="transient:"+xid 
    sighting_obj_json["description"] = description
    sighting_obj_json["title"] = title
    sighting_obj_json["source"] = source
    sighting_obj_json["type"] = "sighting"
    sighting_obj_json["observed_time"] = {"start_time": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ") }
    sighting_obj_json["tlp"] = "amber"
    sighting_obj_json["severity"] = "Critical"
    print("   - Get sighting relationships and add them into sighting definition")
    sighting_obj_json["relations"] = observable_relationships
    print()
    print(' Sightings JSON :\n',cyan(sighting_obj_json,bold=True))
    return json.dumps(sighting_obj_json)   
    
def create_relationship_object(source_xid, target_xid, relationship_xid, relationship_type):
    relationship_json = {}
    relationship_json["external_ids"] = ["transient:"+relationship_xid]
    relationship_json["source_ref"] = source_xid
    relationship_json["target_ref"] = target_xid
    relationship_json["source"] = "XDR Demo"
    relationship_json["relationship_type"] = relationship_type
    relationship_json["type"] = "relationship"
    relationship_json["id"] = "transient:"+relationship_xid
    print(' relationships :\n',cyan(relationship_json,bold=True))
    return json.dumps(relationship_json)

def generate_relationship_xid(source_xid, target_xid):
    hash_value = hashlib.sha1((source_xid + target_xid).encode('utf-8'))
    hash_value = hash_value.hexdigest()
    relationship_xid = "sxo-relationship-" + hash_value
    print(' Relationships External ID :\n',cyan(relationship_xid,bold=True))
    return relationship_xid
    

def create_bundle(incident_json,sighting,relationship,source):
    bundle_json = {}
    bundle_json["source"] = source   
    print('   - Adding Incident payload to Bundle')
    incidents = []
    incidents.append(json.loads(incident_json))
    bundle_json["incidents"] = incidents
    print('   - Adding Sighting payload to Bundle')
    sightings = []
    sightings.append(json.loads(sighting))
    bundle_json["sightings"] = sightings
    print('   - Adding relationship payload ( Sighting to Incident )  to bundle')
    relationships = []
    relationships.append(json.loads(relationship))
    bundle_json["relationships"] = relationships
    print()     
    print('-Bundle JSON Paylod :')
    print(yellow(json.dumps(bundle_json,sort_keys=True,indent=4, separators=(',', ': ')),bold=True))
    return json.dumps(bundle_json)
    
def create_incident(host_for_token,access_token,bundle):
    '''
        create new incident with one sighting
    '''
    print()
    print(yellow("  - Let's connect to XDR API to create the Incident into XDR",bold=True))
    print()
    #url = f"{host}/iroh/private-intel/bundle/import?external-key-prefixes=sxo" 
    url = f"{host_for_token}/iroh/private-intel/bundle/import?external-key-prefixes=sxo"
    print('url : ',url)
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.post(url, data=bundle,headers=headers)
    print()  
    print(response.status_code)
    print(response.json())    
    if response.status_code==401:
        access_token=get_ctr_token(host_for_token)
        headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}        
        response = requests.post(url, data=bundle,headers=headers)           
    if response.status_code==200:
        print(green(response.status_code,bold=True))
        print()         
        print(green("Ok Done Incident created",bold=True))         
        print()    
        #print(response.json())    
        print(cyan(json.dumps(response.json(),sort_keys=True,indent=4, separators=(',', ': ')),bold=True))
        print() 
    return 1
   
def go_for_incident(the_observables,the_targets,the_observable_relationships):
    print()
    print(yellow("- Step 1 create Incident JSON payload",bold=True))
    incident_json,incident_xid=create_incident_json()
    print()
    print(yellow("- Step 2 create Sighting JSON payload",bold=True))
    sighting_xid = create_sighting_xid("Sighting created for asset enrichment test")
    sighting_transient_id="transient:"+sighting_xid
    print("  - Sighting_transient_id : ",cyan(sighting_transient_id,bold=True))
    description='Public IP addresses had been seen trying to hack the Public Web Server'
    source='XDR Demo'
    confidence = "Medium"
    title = "Confirmed Malicious Public IPs targeting Public Company Internet Web Server"
    tlp="amber"
    severity = "High"
    print(red(type(the_observables),bold=True))
    #observables=json.dumps(the_observables)
    #targets=json.dumps(the_targets)
    #observable_relationships=json.dumps(the_observable_relationships)
    sighting=create_sighting_object(sighting_xid,title,the_observables,the_targets,the_observable_relationships,confidence,description,source,tlp,severity)
    print()
    print(yellow("- Step 3 Create Relationship payload for sighting and Incident. Sighting is member-of Incident",bold=True))
    relationship_xid=generate_relationship_xid(sighting_transient_id,incident_xid)
    relationship=create_relationship_object(sighting_transient_id,incident_xid,relationship_xid,"member-of")
    source_for_bundle="XDR Demo"
    print()
    print(yellow("- Step 4 create Bundle JSON payload => Put everything together",bold=True))
    bundle=create_bundle(incident_json,sighting,relationship,source_for_bundle)
    print()
    print(yellow("  - Ok Bundle JSON payload is ready",bold=True))
    print()
    print(yellow("- Step 5 read XDR Tenant details and credentials",bold=True))
    if method=="config.txt":
        with open('config.txt','r') as file:
            text_content=file.read()
        ctr_client_id,ctr_client_password,host,SecureX_Webhook_url,DESTINATION_ROOM_ID,BOT_ACCESS_TOKEN,host_for_token = parse_config(text_content)
    print()
    #print('ctr_client_id :',ctr_client_id)
    #print('ctr_client_password :',ctr_client_password)
    #print('host : ',host )
    #print('SecureX_Webhook_url :',SecureX_Webhook_url)
    #print('BOT_ACCESS_TOKEN : ',BOT_ACCESS_TOKEN)
    #print('DESTINATION_ROOM_ID : ',DESTINATION_ROOM_ID)
    #print('host_for_token : ',host_for_token)
    print(yellow("Step 6 check if current CTR access token valid",bold=True))
    access_token=check_ctr_token(host,host_for_token,ctr_client_id,ctr_client_password)
    #print('access_token :',cyan(access_token,bold=True))
    if access_token==0:
        print(red("Error . Can't get CTR Token",bold=True))
        sys.exit()
    else:
        print(green("Ok Token = Success",bold=True))
    print()
    print(yellow(" OKAY Ready to create the Incident In XDR",bold=True))
    print()
    print(yellow("Step 7 Let's go !",bold=True))
    print('BUNDLE TO SEND : ')
    print(bundle)
    create_incident(host_for_token,access_token,bundle)