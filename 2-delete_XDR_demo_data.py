'''
 utils for deleting demo incidents, sightings, judgments and relationships in the XDRs tenant
'''
import requests
import json
from crayons import *
import sys

host = ""
host_for_token=""
ctr_client_id=""
ctr_client_password=""

item_list=[]

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
    if service=="webex":
        with open('../keys/webex_keys.txt') as creds:
            text=creds.read()
            cles=text.split('\n')
            ACCESS_TOKEN=cles[0].split('=')[1].strip()
            ROOM_ID=cles[1].split('=')[1].strip()
            #print(ACCESS_TOKEN,ROOM_ID) 
            return(ACCESS_TOKEN,ROOM_ID)
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
    if service=="kenna":
        if kenna_token=='paste_kenna_token_here':
            with open('../keys/kenna.txt') as creds:
                access_token=creds.read()
                #print(access_token)          
        else:
            access_token=kenna_token   
        return(access_token)

def get_ctr_token(host_for_token,ctr_client_id,ctr_client_password):
    print(yellow('Asking for new CTR token',bold=True))
    url = f'{host_for_token}/iroh/oauth2/token'
    #url = 'https://visibility.eu.amp.cisco.com/iroh/oauth2/token'
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
    print(token[1])
    fa = open("ctr_token.txt", "w")
    fa.write(token[1])
    fa.close()
    return (token[1])

def get(host,access_token,url,offset,limit):    
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    url = f"{host}{url}?source=XDR Demo&limit={limit}&offset={offset}"
    response = requests.get(url, headers=headers)
    return response

def get2(host,access_token,url,offset,limit):    
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    url = f"{host}{url}?limit={limit}&offset={offset}"
    response = requests.get(url, headers=headers)
    return response    

    
def get_incidents(host,access_token):
    fb = open("z_json_incidents_list.json", "w")
    fd = open("z_incidents_id_list.txt", "w")
    json_output='[\n'
    fc = open("z_incidents_list.txt", "w")
    url = "/ctia/incident/search"
    offset=0
    limit=1000
    go=1 # used to stop the loop   
    while go:      
        index=0
        response = get(host,access_token,url,offset,limit)
        payload = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
        print(response.json())    
        items=response.json()
        for item in items: 
            index+=1
            print(yellow(item,bold=True))
            item_list.append(item)
            #fb.write(json.dumps(item))
            #fb.write(',\n')
            json_output+=json.dumps(item)
            json_output+=',\n'
            fc.write('\n')   
            fd.write(item['id'])
            fd.write('\n')             
        if index>=limit-1:
            go=1
            offset+=index-1
        else:
            go=0
    json_output=json_output[:-2]
    json_output+=']'
    fb.write(json_output)
    fb.close()
    fc.close()
    fd.close()

def get_sightings(host,access_token):
    fb = open("z_json_sighting_list.json", "w")
    fd = open("z_sightings_id_list.txt", "w")    
    url = "/ctia/sighting/search"
    json_output='[\n'
    offset=0
    limit=1000
    go=1 # used to stop the loop   
    while go:      
        index=0
        response = get2(host,access_token,url,offset,limit)
        payload = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
        #print(response.json())    
        items=response.json()
        for item in items: 
            # example of filters here under 
            go=0
            '''
            if 'title' in item.keys():
                if item['title']=="Threat Detected": # filter on title
                    go=1             
            if item['source']=="Secure Endpoint": #filter on source
                go=1  
            if item['severity']=="Critical": # filter on severity
                go=1                             
            for subitem in item["targets"]: # filter on a target name
                for subsubitem in subitem["observables"]:
                    print(yellow(subsubitem))
                    if 'this_endpoint_hostname' in subsubitem.values():
                        go=1    
            '''  
            if item['source']=="XDR Demo": #filter on source
                go=1              
            if go:
                index+=1
                print(yellow(item,bold=True))
                item_list.append(item)
                json_output+=json.dumps(item)
                json_output+=',\n'   
                fd.write(item['id'])
                fd.write('\n')               
            if index>=limit-1:
                go=1
                offset+=index-1
            else:
                go=0
    json_output=json_output[:-2]
    json_output+=']'
    fb.write(json_output)
    fb.close()
    fd.close()
    
def get_judgments(host,access_token):
    source_to_select=["securex-orchestration","Patrick Manually added","XDR Demo"]
    fb = open("z_json_judgements_list.json", "w")
    fd = open("z_judgements_id_list.txt", "w")
    json_output='[\n'
    fc = open("z_judgment_list.txt", "w")
    url = f"/ctia/judgement/search"
    offset=0
    limit=1000
    go=1 # used to stop the loop   
    while go:      
        index=0
        response = get2(host,access_token,url,offset,limit)
        payload = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
        print(response.json())    
        items=response.json()
        for item in items: 
            index+=1
            if item['source'] in source_to_select:
                print(yellow(item,bold=True))
                item_list.append(item)
                #fb.write(json.dumps(item))
                #fb.write(',\n')
                json_output+=json.dumps(item)
                json_output+=',\n'
                ip=item['observable']['value']    
                print(red(ip,bold=True))
                fc.write(ip)
                fc.write('\n')   
                fd.write(item['id'])
                fd.write('\n')             
        if index>=limit-1:
            go=1
            offset+=index-1
        else:
            go=0
    json_output=json_output[:-2]
    json_output+=']'
    fb.write(json_output)
    fb.close()
    fc.close()
    fd.close()
    

    
def get_relationships(host,access_token):
    fb = open("z_json_relationships_list.json", "w")
    fd = open("z_relationships_id_list.txt", "w")
    json_output='[\n'
    fc = open("z_relationships_list.txt", "w")
    url = "/ctia/relationship/search"
    offset=0
    limit=1000
    go=1 # used to stop the loop   
    while go:      
        index=0
        response = get(host,access_token,url,offset,limit)
        payload = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
        print(payload)    
        items=response.json()
        for item in items: 
            index+=1
            print(yellow(item,bold=True))
            item_list.append(item)
            #fb.write(json.dumps(item))
            #fb.write(',\n')
            json_output+=json.dumps(item)
            json_output+=',\n'
            fc.write('\n')   
            fd.write(item['id'])
            fd.write('\n')             
        if index>=limit-1:
            go=1
            offset+=index-1
        else:
            go=0
    json_output=json_output[:-2]
    json_output+=']'
    fb.write(json_output)
    fb.close()
    fc.close()
    fd.close()
    
def delete_incidents(access_token):
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    line_content = []
    with open('z_incidents_id_list.txt') as inputfile:
    	for line in inputfile:
    		line_content.append(line.strip())

    # loop through all urls in z_judgements_id_list.txt ( judgment ids ) and delete them
    for url in line_content:
        #  notice url in z_judgements_id_list.txt are actually the full url with judgment IDs
        print (green(url,bold=True))
        response = requests.delete(url, headers=headers)
        print()
        print (yellow(response,bold=True))     
        
def delete_sightings(access_token):
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    line_content = []
    with open('z_sightings_id_list.txt') as inputfile:
    	for line in inputfile:
    		line_content.append(line.strip())

    # loop through all urls in z_judgements_id_list.txt ( judgment ids ) and delete them
    for url in line_content:
        #  notice url in z_judgements_id_list.txt are actually the full url with judgment IDs
        print (green(url,bold=True))
        response = requests.delete(url, headers=headers)
        print()
        print (yellow(response,bold=True))      
def delete_judgments(access_token):
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    line_content = []
    with open('z_judgements_id_list.txt') as inputfile:
    	for line in inputfile:
    		line_content.append(line.strip())

    # loop through all urls in z_judgements_id_list.txt ( judgment ids ) and delete them
    for url in line_content:
        #  notice url in z_judgements_id_list.txt are actually the full url with judgment IDs
        print (green(url,bold=True))
        response = requests.delete(url, headers=headers)
        print()
        print (yellow(response,bold=True))  

def delete_relationships(access_token):
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    line_content = []
    with open('z_relationships_id_list.txt') as inputfile:
    	for line in inputfile:
    		line_content.append(line.strip())
    for url in line_content:
        print (green(url,bold=True))
        response = requests.delete(url, headers=headers)
        print()
        print (yellow(response,bold=True))         

def main():
    with open('config.txt','r') as file:
        text_content=file.read()
    ctr_client_id,ctr_client_password,host,SecureX_Webhook_url,DESTINATION_ROOM_ID,BOT_ACCESS_TOKEN,host_for_token = parse_config(text_content)
    print('host : ',host)
    print(yellow("Step 1 ask for an access token to CTR",bold=True))
    access_token=get_ctr_token(host_for_token,ctr_client_id,ctr_client_password)
    print(green("Ok Token = Success",bold=True))
    print(yellow("Step 2 get incidents",bold=True))
    get_incidents(host,access_token)
    print(green("Ok incidents Success",bold=True))
    print(yellow("Step 3 delete incidents",bold=True))     
    delete_incidents(access_token)
    print(green("Ok Success",bold=True))    
    print(yellow("Step 4 get sightings",bold=True))    
    get_sightings(host,access_token)
    print(green("Ok sightings Success",bold=True))
    print(yellow("Step 5 delete sightings",bold=True))     
    delete_sightings(access_token)
    print(green("Ok Success",bold=True))
    print(yellow("Step 6 get judgments",bold=True))  
    get_judgments(host,access_token)
    print(green("Ok Success",bold=True))
    print(yellow("Step 7 delete judgments",bold=True))   
    delete_judgments(access_token)
    print(yellow("Step 8 get relationships",bold=True))  
    get_relationships(host,access_token)
    print(green("Ok Success",bold=True))
    print(yellow("Step 9 delete relationships",bold=True))   
    delete_relationships(access_token)
    print(green("Ok All Done ",bold=True))
if __name__ == "__main__":
    main()
