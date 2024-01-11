#!/usr/bin/env python
from __future__ import with_statement
import time, base64
import os,sys,random
import json
import regex as re
from crayons import *
from create_XDR_incident import go_for_incident

observables={}
       
def parser():
    access_logs  = "./input_log_file/access.log"
    start = time.time()
    with open("./out/out.txt","w") as file_out:
        with open(access_logs) as log_file:            
            for line in log_file:
                # IDS SIGNATURES : Here Under signatures used to detect threats line by line
                # Uncomment the signatures you want to activate or add another elif statement with your own signatures
                if "pma_password=" in line and "phpmyadmin" in line and not "token" in line:
                    line_out="Impact High *;* Admin access attempt on MySQL database thru phpmyadmin *;* "+line+'\n'
                    file_out.write(line_out)
                    keep_this_ip_in_observables(line)
                '''
                elif "/cgi-bin/ViewLog.asp" in line or "Akitaskid.arm7" in line:
                    line_out="Impact High *;* Device Vulnerability Exploit ( zyxel ) *;* "+line+'\n'
                    file_out.write(line_out)
                elif "HelloThinkPHP" in line:
                    line_out="Impact High *;* Application Vulnerability Exploit ( Wordpress ) *;* "+line+'\n'
                    file_out.write(line_out) 
                elif "goform/setUsbUnload" in line:
                    line_out="Impact High *;* Device Vulnerability Exploit ( Tenda AC1900 Router AC15 Model Remote Code Execution Vulnerability ) *;* "+line+'\n'
                    file_out.write(line_out) 
                elif "netgear" in line:
                    line_out="Impact High *;* Device Vulnerability Exploit ( Netgear ) *;* "+line+'\n'
                    file_out.write(line_out)   
                elif "/shell" in line and "wget" in line:
                    line_out="Impact High *;* Device Vulnerability Exploit ( ---- ) *;* "+line+'\n'
                    file_out.write(line_out)                     
                elif "HelloThink" in line:
                    line_out="Impact High *;* Application Vulnerability Exploit ( HelloThink ) *;* "+line+'\n'
                    file_out.write(line_out)  
                elif "XDEBUG_SESSION_START=phpstorm" in line:
                    line_out="Impact High *;* Application Vulnerability Exploit ( phpstorm ) *;* "+line+'\n'
                    file_out.write(line_out)          
                elif ( line.count('..')>2 ):
                    line_out="Impact High *;* Directory Traversal *;* "+line+'\n'
                    file_out.write(line_out)   
                elif ( line.count('%')>10 ):
                    line_out="Impact Medium *;* Obfuscation attempt *;* "+line+'\n'
                    file_out.write(line_out)    
                elif "/etc/passwd" in line:
                    line_out="Impact Medium *;* /etc/passwd access attempt *;* "+line+'\n'
                    file_out.write(line_out)    
                elif "+union" in line and "+select" in line:
                    line_out="Impact High *;* SQLI Attempt *;* "+line+'\n'
                    file_out.write(line_out)                      
                elif '" 404 ' in line or '" 403 ' in line:
                    line_out="Impact Low *;* Web Site Resource Scan *;* "+line+'\n'
                    file_out.write(line_out)                         
                if "/robots.txt" in line or "/sitemap.xml" in line:
                    line_out="Impact Low *;* Web Site Mapping attempt *;* "+line+'\n'
                    file_out.write(line_out)  
                if "<script" in line or "%3Cscript" in line or "alert(" in line or "alert%28" in line:
                    line_out="Impact Low *;* Code Injection into formular ( XSS attempt )*;* "+line+'\n'
                    file_out.write(line_out)
                '''
        file_out.write(line_out)                            
    tt = time.time() - start
    print()
    print(cyan("  Parsing Done in %f s" % (tt),bold=True))
    # Create XDR Alerts based on content of analysis results
    if observables:
        print()
        print(yellow("- Step 2 : We have some XDR alerts to add into an XDR Incident",bold=True))
        print()
        a=input("Do you want to create an XDR Incident ( Y/N ) ? : ")
        print()
        if a=='Yes' or a=='Y' or a=='y':
            #print(red(observables,bold=True))
            ip_list=[]
            for item in observables:
                #print(green(observables[item]['nb']))
                if observables[item]['nb']>5:
                    print(cyan(f"Observable to add to XDR Sighting : {item}",bold=True))
                    ip_list.append(item)
            print()
            target_list=get_targets()
            observables_objects,observable_relationships=create_json_observables(ip_list,target_list)
            #go_for_incident(observables_objects,targets,observable_relationships)  
    print()
    print(yellow("- OK ALL DONE !",bold=True))
    
def keep_this_ip_in_observables(line):
    ip=line.split(" ")[0]    
    if ip not in observables.keys(): 
        observables[ip]={'nb':1}
    else:
        observables[ip]['nb']+=1
        
def get_targets():
    # this function is supposed to parse the log or any other source in order to extract targets and put them into the returned list
    # in our case as we know the target, this is the Honeypot Web Server then we set statically the target value
    target_list=[]
    target_list.append('84.85.86.87')
    return target_list
 
def create_json_observables(ip_list,ip_target): 
    observables=[]
    relationships=[]
    for item in ip_list:
        observable_item={'type':'ip','value':item}
        observables.append(observable_item)
        relationship_item={
          "origin": "XDR Demo Detection",
          "origin_uri": "https://localhost:4000/",
          "relation": "Connected_To",
          "source": {
            "value":ip_target[0], # in our demo we only have one target
            "type":"ip"
          },
          "related": {
            "value":item,
            "type":"ip" 
          }
        }
        relationships.append(relationship_item)
    print('observables : ',green(observables,bold=True))  
    print('relationships : ',green(relationships,bold=True))
    return observables,relationships
    
def main():
    access_logs  = "./input_log_file/access.log"
    print()
    print(yellow("- Step 1 : Let's start ./input_log_file/access.log file parsing",bold=True))
    parser()
    print()
    print(green("OK All Done !.  result in ./out subfolder",bold=True))

if __name__ == "__main__":
    main()

