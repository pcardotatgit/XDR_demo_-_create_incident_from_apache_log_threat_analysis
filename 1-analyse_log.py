#!/usr/bin/env python
from __future__ import with_statement
import time, base64
import os,sys,random
import json
import regex as re
from crayons import *
from create_XDR_incident import go_for_incident

#Threat Classification nomenclature
names = {
    'xss'  : 'Cross-Site Scripting',
    'sqli' : 'SQL Injection',
    'csrf' : 'Cross-Site Request Forgery',
    'dos'  : 'Denial Of Service',
    'dt'   : 'Directory Traversal',
    'spam' : 'Spam',
    'id'   : 'Information Disclosure',
    'rce'  : 'Remote File Execution',
    'lfi'  : 'Local File Inclusion',
    'adm'  : 'Admin Access Attempt',
    'scan'  : 'Vulnerability scan test',
    'db-access' : 'Database Access Attempt',
    'appli_vuln_exploit':'Application vulnerability exploitation',
    'device_exploit':'Networking Device vulnerability Exploitation'
}

targets=[
  {
    "type": "endpoint",
    "observables": [
      {
        "value": "Public Web Server",
        "type": "hostname"
      },
      {
        "value": "84.85.86.87",
        "type": "ip"
      },
      {
        "value": "00:E1:6D:26:24:E9",
        "type": "mac_address"
      }
    ],
    "observed_time": {
      "start_time": "2023-09-09T13:31:02.000Z",
      "end_time": "2023-09-09T13:31:02.000Z"
    }
  }
]

observables={}

c_reg = re.compile(r'^(.+)-(.*)\[(.+)[-|+](\d+)\] "([A-Z]+)?(.+) HTTP/\d.\d" (\d+)(\s[\d]+)?(\s"(.+)" )?(.*)$')
table = {}

class BreakLoop( Exception ):
    pass


class object_dict(dict):
    def __init__(self, initd=None):
        if initd is None:
            initd = {}
        dict.__init__(self, initd)
    def __getattr__(self, item):
        d = self.__getitem__(item)
        # if value is the only key in object, you can omit it
        if isinstance(d, dict) and 'value' in d and len(d) == 1:
            return d['value']
        else:
            return d
    def __setattr__(self, item, value):
        self.__setitem__(item, value)

d_replace = {
    "\r":";",
    "\n":";",
    "\f":";",
    "\t":";",
    "\v":";",
    "'":"\"",
    "+ACI-":"\"",
    "+ADw-":"<",
    "+AD4-"      : ">",
    "+AFs-"      : "[",
    "+AF0-"      : "]",
    "+AHs-"      : "{",
    "+AH0-"      : "}",
    "+AFw-"      : "\\",
    "+ADs-"      : ";",
    "+ACM-"      : "#",
    "+ACY-"      : "&",
    "+ACU-"      : "%",
    "+ACQ-"      : "$",
    "+AD0-"      : "=",
    "+AGA-"      : "'",
    "+ALQ-"      : "\"",
    "+IBg-"      : "\"",
    "+IBk-"      : "\"",
    "+AHw-"      : "|",
    "+ACo-"      : "*",
    "+AF4-"      : "^",
    "+ACIAPg-"   : "\">",
    "+ACIAPgA8-" : "\">",
}
re_replace = None


def fill_replace_dict():
    global d_replace, re_replace
    # very first control-chars
    for i in range(0,20):
        d_replace["%%%x" % i] = "%00"
        d_replace["%%%X" % i] = "%00"
    # javascript charcode
    for i in range(33,127):
        c = "%c" % i
        d_replace["\\%o" % i] = c
        d_replace["\\%x" % i] = c
        d_replace["\\%X" % i] = c
        d_replace["0x%x" % i] = c
        d_replace["&#%d;" % i] = c
        d_replace["&#%x;" % i] = c
        d_replace["&#%X;" % i] = c
    # SQL words?
    d_replace["is null"]="=0"
    d_replace["like null"]="=0"
    d_replace["utc_time"]=""
    d_replace["null"]=""
    d_replace["true"]=""
    d_replace["false"]=""
    d_replace["localtime"]=""
    d_replace["stamp"]=""
    d_replace["binary"]=""
    d_replace["ascii"]=""
    d_replace["soundex"]=""
    d_replace["md5"]=""
    d_replace["between"]="="
    d_replace["is"]="="
    d_replace["not in"]="="
    d_replace["xor"]="="
    d_replace["rlike"]="="
    d_replace["regexp"]="="
    d_replace["sounds like"]="="
    re_replace = re.compile("(%s)" % "|".join(map(re.escape, d_replace.keys())))


def multiple_replace(text):
    return re_replace.sub(lambda mo: d_replace[mo.string[mo.start():mo.end()]], text)

# the decode engine tries to detect then decode...
def decode_attempt(string):
    return multiple_replace(string)

def analyzer(data):
    exp_line, regs, array, preferences, org_line = data[0],data[1],data[2],data[3],data[4]
    done = []
    # look for the detected attacks...
    # either stop at the first found or not
    for attack_type in preferences['attack_type']:
        if attack_type in regs:
            if attack_type not in array:
                array[attack_type] = {}
            for _hash in regs[attack_type]:
                if _hash not in done:
                    done.append(_hash)
                    attack = table[_hash]
                    cur_line = exp_line[5]
                    if preferences['encodings']:
                        cur_line = decode_attempt(cur_line)
                    if attack[0].search(cur_line):
                        if attack[1] not in array[attack_type]:
                            array[attack_type][attack[1]] = []
                        array[attack_type][attack[1]].append((exp_line, attack[3], attack[2], org_line))
                        if preferences['exhaustive']:
                            break
                        else:
                            return

def parser(access, filters, preferences = [], output = "text"):
    global table
    if not os.path.isfile(access):
        print("error: the log file doesn't exist")
        return
    # prepare to load the compiled regular expression
    regs = {} # type => (reg.compiled, impact, description, rule)      
    print()
    print(yellow(f"- Step 1 : Loading signature JSON file {filters}",bold=True ) )
    # load the JSON file
    with open(filters) as json_data:
        json_data_2=json.load(json_data)['filters']['filter']
        list_keys=[ k for k in json_data_2 ]
        for x in list_keys:
            '''
            print()
            print(green(x,bold=False))
            print()
            '''
            tags=[]
            impact = int(x['impact'])
            rule = x['rule']
            description = x['description']
            if 'tags' in x and 'tag' in x['tags']:
                if type(x['tags']['tag']) == type([]):
                    for tag in x['tags']['tag']:
                        tags.append(tag)
                else:
                    tags.append(x['tags']['tag'])
            # register the entry in our array
            for t in tags:
                compiled = None
                if t not in regs:
                    regs[t] = []
                try:
                    compiled = re.compile(rule)
                except Exception:
                    print("The rule '%s' cannot be compiled properly" % rule)
                    return
                _hash = hash(rule)
                if impact > -1:
                    table[_hash] = (compiled, impact, description, rule, _hash)
                    regs[t].append(_hash)   
    if len(preferences['attack_type']) < 1:
        preferences['attack_type'] = regs.keys()
    flag = {} # {type => { impact => ({log_line dict}, rule, description, org_line) }}
    print(yellow(f"- Step 1 : OK signatures loaded",bold=True ))   
    print()   
    print(yellow(f"- Step 2 : Processing the log file",bold=True ))   
    loc, lines, nb_lines = 0, 0, 0
    old_diff = 0
    start = time.time()
    diff = []
    with open(access) as log_file:
        txt_content=log_file.read()
        line_list=txt_content.split('\n')
        #for line in log_file:
        for line in line_list:
            lines += 1
            if c_reg.match(line):
                out = c_reg.search(line)
                #print(red(out,bold=True))
                ip = out.group(1)
                name  = out.group(2)
                date = out.group(3)
                ext  = out.group(4)
                method = out.group(5)
                url = out.group(6)
                response = out.group(7)
                byte = out.group(8)
                referrer = out.group(9)
                agent = out.group(10)

                if preferences['ip_exclude'] != [] or preferences['subnet_exclude'] != []:
                    ip_split = ip.split()
                    if ip_split[0] in preferences['ip_exclude']:
                        continue

                    try:
                        for sub in preferences['subnet_exclude']:
                            if ip_split[0].startswith(sub):
                                raise BreakLoop()
                    except BreakLoop:
                        continue

                if not correct_period(date, preferences['period']):
                    continue
                loc += 1
                if len(url) > 1 and method in ('GET','POST','HEAD','PUT','PUSH','OPTIONS'):
                    analyzer([(ip,name,date,ext,method,url,response,byte,referrer,agent),regs,flag, preferences, line])
            elif preferences['except']:
                diff.append(line)

            # mainly testing purposes...
            if nb_lines > 0 and lines > nb_lines:
                break

    tt = time.time() - start
    n = 0
    for t in flag:
        for i in flag[t]:
            n += len(flag[t][i])
    print(yellow(f"- Step 2 : Ok Done",bold=True ))
    print()
    print(cyan("Analysis results:",bold=True))
    print(cyan("\tProcessed %d lines over %d" % (loc,lines),bold=True))
    print(cyan("\tFound %d attack patterns in %f s" % (n,tt),bold=True))
    print()
    short_name = access[access.rfind(os.sep)+1:]
    if n > 0:
        print("Generating output in ./out/result.txt")
        generate_text_file(flag, short_name, filters, preferences['odir'])
    # generate exceptions
    if len(diff) > 0:
        o_except = open(os.path.abspath(preferences['odir'] + os.sep + "except.txt"), "w")
        for l in diff:
            o_except.write(l + '\n')
        o_except.close()
        
def keep_this_ip_in_observables(line):
    ip=line.split(" ")[0]    
    if ip not in observables.keys(): 
        observables[ip]={'nb':1}
    else:
        observables[ip]['nb']+=1
 
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
            "value":ip_target,
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
    
def generate_text_file(flag, access, filters, odir):
    curtime = time.strftime("%a-%d-%b-%Y", time.localtime())
    fname = '/out/result_%s.txt' % (curtime)
    fname = os.path.abspath(odir + os.sep + fname)
    out = open(fname, 'w')
    for attack_type in flag:
        if attack_type in names:
            Attack_type="Attack %s (%s)" % (names[attack_type], attack_type)
        else:
            Attack_type="Attack type: %s" % attack_type
        impacts = list(flag[attack_type].keys())
        impacts.sort(reverse=True)
        for i in impacts:
            Impact_value="Impact %d" % int(i)
            for e in flag[attack_type][i]:
                line_out=Impact_value+" *** "+Attack_type+' *** '
                log=e[3].replace("\n","")
                line_out+=log+" *** Reason: "+e[2]+"\n"
                out.write(line_out)
                if "Admin access attempt on MySQL database thru phpmyadmin" in e[2]:
                    keep_this_ip_in_observables(e[3])
    out.close()
    # Create XDR Alerts based on content of analysis results
    if observables:
        print()
        print(yellow("- Step 3 : We have some XDR alerts to add into an XDR Incident",bold=True))
        print()
        a=input("Do you want to create an XDR Incident ( Y/N ) ? : ")
        if a=='Yes' or a=='Y' or a=='y':
            #print(red(observables,bold=True))
            ip_list=[]
            for item in observables:
                #print(green(observables[item]['nb']))
                if observables[item]['nb']>5:
                    #print(cyan("Observable to add to XDR Sighting : ",item))
                    ip_list.append(item)
            observables_objects,observable_relationships=create_json_observables(ip_list,'84.85.86.87')
            go_for_incident(observables_objects,targets,observable_relationships)
    return

months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']

def correct_period(date, period):
    date   = date.replace(':', '/')
    l_date = date.split('/')
    for i in (2,1,0,3,4,5):
        if i != 1:
            cur = int(l_date[i])
            if cur < period['start'][i] or cur > period['end'][i]:
                return False
        else:
            cur = months.index(l_date[i])
            if cur == -1:
                return False
            if cur < period['start'][i] or cur > period['end'][i]:
                return False
    return True

def main():
    sigs = "./signatures/sigs.json"
    access_logs  = "./input_log_file/access.log"
    output  = ""
    preferences = {
        'attack_type' : [],
        'ip_exclude' : [],
        'subnet_exclude' : [],
        'period' : {
            'start' : [1, 00, 0000, 00, 00, 00],# day, month, year, hour, minute, second
            'end'   : [31, 11, 9999, 24, 59, 59]
        },
        'except'     : False,
        'exhaustive' : True,
        'encodings'  : False,
        'output'     : "text",
        'odir'       : os.path.abspath(os.curdir),
        'sample'     : float(100)
    }

    parser(access_logs, sigs, preferences)
    print()
    print(green("OK All Done !",bold=True))

if __name__ == "__main__":
    main()
