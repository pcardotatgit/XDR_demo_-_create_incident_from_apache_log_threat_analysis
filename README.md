# Create an XDR incident from Attack Detection into apache log

This script is a proof of concept of creation of an XDR Incident from a security log file analysis.

In this proof of concept we apply what we learned in the [XDR_create_incident_with_python ](https://github.com/pcardotatgit/XDR_create_incident_with_python) article to a realistic use case.

In the article mentionned above we created an XDR Incident from static demo data. In this article we dynamically create the XDR Incident data from Threat Analysis done on a apache access log file.

This use case is a good example of somethoing to deploy in production. It is very easy to deploy.

You just have to setup a Honeypot Apache Web Server, expose it on the INTERNET and install into it the apache log analyser described here and that's it.

Within a few hours your web server will be discovered by INTERNET Bots and you will see Web attacks coming. 

These attackes will be visible into the apache access.log file. 

Then you just have to run the application to collect a list of malicious public IP addresses that try to hack your web server and from this create XDR Incident and next add these malicious IP addresses to your XDR blocking feed.

But in order to make this use case pedagogic I added some specifications to the application.

## How the application work ?

For this use case the apache log file named **access.log** is located into the  **./input_log_file** subdirectory.

The application reads it and apply on every line of the log file a partern matching string search for common signature we used to find into Web Attacks. 

Every threat detected is logged into a resulting report file.

The result of the analysis will be located into the **./out** directory. And will contain absolutely every threats detected into the log file.

But only one of this threats will create an **XDR Incident**. This is the **Admin Access Attempt to phpmyadmin threat** which is easily visible into the apache log file. And we decide to add to the Incident only source IP addresses which try to get access to phpmyadmin thru brute force more than 10 times.

This is an arbitrary rule we decide, because that one seems to be good to filter IP source addresses which show real malicious intentions. These malicious IP addresses are 100 % confirmed malicious. 

The core of the application is the **1-analyse_log.py** script. This is the script to run.

The XDR Incident Creation is managed by the **create_XDR_incident.py** script. You will probably recognize it if you went thru the [XDR_create_incident_with_python ](https://github.com/pcardotatgit/XDR_create_incident_with_python) article.

This is exactly the same script a little bit modified for fitting to this use case, and use as a ressource by the **1-analyse_log.py** script.

The **1-analyse_log.py** contains the Threat Detection engine. This is a partern matching engine which search for signatures into every log file lines. Patern search is based an compiled regex and is really reasonably fast !!.

That means that the script will go fast enough for scanning big log files. Performance is not really the goal but still.

That means that the first operation done by the script is to load all signatures before going to analysis. 

Signatures are located into the JSON file named **sigs.json** located in the **./signatures** subdirectory. 

The JSON format makes it very easy to understand and to modify. You can easily add your own signatures. For example log4J signatures are missing in this version. This can become an interesting additionnal challenge.

Don't hesitate to have a look to the signature file and modify it.

So in this project we use the patern matching engine in order to isolate orphan attacks. And among these detected attacks we had an additionnal analysis level, which is in our case a very basic correlation step :

We save the source IP addresses of the **Admin access attempt on MySQL database thru phpmyadmin** alerts when we see more thean 10 occurences of the alert for the same IP address. We keep into a global list a single instance of every malicious IP address.

That means that in this project we decide to promote to XDR Incident only one detected Threat. 

Incident promotion is done when we create the resulting file into the **def generate_text_file()** function of the **1-analyse_log.py** script. So this is really another step that happen only after partner matching search is done into the whole log file.

In this part of the code, we pass the list of the malicious IP addresse to the **create_json_observables()** function which create the JSON payloads for observables and observable_relationships. Regarding the target JSON payload, as we only have one target ( the webe server ) and we know it I decided to declare it into static variable. 

The next step is to pass these payloads as argument to the **def create_sighting_object()** function of the **1-analyse_log.py** script.  This is where we link the main script to the **create_XDR_incident.py** script which is the resource script dedicated to XDR Incident creation.

## Run the application

First edit the **config.txt** file and assig the correct values to the application variables

Second run the application 

    python 1-analyse_log.py
    
The full analysis report will be located into the **./out** dictectory.

And at the same time a new XDR Incident had been created into XDR. Check it into the XDR Incident Manager.

## Clean Up demo data

Run the **2-delete_XDR_demo_data.py** script in order to completely clean up Data created into XDR.


