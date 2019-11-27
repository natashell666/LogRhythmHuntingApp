# LogRhythm Threat Hunting App

This project contains code that allow LogRhythm integration with multiple Threat Intelligence providers, increasing LogRhythm OTB capabilities for Threat Hunting Automation, and Historical Correlation.

## Project Distribution

So far this project contains four different types of providers:
* **ThreatIntel Providers** - These are different ThreatLists options to be integrated into the LogRhythm Platform.
	- **Anomali** - Contain the methods for the integration with Anomali, mapping the origin fields into LogRhythm fields. You have the option to select the minimul level of confidence.
	- **Hippocampe** - Are you familiar with [The Hive Project](https://thehive-project.org/), they have their own ThreatFeed Aggregator: [Hippocampe](https://github.com/TheHive-Project/Hippocampe). This module allows you to integrate the IOC's from Hippocampe and add them into LogRhythm.
	- **LogRhythm** - Do you want to integrate the LogRhythm Threat Feeds into your own solution, this module query the LogRhythm ThreatList API base on your needs.
	- **MISP** - On this module, you can just use MISP as a ThreatFeed aggregator and use them into the LogRhythm Threat Feed lists.

* **Case Providers** - These are the modules that allow interconnect with external cases from or to LogRhythm.
	- **The Hive** - *Work In Progress* -Allows LogRhythm create incidents into The Hive.
	- **MISP** - Using your LogRhythm cases, this module allows you to export the information on LogRhythm and create an Evento into MISP, adding as many IOC's as necessary.
	- **LogRhythm** - Sometimes you want to edit or modify Alarms or Cases into the LogRhythm SOAR, this module has all the methods to do that.

* **List Providers** - This module has the methods needed to integrate with the LogRhythm List API for integration in other modules.

* **Hunting Providers** - These modules extend LogRhythm capabilities for Threat Hunting.
	- **Cortex** - Contain the methods needeed to run the analyzers and export the output acording to the integration requierements.
	- **MISP** - Contain the methods for advanced integration with MISP, including exporting of IOC's, events and zMQ subscription.

## Prerequisites

------------

### LogRhythm
1. An [API Key](https://onlinehelp74.logrhythm.com/#3Administration/AdminAPI/AdminAPIOverview.htm) must be generated.

2. Create a [Third Party Application](https://onlinehelp74.logrhythm.com/#3Administration/AdminAPI/Register3rdPartyAppUseAdminAPI.htm).

3. Generate the [JWT Token](https://onlinehelp74.logrhythm.com/#3Administration/AdminAPI/GenerateJSONTokenUseAdminAPI.htm) and copy it to the configuration file you need.

4. If you want to make use of the Historical Search Capabilities using this application, you'll have to create access to the elasticsearch instance on the Data Indexer (For each DX Node, allow access to the port 9200)

5. Finally if you want to add playbooks to the Cases generated inside LogRhythm, you'll need a the Playbook UUID. If you want to know the UUID for a Playbook:

	a. Login into the LogRhythm WebConsole

	b. Click on Administration --> Playbooks

	c. Click on the Playbook you're interested and copy from the URL the UUID, the URL has the following format: `https://Hostname:Port/admin/playbooks/{UUID}`
    
------------

### MISP
1. Configure the [ZeroMQ](https://www.circl.lu/doc/misp/misp-zmq/) functionality.

2. Allow the access to the zmq port (By default port 50000)

3. If you want to push events to MISP, from LogRhythm you'll need the [API URL](https://www.circl.lu/doc/misp/automation/#automation-url) and [API Key](https://www.circl.lu/doc/misp/automation/#automation-key) from you deployment.

------------

### CORTEX
Cortex API can work using API, Sessions or Basic Authentication, however this project uses and API Key, to create the API Key needed:
1. Connect to the Cortex using an orgAdmin account

2. Click on Organization.

3. Click on the Create API Key button in the row corresponding to the user you intend to use for API authentication.

4. Once the API key has been created, click on Reveal to display the API key

5. Click on the copy to clipboard button and save it on the requested file.

------------

### The Hive
1. Log into your Hive deployment.

2. Go to the main menu in the top right.

3. Select the "API information"

4. Generate a key for use throughout the API.

## Installation and Configuration
This project requires Python 3. It does not support Python 2.

### Pyhton Requirements
* requests >= 2.21.0
* pyodbc >= 4.0.26
* pymisp >= 2.4.103
* urllib3 >= 1.24.2
* Cython >= 0.29.7
* jsonschema >= 3.0.1
* certifi >= 2019.3.9
* chardet >= 3.0.4
* idna >= 2.8
* python-dateutil >= 2.8.0
* six >= 1.12.0
* zmq >= 0.0.0
* elasticsearch >= 6.3.1
* ElasticQuery >= 3.2
* PyYAML > 5.1.1
* attrs >= 19.1.0
* cffi >= 1.7.0
* cortex4py >= 2.0.1
* future >= 0.17.1
* libmagic >= 1.0
* python-libmagic >= 0.4.0
* python-magic >= 0.4.13
* python-magic-bin >= 0.4.14
* python-magic-win64 >= 0.4.14 (If running the app on Windows)
* pyzmq >= 18.0.1
* thehive4py >= 1.6.0
* typing >= 3.7.4

### Install It
1. Clone the Repository

2. Install the pre-requisites

## Use Cases

### Anomali Threat List Update
If you don't want to use the LogRhythm Threat Intelligence Services (TIS), you can make use of this app to connecto to Anomali

    python.exe LogRhythmAnomaliLists.py 'email@domain.com' MyAnomaliAPIKey --all --list_directory=C:\Users\natas\Anomali_test --risk 0 --list

This command connects to the Anomali API and download all the Threat Lists in the speciefied directory. The *risk* parameter is the minimun confidence level.
If you want to learn more about this command, you can get the help via:

    python.exe LogRhythmAnomaliLists.py

### Hippocampe Threat List Update
This command connects to the Anomali API and download all the Threat Lists in the speciefied directory. The main parameters are:
* -\-list -> Save the list item in files inside a Directory
* -\-api -> Save the list items into LogRhythm Directly using the LogRhythm REST API.

If you want to learn more about this command, you can get the help via:

    python.exe ### Anomali Threat List Update
If you don't want to use the LogRhythm Threat Intelligence Services (TIS), you can make use of this app to connecto to Anomali

    python.exe LogRhythmAnomaliLists.py 'email@domain.com' MyAnomaliAPIKey --all --list_directory=C:\Users\natas\Anomali_test --risk 0 --list

This command connects to the Anomali API and download all the Threat Lists in the speciefied directory. The *risk* parameter is the minimun confidence level.
If you want to learn more about this command, you can get the help via:

    python.exe LogRhythmAnomaliLists.py

### LogRhythm Hunting App daemon.

It's an uninterrupted process that await MIPS events or attributes and search for them in the Data Indexer for any coincidence. Depending on the selected configuration, the daemon may just update a Threat List, or even raised a case and launch a complete Hunting Automation Process.

When a new event arrives to the MISP, it will be sent to LogRhythm and LogRhythm will be waiting for the IoC's. Those IoC's will be saved in a temporary buffer that will wait *N seconds* after a new event comming or after *N seconds* without interaction.

After a new attr is gather it will be looked into the platform too.

In case of the events of the whole EVENT is generated, a new case will be launch with the information
* Case
* Event from MISP as NAME
* Summary
* Collaborators
* Notes as result of the search

The IoC's will be add to a ThreatList too.

When the daemon receives an attribute, the daemon will perform the following steps:
* The IOC will be add to a list
* The IOC will be search in the whole Data Indexer it'll raise an Event that can be correlated too.

To start the daemon, you have to type:

    python.exe -m HuntingProviders.MISP.MISPReceiver --config PATH_TO_CONFIG_FILE

The configuration file is YAML based and provides options and features to be enabled/disabled.
This configuration YAML looks like this:


    misp:
      misp_host: misp.natashell.me
      misp_port: 50000
    # These are the misp events accepted via zmq. 
      misp_filter:
        - misp_json_event
        - misp_json_attribute
        - misp_json
        - misp_json_sighting
        - misp_json_self
    #Enable the debug file for MIS Conncetions
      misp_status: False
    #Files where the misp events or logs are saved
      misp_file_status: c:\misp-events\misp.status
      misp_file_event: c:\misp-events\misp_evt.log

    elastic:
    #How many historical hours look for
      search_back: 1440
      max_timeout: 20
      elastic_host: dx.natashell.me
    #Select only a few fields to be displayed on the search.
      fields:
        - originIp
        - originHostName
        - commonEventName
        - msgClassName
        - impactedIp
        - logMessage
        - logSourceName

    logrhythm:
      api_host: https://mypm.natashell.me:8501
      api_key: ACBDEABCDEABCDE
    # User ID of the collaborators to be add in the case.
      colabs:
        - 1
        - 5
    # User ID of the owner of the Case raised into LogRhythm
      owner: 0
    # Case Status
      status: 3
    # Playbook ID to be add into the case
      playbook_id: 3BEDB5AF-2BD0-4080-BBB4-3F86F72FA799
    # Priority of the Case raised into LogRhythm
      priority: 1
    # Tags to be add into the case
      tags:
        - misp
        - incident
        - collaboration
        - sharing
        - lr_integration
        - hunting
        - automation
    # Max number of evidence saved as a Note in the LogRhythm case. Each result will be a note in the case
      top_es_evidence: 10

## TODO
* SmartResponse Plugins for manual/automatic execution on an  Alarm.
* The Hive command line
* Dinamic Collaborator, Owner, Playboor or tags based on custom user rules.
