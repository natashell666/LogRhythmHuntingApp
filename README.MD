GENERAL WORKFLOW:

When a new event arrives to the MISP, it will be sent to LogRhythm and LogRhythm will be waiting for the IoC's.
Those IoC's will be saved in a temporary buffer that will wait Nsecs after a new event comming or after Nsecs without
interaction.

After a new attr is gather it will be looked into the platform too.

-------------------

In case of the events of the whole EVENT is generated, a new case will be launch with the information
    * Case
    * Event from MISP as NAME
    * Summary
    * Collaborators
    * Notes as result of the search

The IoC's will be add to a ThreatList too.
    
In case of the attrs they:
    * Will be add to a list
    * Will be looked internally and raise an Event, this event can generate the multiple as CAT
    
--------------------

Better instructions and README to be published during the week.
    