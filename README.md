DSer-SQLi
=========

At it's current state, this is a very rough modification to Manish Saindane's tool "DSer".  The idea is to incorporate injection tools (that support proxies) with the intent to attack Java serialized communication in an automated fashion.  For instance, if you know a SQLi vuln exists, it would be nice to use a tool like sqlmap to automate exploitation. If you are unfamiliar with DSer, please take a moment to watch Manish's video located on the Attack and Defense website (http://www.andlabs.org).  You can also read his slides from Blackhat Europe 2010 ("Attacking Java Serialized Communication") as well as dowload his original tool there. 

UPDATE: Chilik Tamir has created a plugin for Burp Proxy called "Belch" which can be downloaded from the AppSec-Labs web site:

https://appsec-labs.com/belch

I haven't had a chance to use it yet but it looks very well done.  At this point in time, I would recommend using his tool instead. 

Nice job Chilik!
