# Field names, types and description #

## Index redirtraffic-* ##

### ELK stack / Filebeat default fields ###
| Field name   | Type    | Description    |
| --- | --- | --- |
| beat.hostname  | String | Hostname of redirector, alias to agent.hostname (legacy field name, dropped in v7 in favor of agent.hostname) |
| beat.name	   	 | String | Host identifier as entered in the filebeat.yml cionfig file on the redir (legacy field name, dropped in v7 in favor of host.name) |
| beat.version	 | String | Version of filebeat running on the redirector |
| host.name	   	 | String | Host identifier as entered in the filebeat.yml config file on the redir |
| input.type	 | String | Type of the log as identified in the filebeat.yml config file |
| log.file.path	 | String | File path of the log file on the redirector |
| message	   	 | String | Full log message |
| offset	   	 | Number | Number of bytes read |
| prospector.type| String | Legacy naming of input.type, as defined in the filebeat.yml config file | 

### RedELK introduced fields ###
| Field name   | Type    | Description    |
| --- | --- | --- |
| attackscenario                    | String  | Name of the attackscenario this redirector traffic belongs to, configured in filebeat.yml on redir |
| geoip.as_org	   	                | String  | AS name according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.asn	   	                    | String  | AS number according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.city_name	   	            | String  | City name according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.continent_code              | String  | Continent code according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.country_code2               | String  | Country code according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.country_code3	            | String  | Country code in other naming according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.country_name                | String  | Country name according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.dma_code                    | Number  | DMA/Metro code according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.ip	   	                    | IP      | IP address used for GeoIP lookup, copied from redirtraffic.sourceip |
| geoip.latitude	   	            | Number  | Latitude position according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.location	   	            | GeoPoint| GeoPoint type, contains lat and lon value, used for plotting on maps |
| geoip.longitude	   	            | Number  | Longitude position according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.postal_code	                | String  | Postal code according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.region_code	                | String  | Region code according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.region_name	                | String  | Region name according to GeoIP lookup, source is redirtraffic.sourceip |
| geoip.timezone	   	            | String  | Timezone name according to GeoIP lookup, source is redirtraffic.sourceip |
| greynoise.*                       | Varying | Fields and data as set by Greynoise |
| infralogtype                      | String  | identifier of the type of log that filebeat ships, configured in filebeat.yml on redir, default 'redirtraffic' |
| syslogpid                         | Number  | Process ID of the redirector program, as reported by Syslog |
| syslogprogram                     | String  | Name of the redirector program, as reported by Syslog |
| redir.backendname 	            | String  | Name of the destination that the traffic has sent to, typical something like decoy-http1 or c2-https as defined in the redir program's config |
| redir.frontendname 	            | String  | Name of the frontend that redirecotr received the the traffic on, typical something like www-http or www-https as defined in the redir program's config |
| redir.frontendip                  | IP      | IP address of the redirector where the traffic was received on |
| redir.frontendport                | Number  | Port on the redirector where the traffic was received on |
| sysloghostname 	                | String  | Hostname of the redirector, as reported by Syslog or by Apache |
| redirtraffic.headersall           | String  | All headers as logged by the rediredctor program. These are: User-Agent, Host, X-Forwarded-For, X-Forwarded-Proto, X-Host, Forwarded, Via. Split by `|  |
| redirtraffic.header.host          | String  | content of header Host |
| redirtraffic.header.xforwardedfor | String  | content of header X-Forwarded-For |
| redirtraffic.header.xforwardedproto| String  | content of header X-Forwarded-Proto |
| redirtraffic.header.xhost         | String  | content of header X-Host |
| redirtraffic.header.forwarded     | String  | content of header Forwarded |
| redirtraffic.header.via           | String  | content of header Via |
| redirtraffic.httprequest          | String  | Actual HTTP request that was made |
| redirtraffic.httpstatus           | Number  | HTTP status code number |
| redirtraffic.timestamp            | String  | Time the redirecotr program handled the trafficc |
| redirprogram	   	                | String  | name of the redirector program, configured in filebeat.yml on redir |
| redirtraffic.sourceip             | IP      | IP address that initiated the traffic to the redirector, as reported by the redirector program |
| redirtraffic.sourceport           | Number  | Source Port of the initiated traffic to the redirector, as reported by the redirector program |
| redirtraffic.sourcedns            | String  | Reverse DNS lookup of thesource.ip |
| redirtraffic.sourceipcdn 	   	    | IP      | In case of CDN setup, IP address that initiated the traffic to the redirector, as reported by the redirector program |
| redirtraffic.sourceportcdn 	   	| Number  | In case of CDN setup, source Port of the initiated traffic to the redirector, as reported by the redirector program |
| redirtraffic.sourcednscdn 	   	| String  | In case of CDN setup, the reverse DNS lookup of redirtraffic.sourceipcdn |

### Tags set  by RedELK ### 
| Tag name   | Description    |
| --- | --- |
| beats_input_codec_plain_applied | Filebeat native tag |
| redirtrafficxforwardedfor | Indicator for CDN/Domain Fronted traffic, is set when a X-Forwarded-For header is found at the redirector |
| enrich_greynoise | Set when enrichment from Greynoise was performed |
| iplist_redteam_v0X | Set when the source IP adress was found to match that of /etc/redelk/iplist_redteam.conf |
| sandboxes_v0X | Set when log messages matches with config in /etc/redelkd/known_sandboxes.conf  |
| testsystems_v0X | Set when log messages matches with config in /etc/redelkd/known_testsystem.conf |
| torexitnodes_v0X | Set when source IP address matches with config in /etc/redelk/torexitnodes.conf |
| iplist_customer_v0X | Set when source IP address matches with config in /etc/redelk/iplist_customer.conf |
| iplist_unknown_v0X | Set when source IP address matches with config in /etc/redelk/iplist_unknwown.conf |
| iplist_alarmed | Set when this event was already alarmed |




## Index rtops ##

### ELK stack / Filebeat default fields ###
| Field name   | Type    | Description    |
| --- | --- | --- |
| beat.hostname	   	| String | Hostname of redirector, alias to agent.hostname (legacy field name, dropped in v7 in favor of agent.hostname) |
| beat.name	   	    | String | Host identifier as entered in the filebeat.yml cionfig file on the redir (legacy field name, dropped in v7 in favor of host.name) |
| beat.version	   	| String | Version of filebeat running on the redirector |
| host.name	   	    | String | Host identifier as entered in the filebeat.yml config file on the redir  |
| input.type	   	| String | Type of the log as identified in the filebeat.yml config file |
| log.file.path	   	| String | File path of the log file on the redirector - same as source |
| log.flags         | String | Flag set by filebeat on the redirector for the specific message (often set to multile)  |
| message	   	    | String | Full log message |
| offset	   	    | Number | Number of bytes read |
| prospector.type	| String | Legacy naming of input.type, as defined in the filebeat.yml config file |
| source            | String | File path of the log file on the redirector - same as log.file.path |


### RedELK introduced fields ###
| Field name   | Type    | Description    |
| --- | --- | --- |
| attackscenario      | String  | Name of the attackscenario this beacon belongs to, configured in filebeat.yml on teamserver |
| attack_technique    | String  | Array like list of T-numbers from MITRE ATT&CK framework. Only present on cslogtype:beacon_task log messages. |
| beacon_arch         | String  | The architecture of the beacon, x86 or x64. Only present on cslogtype:beacon_newbeacon log messages. |
| beacon_checkin      | String  | Message from the beacon while checking in. Only present on cslogtype:beacon_checkin log messages. |
| beacon_id           | String  | The Cobalt Strike ID of the beacon. |
| beacon_input        | String  | The input line as stated by the operator. Only present on cslogtype:beacon_input log messages. |
| beacon_task         | String  | The task as acknowledged by Cobalt Strike. Only present on cslogtype:beacon_task log messages. |
| beacon_output       | String  | The output as reported by Cobalt Strike. Basicly the same info as csmessage, with '[output]' stripped. |
| beaconlogfile       | String  | Clickable link to the full beacon log file. |
| cslogtype           | String  | Identifier of the type of Cobalt Strike logfile. Can be beacon_task, beacon_input, beacon_newbeacon, etc. |
| csmessage           | String  | The entire log message from Cobalt Strike |
| cstimestamp         | String  | The timestamp of the log message as reported by Cobalt Strike |
| infralogtype	   	  | String  | Identifier of the type of log that filebeat ships, configured in filebeat.yml on redir, default 'redirtraffic' |
| ioc_bytesize        | Number  | IOC size |
| ioc_hash            | String  | IOC DM5 hash |
| ioc_name            | String  | IOC name |
| ioc_path            | String  | IOC path|
| ioc_type            | String  | IOC type, currently file or service |
| screenshotfull      | URL     | Clickable link to the full screenshot |
| screenshotthumb     | Picture | Thumbnail picture of the screenshot |
| target_hostname     | String  | Hostname of the target |
| target_ipext        | IP      | External IP of the target  |
| target_ipint        | IP      | Internal IP of the target |
| target_os           | String  | OS of the target |
| target_osversion    | String  | OS version of the targert |
| target_pid          | Number  | Process ID we are running in on the target |
| target_process      | String  | Process name we are running in on the target |
| target_user         | String  | Username we are running in on the target |


### Tags set  by RedELK ### 
| Tag name   | Description    |
| --- | --- |
| beats_input_codec_plain_applied | Filebeat native tag |
| _rubyparseok | Logstash Ruby plugin native tag |
| enriched_v01 | Indicator enrich.py ran successfully  |


## Index beacondb ##

### ELK stack / Filebeat default fields ###
| Field name   | Type    | Description    |
| --- | --- | --- |
| beat.hostname  | String | Hostname of redirector, alias to agent.hostname (legacy field name, dropped in v7 in favor of agent.hostname) |
| beat.name	   	 | String | Host identifier as entered in the filebeat.yml cionfig file on the redir (legacy field name, dropped in v7 in favor of host.name) |
| beat.version	 | String | Version of filebeat running on the redirector |
| input.type	 | String | Type of the log as identified in the filebeat.yml config file |
| log.file.path	 | String | File path of the log file on the redirector |
| message	   	 | String | Full log message |
| offset	   	 | Number | Number of bytes read |
| prospector.type| String | Legacy naming of input.type, as defined in the filebeat.yml config file | 
| source            | String | File path of the log file on the redirector - same as log.file.path |

### RedELK introduced fields ###
| Field name   | Type    | Description    |
| --- | --- | --- |
| attackscenario      | String | Name of the attackscenario this beacon belongs to, configured in filebeat.yml on teamserver |
| beacon_arch         | String | The architecture of the beacon, x86 or x64. Only present on cslogtype:beacon_newbeacon log messages. |
| beacon_id           | String | The Cobalt Strike ID of the beacon. |
| beacon_linked       | String | Set to true if the beacon is linked to another beacon |
| beacon_linkmode     | String | Type of linking, e.g. SMB or TCP |
| beacon_linkparentid | String | Beacon ID of the parent beacon in case of linking |
| beaconlogfile       | String | Clickable link to the full beacon log file. |
| cstimestamp         | String | The timestamp of the log message as reported by Cobalt Strike |
| target_hostname     | String | Hostname of the target |
| target_ipext        | IP     | External IP of the target  |
| target_ipint        | IP     | Internal IP of the target |
| target_os           | String | OS of the target |
| target_osversion    | String | OS version of the targert |
| target_pid          | Number | Process ID we are running in on the target |
| target_process      | String | Process name we are running in on the target |
| target_user         | String | Username we are running in on the target |
| type                | String | Set to beacondb |