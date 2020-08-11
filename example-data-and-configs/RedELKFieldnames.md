# Field names, types and description

## Index redirtraffic-\*

### ELK stack / Filebeat default fields

| Field name      | Type   | New field name | New type    | Description                                                                                                                      |
| --------------- | ------ | -------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------- |
| beat.hostname   | String | agent.hostname | keyword     | Hostname of redirector, alias to agent.hostname (legacy field name, dropped in v7 in favor of agent.hostname)                    |
| beat.name       | String | agent.name     | keyword     | Host identifier as entered in the filebeat.yml config file on the redir (legacy field name, dropped in v7 in favor of host.name) |
| beat.version    | String | agent.version  | keyword     | Version of filebeat running on the redirector                                                                                    |
| host.name       | String | -              | -           | To be removed: Host identifier as entered in the filebeat.yml config file on the redir                                           |
| input.type      | String | input.type     | keyword     | Type of the log as identified in the filebeat.yml config file                                                                    |
| log.file.path   | String | log.file.path  | keyword     | File path of the log file on the redirector                                                                                      |
| message         | String | messages       | text        | Full log message                                                                                                                 |
| offset          | Number | log.offset     | number.long | Number of bytes read                                                                                                             |
| prospector.type | String | -              | -           | To be removed: legacy naming of input.type, as defined in the filebeat.yml config file                                           |

### RedELK introduced fields

| Field name                          | Type     | New field name                 | New type | Description                                                                                                                                             |
| ----------------------------------- | -------- | ------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------|
| attackscenario                      | String   | infra.attack_scenario          |          | Name of the attackscenario this redirector traffic belongs to, configured in filebeat.yml on redir                                                      |
| geoip.as_org                        | String   | source.as.organization.name    | keyword  | AS name according to GeoIP lookup, source is redirtraffic.sourceip                                                                                      |
| geoip.asn                           | String   | source.as.number               | keyword  | AS number according to GeoIP lookup, source is redirtraffic.sourceip                                                                                    |
| geoip.city_name                     | String   | source.geo.city_name           |          | City name according to GeoIP lookup, source is redirtraffic.sourceip                                                                                    |
| geoip.continent_code                | String   | source.geo.continent_name      |          | Continent code according to GeoIP lookup, source is redirtraffic.sourceip                                                                               |
| geoip.country_code2                 | String   | source.geo.country_iso_code    |          | Country code according to GeoIP lookup, source is redirtraffic.sourceip                                                                                 |
| geoip.country_code3                 | String   | -                              |          | Country code in other naming according to GeoIP lookup, source is redirtraffic.sourceip                                                                 |
| geoip.country_name                  | String   | source.geo.country_name        |          | Country name according to GeoIP lookup, source is redirtraffic.sourceip                                                                                 |
| geoip.dma_code                      | Number   | -                              |          | DMA/Metro code according to GeoIP lookup, source is redirtraffic.sourceip                                                                               |
| geoip.ip                            | IP       | -                              |          | IP address used for GeoIP lookup, copied from redirtraffic.sourceip                                                                                     |
| geoip.latitude                      | Number   | -                              |          | Latitude position according to GeoIP lookup, source is redirtraffic.sourceip                                                                            |
| geoip.location                      | GeoPoint | source.geo.location            |          | GeoPoint type, contains lat and lon value, used for plotting on maps                                                                                    |
| geoip.longitude                     | Number   | -                              |          | Longitude position according to GeoIP lookup, source is redirtraffic.sourceip                                                                           |
| geoip.postal_code                   | String   | -                              |          | Postal code according to GeoIP lookup, source is redirtraffic.sourceip                                                                                  |
| geoip.region_code                   | String   | source.geo.region_iso_code     |          | Region code according to GeoIP lookup, source is redirtraffic.sourceip                                                                                  |
| geoip.region_name                   | String   | source.geo.region_name         |          | Region name according to GeoIP lookup, source is redirtraffic.sourceip                                                                                  |
| geoip.timezone                      | String   | -                              |          | Timezone name according to GeoIP lookup, source is redirtraffic.sourceip                                                                                |
| greynoise.\*                        | Varying  | greynoise.\*                   |          | Fields and data as set by Greynoise                                                                                                                     |
| infralogtype                        | String   | infra.log.type                 |          | identifier of the type of log that filebeat ships, configured in filebeat.yml on redir, default 'redirtraffic'                                          |
| syslogpid                           | Number   | process.pid                    |          | Process ID of the redirector program, as reported by Syslog                                                                                             |
| syslogprogram                       | String   | process.name                   |          | Name of the redirector program, as reported by Syslog                                                                                                   |
| redir.backendname                   | String   | redir.backend.name             |          | Name of the destination that the traffic has sent to, typical something like decoy-http1 or c2-https as defined in the redir program's config           |
| redir.frontendname                  | String   | redir.frontend.name            |          | Name of the frontend that redirecotr received the the traffic on, typical something like www-http or www-https as defined in the redir program's config |
| redir.frontendip                    | IP       | redir.frontend.ip              |          | IP address of the redirector where the traffic was received on                                                                                          |
| redir.frontendport                  | Number   | redir.frontend.port            |          | Port on the redirector where the traffic was received on                                                                                                |
| sysloghostname                      | String   | host.name                      |          | Hostname of the redirector, as reported by Syslog or by Apache                                                                                          |
| redirtraffic.headersall             | String   | http.headers.all               |          | All headers as logged by the rediredctor program. These are: User-Agent, Host, X-Forwarded-For, X-Forwarded-Proto, X-Host, Forwarded, Via. Split by \`  |
| redirtraffic.header.host            | String   | http.headers.host              |          | content of header Host                                                                                                                                  |
| redirtraffic.header.xforwardedfor   | String   | http.headers.x_forwarded_for   |          | content of header X-Forwarded-For                                                                                                                       |
| redirtraffic.header.xforwardedproto | String   | http.headers.x_forwarded_proto |          | content of header X-Forwarded-Proto                                                                                                                     |
| redirtraffic.header.xhost           | String   | http.headers.x_host            |          | content of header X-Host                                                                                                                                |
| redirtraffic.header.forwarded       | String   | http.headers.forwarded         |          | content of header Forwarded                                                                                                                             |
| redirtraffic.header.via             | String   | http.headers.via               |          | content of header Via                                                                                                                                   |
| redirtraffic.httprequest            | String   | http.request.body.content      |          | Actual HTTP request that was made                                                                                                                       |
| redirtraffic.httpstatus             | Number   | http.response.status_code      |          | HTTP status code number                                                                                                                                 |
| redirtraffic.timestamp              | String   | redir.timestamp                |          | Time the redirecotr program handled the trafficc                                                                                                        |
| redirprogram                        | String   | redir.program                  |          | name of the redirector program, configured in filebeat.yml on redir                                                                                     |
| redirtraffic.sourceip               | IP       | source.ip                      |          | IP address that initiated the traffic to the redirector, as reported by the redirector program                                                          |
| redirtraffic.sourceport             | Number   | source.port                    |          | Source Port of the initiated traffic to the redirector, as reported by the redirector program                                                           |
| redirtraffic.sourcedns              | String   | source.domain                  |          | Reverse DNS lookup of thesource.ip                                                                                                                      |
| redirtraffic.sourceipcdn            | IP       | source.nat.ip                  |          | In case of CDN setup, IP address that initiated the traffic to the redirector, as reported by the redirector program                                    |
| redirtraffic.sourceportcdn          | Number   | source.nat.port                |          | In case of CDN setup, source Port of the initiated traffic to the redirector, as reported by the redirector program                                     |
| redirtraffic.sourcednscdn           | String   | source.nat.domain              |          | In case of CDN setup, the reverse DNS lookup of redirtraffic.sourceipcdn                                                                                |

### Tags set  by RedELK

| Tag name                        | Description                                                                                               |
| ------------------------------- | --------------------------------------------------------------------------------------------------------- |
| beats_input_codec_plain_applied | Filebeat native tag                                                                                       |
| redirtrafficxforwardedfor       | Indicator for CDN/Domain Fronted traffic, is set when a X-Forwarded-For header is found at the redirector |
| enrich_greynoise                | Set when enrichment from Greynoise was performed                                                          |
| iplist_redteam_v0X              | Set when the source IP adress was found to match that of /etc/redelk/iplist_redteam.conf                  |
| sandboxes_v0X                   | Set when log messages matches with config in /etc/redelkd/known_sandboxes.conf                            |
| testsystems_v0X                 | Set when log messages matches with config in /etc/redelkd/known_testsystem.conf                           |
| torexitnodes_v0X                | Set when source IP address matches with config in /etc/redelk/torexitnodes.conf                           |
| iplist_customer_v0X             | Set when source IP address matches with config in /etc/redelk/iplist_customer.conf                        |
| iplist_unknown_v0X              | Set when source IP address matches with config in /etc/redelk/iplist_unknwown.conf                        |
| iplist_alarmed                  | Set when this event was already alarmed                                                                   |

## Index rtops

### ELK stack / Filebeat default fields

| Field name      | Type   | New field name | New type    | Description                                                                                                                       |
| --------------- | ------ | -------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------- |
| beat.hostname   | String | agent.hostname |             | Hostname of redirector, alias to agent.hostname (legacy field name, dropped in v7 in favor of agent.hostname)                     |
| beat.name       | String | agent.name     |             | Host identifier as entered in the filebeat.yml cionfig file on the redir (legacy field name, dropped in v7 in favor of host.name) |
| beat.version    | String | agent.version  |             | Version of filebeat running on the redirector                                                                                     |
| host.name       | String | -              | -           | To be removed (not the purpose of this field): Host identifier as entered in the filebeat.yml config file on the redir            |
| input.type      | String | input.type     | keyword     | Type of the log as identified in the filebeat.yml config file                                                                     |
| log.file.path   | String | log.file.pat   | keyword     | File path of the log file on the redirector - same as source                                                                      |
| log.flags       | String | log.flags      | keyword     | Flag set by filebeat on the redirector for the specific message (often set to multile)                                            |
| message         | String | message        | text        | Full log message                                                                                                                  |
| offset          | Number | log.offset     | number.long | Number of bytes read                                                                                                              |
| prospector.type | String | -              | -           | To be removed (obsolete): Legacy naming of input.type, as defined in the filebeat.yml config file                                 |
| source          | String | -              | -           | To be removed (obsolete): File path of the log file on the redirector - same as log.file.path                                     |
| -               | -      | event.kind     | keyword     | ECS event kind. (default static field: 'event')                                                                                   |
| -               | -      | event.category | keyword     | ECS event category. (default static field: 'host')                                                                                |
| -               | -      | event.module   | keyword     | ECS event module that is source of the event. (default static field: 'redelk')                                                    |
| -               | -      | event.dataset  | keyword     | ECS event dataset that is source of the event. (default static field: 'c2log')                                                    |
| -               | -      | event.action   | keyword     | ECS event action (matches 'cs.logtype')                                                                                           |
| -               | -      | event.type     | keyword     | ECS event action (matches 'cs.logtype')                                                                                           |

### RedELK introduced fields

| Field name                           | Type    | New field name        | New type      | Description                                                                                                                                                         |     |
| ------------------------------------ | ------- | --------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| attackscenario                       | String  | infra.attack_scenario | keyword       | Name of the attackscenario this implant belongs to, configured in filebeat.yml on teamserver                                                                        |     |
| attack_technique                     | String  | threat.technique.id   | keyword       | Array like list of T-numbers from MITRE ATT&CK framework. Not present in every C2 framework (Cobalt Strike picks this up from c2logtype:implant_task log messages). |     |
| implant_arch (was beacon_arch)       | String  | implant.arch          | keyword       | The architecture of the implant, x86 or x64.                                                                                                                        |     |
| implant_checkin (was beacon_checkin) | String  | implant.checkin       | text          | Message from the implant while checking in.                                                                                                                         |     |
| implant_id (was beacon_id)           | String  | implant.id            | keyword       | The ID of the implant.                                                                                                                                              |     |
| implant_input (was beacon_input)     | String  | implant.input         | text          | The input line as stated by the operator.                                                                                                                           |     |
| implant_task (was beacon_task)       | String  | implant.task          | text          | The task as acknowledged by Cobalt Strike.                                                                                                                          |     |
| implant_output (was beacon_output)   | String  | implant.output        | text          | The output as reported by the implant.                                                                                                                              |     |
| implantlogfile (was beaconlogfile)   | String  | implant.logfile       | text          | Clickable link to the full log file of the implant. Not present in every C2 framework.                                                                              |     |
| c2logtype (was cslogtype)            | String  | c2.log.type           | keyword       | Identifier of the type of implant logfile. Can be implant_task, implant_input, implant_newimplant, keystrokes, etc.                                                 |     |
| c2message (was csmessage)            | String  | c2.message            | text          | The entire log message from the C2 framework for that implant.                                                                                                      |     |
| c2timestamp (was cstimestamp)        | String  | c2.timestamp          | timestamp     | The timestamp of the log message as reported by the implant.                                                                                                        |     |
| infralogtype                         | String  | infra.log.type        | keyword       | Identifier of the type of log that filebeat ships, configured in filebeat.yml on c2server, default 'rtops'                                                          |     |
| ioc_bytesize                         | Number  | file.size             | number.log    | IOC size (bytes)                                                                                                                                                    |     |
| ioc_hash                             | String  | file.hash.md5         |               | IOC DM5 hash                                                                                                                                                        |     |
| ioc_name                             | String  | file.name             | keyword       | IOC file name                                                                                                                                                       |     |
| ioc_path                             | String  | file.directory        | keyword       | IOC path (without file name)                                                                                                                                        |     |
| -                                    | -       | file.path             | keyword       | IOC path (with file name)                                                                                                                                           |     |
| -                                    | -       | service.name          | keyword       | IOC service name                                                                                                                                                    |     |
| ioc_type                             | String  | ioc.type              | keyword       | IOC type, currently file or service. Additional information can be added to file.\* fields                                                                          |     |
| -                                    | -       | file.type             | keyword       | IOC static field, should be 'file'                                                                                                                                  |     |
| -                                    | -       | service.type          | keyword       | IOC static field, should be 'windows' if 'ioc.type' is 'service'                                                                                                    |     |
| screenshotfull                       | URL     | screenshot.url        | keyword (url) | Clickable link to the full screenshot                                                                                                                               |     |
| screenshotthumb                      | Picture | screenshot.thumb      | keyword (url) | Thumbnail picture of the screenshot                                                                                                                                 |     |
| target_hostname                      | String  | host.name             | keyword       | Hostname of the target                                                                                                                                              |     |
| target_ipext                         | IP      | host.ip               | IP            | External IP of the target (array with internal IP)                                                                                                                  |     |
| target_ipint                         | IP      | host.ip               | IP            | Internal IP of the target (array with external IP)                                                                                                                  |     |
| target_os                            | String  | host.os.name          | keyword       | OS name of the target                                                                                                                                               |     |
| -                                    | -       | host.os.platform      | keyword       | OS platform family of the target                                                                                                                                    |     |
| -                                    | -       | host.os.fullname      | keyword       | OS name of the target (including version and kernel/build info)                                                                                                     |     |
| target_osbuild                       | String  | host.os.kernel        | keyword       | OS kernel info of the target                                                                                                                                        |     |
| target_osversion                     | String  | host.os.version       | keyword       | OS version of the targer                                                                                                                                            |     |
| target_pid                           | Number  | process.pid           | number.long   | Process ID we are running in on the target                                                                                                                          |     |
| target_process                       | String  | process.name          | keyword       | Process name we are running in on the target                                                                                                                        |     |
| target_user                          | String  | user.name             | keyword       | Username we are running in on the target                                                                                                                            |     |
| implant_sleep                        | String  | implant.sleep         | keyword       | Sleep value as reported by the implant. Not present in every C2 framework                                                                                           |     |
| implant_url                          | String  | implant.url           | keyword       | URL as reported by the implant. Not present in every C2 framework                                                                                                   |     |
| beacon_linkparentid                  | String  | implant.parent_id     | keyword       | Beacon linked parent ID                                                                                                                                             |     |
| beacon_linked                        | Boolean | implant.linked        | boolean       | Is beacon linked?                                                                                                                                                   |     |
| beacon_linkmode                      | String  | implant.link_mode     | keyword       | Beacon linked mode                                                                                                                                                  |     |
| pathlocal                            | String  | file.path_local       | keyword       | Local download path of the file                                                                                                                                     |     |
| pathremote                           | String  | file.path             | keyword       | Remote path of the download (on target)                                                                                                                             |     |
| -                                    | -       | file.directory_local  | keyword       | Local download directory (without file name)                                                                                                                        |     |
| c2program                            | String  | c2.program            | keyword       | C2 program used (e.g. cobaltstrike)                                                                                                                                 |     |
| downloadsurl                         | String  | file.url              | keyword       | RedELK URL to download the file                                                                                                                                     |     |
| keystrokesfull                       | String  | keystrokes.url        | keyword       | RedELK URL to download the full keystorkes output                                                                                                                   |     |
| -                                    | -       | creds.host            | keyword       | Host where the credentials have been harvested                                                                                                                      |     |
| -                                    | -       | creds.credential      | keyword       | Credential (password, hash, ...)                                                                                                                                    |     |
| -                                    | -       | creds.username        | keyword       | User name                                                                                                                                                           |     |
| -                                    | -       | creds.source          | keyword       | How the credentials have been harvested (e.g. mimikatz, manual, ...)                                                                                                |     |
| -                                    | -       | creds.realm           | keyword       | Where the credentials are valid (e.g. AD Domain, host, ...)                                                                                                         |     |

### Tags set  by RedELK

| Tag name                        | Description                          |
| ------------------------------- | ------------------------------------ |
| beats_input_codec_plain_applied | Filebeat native tag                  |
| \_rubyparseok                   | Logstash Ruby plugin native tag      |
| enriched_v01                    | Indicator enrich.py ran successfully |

## Index implantsdb

Was called beacondb in the past

### ELK stack / Filebeat default fields

| Field name      | Type   | New field name | New type    | Description                                                                                                                       |
| --------------- | ------ | -------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------- |
| beat.hostname   | String | agent.hostname |             | Hostname of redirector, alias to agent.hostname (legacy field name, dropped in v7 in favor of agent.hostname)                     |
| beat.name       | String | agent.name     |             | Host identifier as entered in the filebeat.yml cionfig file on the redir (legacy field name, dropped in v7 in favor of host.name) |
| beat.version    | String | agent.version  |             | Version of filebeat running on the redirector                                                                                     |
| host.name       | String | -              | -           | To be removed (not the purpose of this field): Host identifier as entered in the filebeat.yml config file on the redir            |
| input.type      | String | input.type     | keyword     | Type of the log as identified in the filebeat.yml config file                                                                     |
| log.file.path   | String | log.file.pat   | keyword     | File path of the log file on the redirector - same as source                                                                      |
| log.flags       | String | log.flags      | keyword     | Flag set by filebeat on the redirector for the specific message (often set to multile)                                            |
| message         | String | message        | text        | Full log message                                                                                                                  |
| offset          | Number | log.offset     | number.long | Number of bytes read                                                                                                              |
| prospector.type | String | -              | -           | To be removed (obsolete): Legacy naming of input.type, as defined in the filebeat.yml config file                                 |
| source          | String | -              | -           | To be removed (obsolete): File path of the log file on the redirector - same as log.file.path                                     |

### RedELK introduced fields

| Field name                                     | Type   | New field name        | New type    | Description                                                                                  |
| ---------------------------------------------- | ------ | --------------------- | ----------- | -------------------------------------------------------------------------------------------- |
| attackscenario                                 | String | infra.attack_scenario | keyword     | Name of the attackscenario this implant belongs to, configured in filebeat.yml on teamserver |
| implant_arch (was beacon_arch)                 | String | implant.arch          | keyword     | The architecture of the implant, x86 or x64.                                                 |
| implant_checkin (was beacon_checkin)           | String | implant.checkin       | text        | Message from the implant while checking in.                                                  |
| implant_id (was beacon_id)                     | String | implant.id            | keyword     | The ID of the implant.                                                                       |
| implant_input (was beacon_input)               | String | implant.input         | text        | The input line as stated by the operator.                                                    |
| implant_task (was beacon_task)                 | String | implant.task          | text        | The task as acknowledged by Cobalt Strike.                                                   |
| implant_output (was beacon_output)             | String | implant.output        | text        | The output as reported by the implant.                                                       |
| implantlogfile (was beaconlogfile)             | String | implant.logfile       | text        | Clickable link to the full log file of the implant. Not present in every C2 framework.       |
| c2message (was csmessage)                      | String | c2.message            | text        | The entire log message from the C2 framework for that implant.                               |
| c2timestamp (was cstimestamp)                  | String | c2.timestamp          | timestamp   | The timestamp of the log message as reported by the implant.                                 |
| target_hostname                                | String | host.name             | keyword     | Hostname of the target                                                                       |
| target_ipext                                   | IP     | host.ip               | IP          | External IP of the target (array with internal IP)                                           |
| target_ipint                                   | IP     | host.ip               | IP          | Internal IP of the target (array with external IP)                                           |
| target_os                                      | String | host.os.name          | keyword     | OS name of the target                                                                        |
| -                                              | -      | host.os.platform      | keyword     | OS platform family of the target                                                             |
| -                                              | -      | host.os.fullname      | keyword     | OS name of the target (including version and kernel/build info)                              |
| target_osbuild                                 | String | host.os.kernel        | keyword     | OS kernel info of the target                                                                 |
| target_osversion                               | String | host.os.version       | keyword     | OS version of the targer                                                                     |
| target_pid                                     | Number | process.pid           | number.long | Process ID we are running in on the target                                                   |
| target_process                                 | String | process.name          | keyword     | Process name we are running in on the target                                                 |
| target_user                                    | String | user.name             | keyword     | Username we are running in on the target                                                     |
| -                                              | String | implant.sleep         | keyword     | Sleep value as reported by the implant. Not present in every C2 framework                    |
| -                                              | String | implant.url           | keyword     | URL as reported by the implant. Not present in every C2 framework                            |
| implant_linked (was beacon_linked)             | String | implant.linked        | keyword     | Set to true if the implant is linked to another implant                                      |
| implant_linkmode (was beacon_linkmode)         | String | implant.linkmode      | keyword     | Type of linking, e.g. SMB or TCP                                                             |
| implant_linkparentid (was beacon_linkparentid) | String | implant.parent.id     | keyword     | ID of the parent implant in case of linking                                                  |
