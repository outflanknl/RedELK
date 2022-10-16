
# Field names, types and description

[Index redirtraffic](#Index-redirtraffic)

[Index rtops](#Index-rtops)

[Index credentials](#Index-credentials)

[Index implantsdb](#Index-implantsdb)

### Only relevant fields are listed here ###
The indices in RedELK have more fields than listed below. Only the most relevant fields for RedELK operations are listed below.

## Index redirtraffic
| Fieldname                     | ES type       | Kibana type   | Comment                                     |
| ----------------------------- | ------------- | ------------- | --------------------------------------------- |
| agent.hostname                | keyword       | string        | Hostname of system where filebeat is running      |
| agent.name                    | keyword       | string        | Custom name of the agent as as entered in the filebeat.yml config file       |
| greynoise.Name_list           | text          | string        | Names given by Greynoise        |
| greynoise.OS_list             | text          | string        | OS details if known by Greynoise       |
| greynoise.first_seen          | keyword       | string        | Timestamp of first recording of this IP by Greynoise        |
| greynoise.ip                  | ip            | ip            | The IP address that was used for querying Greynoise. Should be equal to source.ip       |
| greynoise.last_result.category   | keyword    | string        | Category that Greynoise has for this IP        |
| greynoise.last_result.confidence   | keyword  | string        | Confidence rating of Greynoise results, Greynoise own rating       |
| greynoise.last_result.first_seen   | keyword  | string        | Timestamp of first recording of this IP with the current result. Differs from greynoise.first_seen when the classification of the IP has changed over time       |
| greynoise.last_result.intention   | keyword   | string        | Does Greynoise think it is benign, malicious, unknown, etc       |
| greynoise.last_result.last_updated   | keyword   | string     | Last update by Greynoise       |
| greynoise.last_result.metadata.asn   | keyword   | string     | ASN info as reported by Greynoise       |
| greynoise.last_result.metadata.datacenter   | text   | string | Datacenter info as reported by Greynoise        |
| greynoise.last_result.metadata.link   | text   | string       | Link info as reported by Greynoise, modem, ethernet, IPIP, tunnel/VPN, etc       |
| greynoise.last_result.metadata.org   | text   | string        | Owner info of the IP       |
| greynoise.last_result.metadata.os   | text   | string         | OS info as reported by Greynoise        |
| greynoise.last_result.metadata.rdns   | keyword   | string    | Reverse DNS info as reported by Greynoise       |
| greynoise.last_result.metadata.rdns_parent| keyword | string  | Main domain reverse DNS info as reported by Greynoise       |
| greynoise.last_result.metadata.tor   | boolean   | boolean    | Does greynoise think it is TOR       |
| greynoise.last_result.name   | keyword        | string        | Latest name that Greynoise has for this IP       |
| greynoise.query_timestamp   | long            | number        | Timestamp when we queried Greynoise for this ino       |
| greynoise.status              | keyword       | string        | Status of Greynoise info, OK or unknown       |
| host.name                     | keyword       | string        | Array of names given to the host collecting the information; the redirector.       |
| http.headers.all              | text          | string        | All headers as captured by the redir proxy       |
| http.headers.forwarded        | keyword       | string        | Forwarded header info (not X-Forwarded-For!)       |
| http.headers.host             | keyword       | string        | Host header info       |
| http.headers.useragent        | keyword       | string        | Useragent header info       |
| http.headers.via              | keyword       | string        | Via header info       |
| http.headers.x_forwarded_for  | ip            | ip            | X-Forwarded-For header info       |
| http.headers.x_forwarded_proto| keyword       | string        | X-Forwarded-Proto header info       |
| http.headers.x_host           | keyword       | string        | X-Host header info       |
| http.request.body.content     | text          | string        | Content of the http body       |
| http.response.status_code     | long          | number        | HTTP respsonse status code}       |
| infra.attack_scenario         | keyword       | string        | Name of the attack scenario/campaign this event belongs to. Defined in filebeat config       |
| infra.log.type                | keyword       | string        | Type of log event. Defined in filebeat config        |
| log.file.path                 | keyword       | string        | File path of the logfile this event was read from       |
| message                       | text          | string        | Full message as received by logstash       |
| process.name                  | keyword       | string        | Process name as read from the log event       |
| process.pid                   | long          | number        | PID of the process as read from the log event       |
| redir.backend.name            | keyword       | string        | Name of the backend the redirector choose for routing this traffic event       |
| redir.catchall                | text          | string        | Failsafe field to catch the log line when all other logstash filters couldn't       |
| redir.frontend.ip             | ip            | ip            | IP address of the redir frontend where the traffic was received       |
| redir.frontend.name           | keyword       | string        | Name of the frontend oo the redir where the traffic was received       |
| redir.frontend.port           | long          | number        | Port the frontend was listening on       |
| redir.program                 | keyword       | string        | Name of the redir program. This is set in the filebeat config       |
| redir.timestamp               | text          | string        | Timestamp of the actual log event in the redir log. This is copied over to @timestamp       |
| source.as.number              | long          | number        | AS number of source.ip. Generated from Elastic AS plugin.       |
| source.as.organization.name   | text          | string        | Org name of AS of source.ip. Generated from Elastic AS plugin.       |
| source.domain                 | keyword       | string        | Reverse DNS value of source.ip        |
| source.geo.as.organization.name| keyword      | string        | Org name of AS of source.ip. Generated from Elastic AS plugin.       |
| source.geo.as.organization.number   | long    | number        | ASnr of source.ip. Generated from Elastic AS plugin.       |
| source.geo.city_name          | keyword       | string        | City name of source.ip based on GeoIP Elastic plugin.        |
| source.geo.continent_name     | keyword       | string        | Continent name of source.ip based on GeoIP Elastic plugin.       |
| source.geo.country_iso_code   | keyword       | string        | ISO code country of source.ip based on GeoIP Elastic plugin.       |
| source.geo.country_name       | keyword       | string        | Country name of source.ip based on GeoIP Elastic plugin.       |
| source.geo.location           | geo_point     | geo_point     | Geo coordinates of source.ip based on GeoIP Elastic plugin.       |
| source.geo.name               | keyword       | string        | Short name of source.ip based on GeoIP Elastic plugin.        |
| source.geo.region_iso_code    | keyword       | string        | Region ISO code of source.ip based on GeoIP Elastic plugin.       |
| source.geo.region_name        | keyword       | string        | Rregion name of source.ip based on GeoIP Elastic plugin.       |
| source.host_info.build        | keyword       | string        | Source host build info based on useragent plugin of Elastic       |
| source.host_info.device       | keyword       | string        | Source host device info based on useragent plugin of Elastic       |
| source.host_info.major        | keyword       | string        | Source host major release info based on useragent plugin of Elastic       |
| source.host_info.minor        | keyword       | string        | Source host minor release info based on useragent plugin of Elastic       |
| source.host_info.name         | text          | string        | Source host browser name info based on useragent plugin of Elastic       |
| source.host_info.os           | text          | string        | Source host OS info based on useragent plugin of Elastic       |
| source.host_info.os_name      | text          | string        | Source host OS name info based on useragent plugin of Elastic       |
| source.host_info.patch        | keyword       | string        | Source host OS patch level info based on useragent plugin of Elastic       |
| source.ip                     | ip            | ip            | IP address of the source initiating the connection to the redir. If there was a X-Forwarded-For header, the value of that header is placed in source.ip and the source.ip is moved to source.cdn.ip       |
| source.port                   | long          | number        | Source port number of the source initiating the connection to the redir.        |
| source.cdn.domain             | keyword       | string        | Reverse DNS of source.cdn.ip       |
| source.cdn.ip                 | ip            | ip            | IP address of the intermediate proxy/CDN that initiated the connection to the redir. If there was a X-Forwarded-For header, the value of that header is placed in source.ip and the source.ip is moved to source.cdn.ip       |
| source.cdn.port               | long          | number        | Source port number of the CDN source initiating the connection to the redir. If this is filled, the source.port field is not filled as it cannot be determined       |

##### Tags in redirtraffic index
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
| iplist_alarmed                  | Set when this event was already alarmed
| redirlongmessagecatchall        | Set when the catchall logstash grok rule was matched (redir.catchall is filled)  |



## Index rtops
| Fieldname                     | ES type       | Kibana type   | Comment                                       |
| ----------------------------- | ------------- | ------------- | --------------------------------------------- |
| agent.hostname                | keyword       | string        | Hostname of system where filebeat is running      |
| agent.name                    | keyword       | string        | Custom name of the agent as as entered in the filebeat.yml config file       |
| c2.listener.bind_port         | long          | number        | C2 server listener info on port number for the bind listener       |
| c2.listener.domains           | keyword&string| string        | C2 server listener info on valid domains      |
| c2.listener.host              | keyword       | string        | C2 server listener info on host       |
| c2.listener.name              | keyword       | string        | C2 server listener name       |
| c2.listener.port              | long          | number        | C2 server listener info on port number       |
| c2.listener.profile           | keyword       | string        | C2 server listener info on the profile       |
| c2.listener.proxy             | keyword       | string        | C2 server listener info on proxy       |
| c2.listener.type              | keyword       | string        | C2 server listener info on type       |
| c2.log.type                   | keyword       | string        | Defines the type of C2 log, e.g. implant_output, implant_checkin, etc       |
| c2.message                    | keyword       | string        | The full message from the C2 server log       |
| c2.program                    | keyword       | string        | Shows the exact C2 program       |
| c2.timestamp                  | text          | string        | The exact timestamp of the event as reported by the C2 server. This is copied over to @timestamp       |
| creds.credential              | keyword       | string        | The actual credential       |
| creds.host                    | keyword       | string        | Host where the credential is for       |
| creds.realm                   | keyword       | string        | Realm of the credential       |
| creds.source                  | keyword       | string        | Host where the credential was gathered from       |
| creds.username                | keyword       | string        | usernaem of the credential       |
| event.action                  | keyword       | string        | ECS event action (matches 'c2.log.type')        |
| event.category                | keyword       | string        | ECS event category. (default static field: 'host')       |
| event.dataset                 | keyword       | string        | ECS event dataset that is source of the event. (default static field: 'c2log')       |
| event.kind                    | keyword       | string        | ECS event kind. (default static field: 'event')           |
| event.module                  | keyword       | string        | ECS event module that is source of the event. (default static field: 'redelk')       |
| event.type                    | keyword       | string        | ECS event action (matches 'c2.log.type')       |
| file.directory                | keyword       | string        | Directory of the file at the target       |
| file.directory_local          | keyword       | string        | Directory of the file at the C2 server       |
| file.hash.md5                 | keyword       | string        | MD5 has of the file, in case of IOC       |
| file.hash.sha1                | keyword       | string        | Sha1 has of the file, in case of IOC       |
| file.hash.sha256              | keyword       | string        | Sha256 has of the file, in case of IOC       |
| file.hash.sha512              | keyword       | string        | Sha512 has of the file, in case of IOC       |
| file.name                     | keyword       | string        | Name of the file, in case of downloaded or IOC       |
| file.path                     | text          | string        | Path of the file, in case of downloaded or IOC       |
| file.path_local               | text          | string        | Local path of the file       |
| file.size                     | long          | number        | Size of the file       |
| host.domain_ext               | keyword       | string        | Reverse DNS lookup result of host.ip_ext       |
| host.ip                       | ip            | ip            | Collection of IP addresses of multiple sources       |
| host.ip_ext                   | ip            | ip            | External IP address of the target where the implant is running       |
| host.ip_int                   | ip            | ip            | Inernal IP address of the target where the implant is running       |
| host.name                     | keyword       | string        | Name of the host       |
| host.os.family                | keyword       | string        | Same as host.name.os       |
| host.os.full                  | keyword&string| string        | Same as host.os.family + host.os.version + host.os.kernel       |
| host.os.kernel                | keyword       | string        | Kernel info on the host       |
| host.os.name                  | keyword       | string        | OS name of the host       |
| host.os.platform              | keyword       | string        | Same as host.name.os       |
| host.os.version               | keyword       | string        | OS version        |
| implant.arch                  | keyword       | string        | Architecture of the host where the implant is running       |
| implant.checkin               | text          | string        | Checkin message from the implant       |
| implant.child_id              | keyword       | string        | In case of linked implants, the implant ID of the child       |
| implant.id                    | keyword       | string        | The ID of the implant       |
| implant.input                 | text          | string        | Input message for the implant       |
| implant.kill_date             | keyword       | string        | Kill date of the implant - not recorded by every C2 framework       |
| implant.link_mode             | keyword       | string        | In case of linked implants, the mode of linking       |
| implant.linked                | boolean       | boolean       | Boolean indicator to see if this implant is linked       |
| implant.log_file              | keyword       | string        | Name of the C2 implant's log file       |
| implant.operator              | text          | string        | Name of the operator taht issued the C2 command       |
| implant.output                | text          | string        | Output received from the implant       |
| implant.parent_id             | keyword       | string        | In case of linked implants, the implant ID of the parent       |
| implant.task                  | keyword       | string        | The task sent to the implant       |
| implant.task_id               | keyword       | string        | Unique ID of the task sent to the implant       |
| implant.parameters            | keyword       | string        | Parameters sent to the implant      |
| implant.url                   | keyword       | string        | URL as reported by the implant.      |
| infra.attack_scenario         | keyword       | string        | Name of the attack scenario/campaign this event belongs to. Defined in filebeat config       |
| infra.log.type                | keyword       | string        | Type of log event. Defined in filebeat config        |
| input.type                    | keyword       | string        | Way how the log event was ingeste, e.g. log, manual.        |
| ioc.type                      | keyword       | string        | Type of IOC       |
| keystrokes.url                | keyword       | string        | Full clickable URL to the keystrokes file on the RedELK server       |
| log.file.path                 | keyword       | string        | File path of the logfile this event was read from       |
| message                       | text          | string        | Full message as received by logstash       |
| process.name                  | keyword       | string        | Process name the implant is running in on the target      |
| process.pid                   | long          | number        | Process ID the implant is running in on the target       |
| screenshot.full               | keyword       | string        | Clickable link to the full screenshot      |
| screenshot.thumb              | keyword       | string        | Thumbnail picture of the screenshot       |
| threat.technique.id           | keyword       | string        | Mitre ATT&CK Technique ID of the implant's action       |
| type                          | keyword       | string        | Used in rare cases, for example when a log event is duplicated for the implantsdb       |
| user.name                     | keyword       | string        | Name of the user the implant is running as       |

##### Tags set by RedELK for for index rtops

| Tag name                        | Description                          |
| ------------------------------- | ------------------------------------ |
| beats_input_codec_plain_applied | Filebeat native tag                  |
| \_rubyparseok                   | Logstash Ruby plugin native tag      |
| enriched_v01                    | Indicator enrich.py ran successfully |



## Index implantsdb
|   Fieldname                   |   ES type    |   Kibana type  |   Comment                                     |
| ----------------------------- | ------------ | -------------- | --------------------------------------------- |
| agent.hostname                | keyword       | string        | Hostname of system where filebeat is running      |
| agent.name                    | keyword       | string        | Custom name of the agent as as entered in the filebeat.yml config file       |
| c2.program                    | keyword       | string        | Shows the exact C2 program       |
| c2.timestamp                  | text          | string        | The exact timestamp of the event as reported by the C2 server. This is copied over to @timestamp       |
| host.ip                       | ip            | ip            | Collection of IP addresses of multiple sources       |
| host.ip_ext                   | keyword       | ip            | External IP address of the target where the implant is running       |
| host.ip_int                   | keyword       | ip            | Inernal IP address of the target where the implant is running       |
| host.name                     | keyword       | string        | Name of the host       |
| host.os.family                | keyword       | string        | Same as host.name.os       |
| host.os.full                  | keyword       | string        | Same as host.os.family + host.os.version + host.os.kernel       |
| host.os.kernel                | keyword       | string        | Kernel info on the host       |
| host.os.name                  | keyword       | string        | OS name of the host       |
| host.os.platform              | keyword       | string        | Same as host.name.os       |
| host.os.version               | keyword       | string        | OS version        |
| implant.id                    | keyword       | string        | The ID of the implant       |
| implant.arch                  | keyword       | string        | Architecture of the host where the implant is running       |
| implant.link_mode             | keyword       | string        | In case of linked implants, the mode of linking       |
| implant.linked                | boolean       | boolean       | Boolean indicator to see if this implant is linked       |
| implant.log_file              | keyword       | string        | Name of the C2 implant's log file       |
| implant.parent_id             | keyword       | string        | In case of linked implants, the implant ID of the parent       |
| infra.attack_scenario         | keyword       | string        | Name of the attack scenario/campaign this event belongs to. Defined in filebeat config       |
| infra.log.type                | keyword       | string        | Type of log event. Defined in filebeat config        |
| log.file.path                 | keyword       | string        | File path of the logfile this event was read from       |
| message                       | text          | string        | Full message as received by logstash       |
| process.name                  | keyword       | string        | Process name the implant is running in on the target      |
| process.pid                   | long          | number        | Process ID the implant is running in on the target       |
| user.name                     | keyword       | string        | Name of the user the implant is running as       |

##### Tags set by RedELK for for index rtops

| Tag name                        | Description                          |
| ------------------------------- | ------------------------------------ |
| beats_input_codec_plain_applied | Filebeat native tag                  |
| \_rubyparseok                   | Logstash Ruby plugin native tag      |
