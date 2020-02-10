## Field names, types and description



## Index redirtraffic-*

# ELK stack default fields
beat.hostname	   	String      : Hostname of redirector, alias to agent.hostname (legacy field name, dropped in v7 in favor of agent.hostname)
beat.name	   	    String      : Host identifier as entered in the filebeat.yml cionfig file on the redir (legacy field name, dropped in v7 in favor of host.name)
beat.version	   	String      : Version of filebeat running on the redirector
host.name	   	    String      : Host identifier as entered in the filebeat.yml config file on the redir 
input.type	   	    String      : Type of the log as identified in the filebeat.yml config file
log.file.path	   	String      : File path of the log file on the redirector
message	   	        String      : Full log message
offset	   	        Number      : Number of bytes read
prospector.type	   	String      : Legacy naming of input.type, as defined in the filebeat.yml config file

# RedELK introduced fields
attackscenario                      String  : Name of the attackscenario this redirector traffic belongs to, configured in filebeat.yml on redir
geoip.as_org	   	                String  : AS name according to GeoIP lookup, source is redirtraffic.sourceip
geoip.asn	   	                    String  : AS number according to GeoIP lookup, source is redirtraffic.sourceip
geoip.city_name	   	                String  : City name according to GeoIP lookup, source is redirtraffic.sourceip
geoip.continent_code                String  : Continent code according to GeoIP lookup, source is redirtraffic.sourceip
geoip.country_code2                 String  : Country code according to GeoIP lookup, source is redirtraffic.sourceip
geoip.country_code3	                String  : Country code in other naming according to GeoIP lookup, source is redirtraffic.sourceip
geoip.country_name                  String  : Country name according to GeoIP lookup, source is redirtraffic.sourceip
geoip.dma_code                      Number  : DMA/Metro code according to GeoIP lookup, source is redirtraffic.sourceip
geoip.ip	   	                    IP      : IP address used for GeoIP lookup, copied from redirtraffic.sourceip
geoip.latitude	   	                Number  : Latitude position according to GeoIP lookup, source is redirtraffic.sourceip
geoip.location	   	                GeoPoint: GeoPoint type, contains lat and lon value, used for plotting on maps
geoip.longitude	   	                Number  : Longitude position according to GeoIP lookup, source is redirtraffic.sourceip
geoip.postal_code	                String  : Postal code according to GeoIP lookup, source is redirtraffic.sourceip
geoip.region_code	                String  : Region code according to GeoIP lookup, source is redirtraffic.sourceip
geoip.region_name	                String  : Region name according to GeoIP lookup, source is redirtraffic.sourceip
geoip.timezone	   	                String  : Timezone name according to GeoIP lookup, source is redirtraffic.sourceip
infralogtype	   	                String  : identifier of the type of log that filebeat ships, configured in filebeat.yml on redir, default 'redirtraffic'
syslogpid                           Number  : Process ID of the redirector program, as reported by Syslog
syslogprogram                       String  : Name of the redirector program, as reported by Syslog
redir.backendname 	                String  : Name of the destination that the traffic has sent to, typical something like decoy-http1 or c2-https as defined in the redir program's config
redir.frontendname 	                String  : Name of the frontend that redirecotr received the the traffic on, typical something like www-http or www-https as defined in the redir program's config
redir.frontendip                    IP      : IP address of the redirector where the traffic was received on
redir.frontendport                  Number  : Port on the redirector where the traffic was received on
sysloghostname 	                    String  : Hostname of the redirector, as reported by Syslog or by Apache
redirtraffic.headersall             String  : All headers as logged by the rediredctor program. These are: User-Agent, Host, X-Forwarded-For, X-Forwarded-Proto, X-Host, Forwarded, Via. Split by |
redirtraffic.header.host            String  : content of header Host
redirtraffic.header.xforwardedfor   String  : content of header X-Forwarded-For
redirtraffic.header.xforwardedproto String  : content of header X-Forwarded-Proto
redirtraffic.header.xhost           String  : content of header X-Host
redirtraffic.header.forwarded       String  : content of header Forwarded
redirtraffic.header.via             String  : content of header Via
redirtraffic.httprequest            String  : Actual HTTP request that was made
redirtraffic.httpstatus             Number  : HTTP status code number
redirtraffic.timestamp              String  : Time the redirecotr program handled the trafficc
redirprogram	   	                String  : name of the redirector program, configured in filebeat.yml on redir
redirtraffic.sourceip               IP      : IP address that initiated the traffic to the redirector, as reported by the redirector program
redirtraffic.sourceport             Number  : Source Port of the initiated traffic to the redirector, as reported by the redirector program
redirtraffic.sourcedns              String  : Reverse DNS lookup of thesource.ip
redirtraffic.sourceipcdn 	   	    IP      : In case of CDN setup, IP address that initiated the traffic to the redirector, as reported by the redirector program
redirtraffic.sourceportcdn 	   	    Number  : In case of CDN setup, source Port of the initiated traffic to the redirector, as reported by the redirector program
redirtraffic.sourcednscdn 	   	    String  : In case of CDN setup, the reverse DNS lookup of redirtraffic.sourceipcdn
