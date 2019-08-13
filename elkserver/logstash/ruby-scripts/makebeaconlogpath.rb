#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full TXT file of a Cobalt Strike keystrokes file
#
# Author: Outflank B.V. / Marc Smeets
#

def register(params)
#        @timestamp = params["timestamp"]
#        @source = param["source"]
#	@beacon_id = param["beacon_id"]
end

def filter(event)
	host = event.get("[beat][name]")
	logpath = event.get("source")
	beacon_id = event.get("beacon_id")
	temppath = logpath.split('/cobaltstrike')
	temppath2 = temppath[1].split(/\/([^\/]*)$/)
	beaconlogpath = "/cslogs/" + "#{host}" + "#{temppath[1]}"
	event.tag("_rubyparseok")
    	event.set("beaconlogfile", beaconlogpath)
	return [event]
end
