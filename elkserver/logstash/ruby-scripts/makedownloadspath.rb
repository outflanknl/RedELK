#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the downloaded file
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
        filename = event.get("filename")
	file_path = event.get("pathlocal")
	file_patharray = file_path.split(/\/([^\/]*)$/)
	file_id = file_patharray[-1]
	downloadsurl = "/cslogs/" + "#{host}" + "/downloads/" + "#{file_id}" + "_" + "#{filename}" 
	event.tag("_rubyparseok")
    	event.set("downloadsurl", downloadsurl)
	return [event]
end
