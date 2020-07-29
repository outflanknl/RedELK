#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the Cobalt Strike downloaded file
#
# Author: Outflank B.V. / Marc Smeets 
#

def filter(event)
	host = event.get("[agent][hostname]")
	logpath = event.get("[log][file][path]")
	implant_id = event.get("implant_id")
    filename = event.get("filename")
	file_path = event.get("pathlocal")
	file_patharray = file_path.split(/\/([^\/]*)$/)
	file_id = file_patharray[-1]
	downloadsurl = "/c2logs/" + "#{host}" + "/downloads/" + "#{file_id}" + "_" + "#{filename}" 
	event.tag("_rubyparseok")
    event.set("downloadsurl", downloadsurl)
	return [event]
end
