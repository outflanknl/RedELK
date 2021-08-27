#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the Cobalt Strike downloaded file
#
# Author: Outflank B.V. / Marc Smeets
#

def filter(event)
	host = event.get("[agent][name]")
	logpath = event.get("[log][file][path]")
	implant_id = event.get("[implant][id]")
  	filename = event.get("[file][name]")
	file_path = event.get("[file][directory_local]")
	file_patharray = file_path.split(/\/([^\/]*)$/)
	file_id = file_patharray[-1]
	downloadsurl = "/c2logs/" + "#{host}" + "/cobaltstrike/downloads/" + "#{file_id}" + "_" + "#{filename}"
	event.tag("_rubyparseok")
  	event.set("[file][url]", downloadsurl)
	return [event]
end
