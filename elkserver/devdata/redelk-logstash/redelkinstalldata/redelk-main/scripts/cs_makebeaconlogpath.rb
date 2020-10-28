#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full TXT file of a Cobalt Strike keystrokes file
#
# Author: Outflank B.V. / Marc Smeets
#

def filter(event)
	host = event.get("[agent][name]")
	logpath = event.get("[log][file][path]")
	implant_id = event.get("[implant][id]")
	temppath = logpath.split('/cobaltstrike')
	temppath2 = temppath[1].split(/\/([^\/]*)$/)
	implantlogpath = "/c2logs/" + "#{host}" + "#{temppath[1]}"
	event.tag("_rubyparseok")
  	event.set("[implant][log_file]", implantlogpath)
	return [event]
end
