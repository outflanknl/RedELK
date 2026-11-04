#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full TXT file of a Cobalt Strike keystrokes file
#
# Author: Outflank B.V. / Marc Smeets
#

def filter(event)
	host = event.get("[agent][name]")
	logpath = event.get("[log][file][path]")
	temppath = logpath.split('/cobaltstrike/server')
	implantlogpath = "/c2logs/" + "#{host}" + "/cobaltstrike" + "#{temppath[1]}"
	event.tag("_rubyparseok")
  	event.set("[implant][log_file]", implantlogpath)
	return [event]
end
