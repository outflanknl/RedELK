#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full TXT file of a Cobalt Strike keystrokes file
#
# Author: Outflank B.V. / Marc Smeets
#

def filter(event)
	host = event.get("[agent][hostname]")
	logpath = event.get("[log][file][path]")
	implant_id = event.get("[implant][id]")
	temppath = logpath.split('/cobaltstrike')
	temppath2 = temppath[1].split(/\/([^\/]*)$/)
	keystrokespath = "/c2logs/" + "#{host}" + "#{temppath2[0]}" + "/keystrokes_" + "#{implant_id}" + ".txt"
	event.tag("_rubyparseok")
  event.set("[keystrokes][url]", keystrokespath)
	return [event]
end
