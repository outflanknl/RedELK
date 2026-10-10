#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full TXT file of a Cobalt Strike keystrokes file
# Before Cobalt Strike 4.2
#
# Author: Outflank B.V. / Marc Smeets
#

def filter(event)
	host = event.get("[agent][name]")
	logpath = event.get("[log][file][path]")
	implant_id = event.get("[implant][id]")
	log_dir = File.dirname(logpath.rpartition('/logs').last)
	keystrokespath = "/c2logs/#{host}/cobaltstrike/logs#{log_dir}/keystrokes_#{implant_id}.txt"
	event.tag("_rubyparseok")
  	event.set("[keystrokes][url]", keystrokespath)
	return [event]
end
