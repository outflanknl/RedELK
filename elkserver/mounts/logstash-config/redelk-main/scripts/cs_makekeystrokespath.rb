#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full TXT file of a Cobalt Strike keystrokes file
# Cobalt Strike 4.2 and higher
#
# Author: Outflank B.V. / Marc Smeets
#

def filter(event)
	host = event.get("[agent][name]")
	logpath = event.get("[log][file][path]")
	relative_path = logpath.rpartition('/logs').last
	keystrokespath = "/c2logs/#{host}/cobaltstrike/logs#{relative_path}"
	event.tag("_rubyparseok")
  	event.set("[keystrokes][url]", keystrokespath)
	return [event]
end
