#
# Part of RedELK
# Script to have logstash insert an extra field pointing to downloaded file via Outflank Stage1 C2
#
# Author: Outflank B.V. / Marc Smeets
#


def filter(event)
	host = event.get("[agent][name]")
	filename = event.get("[file][name]")
	file_path = event.get("[file][directory_local]")
	downloadsurl = "/c2logs/" + "#{host}" + "/stage1/downloads/" + "#{file_path}" + "_" + "#{filename}"
	event.tag("_rubyparseok")
	event.set("[file][url]", downloadsurl)
	return [event]
end