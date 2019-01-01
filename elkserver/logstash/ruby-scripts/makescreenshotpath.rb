#
# Part of RedELK
# Script to have logstash insert a extra fields  pointing to the Cobalt Strike screenshots
#
# Author: Outflank B.V. / Marc Smeets / @mramsmeets
#

def register(params)
#        @timestamp = params["timestamp"]
#        @source = param["source"]
#	@beacon_id = param["beacon_id"]
end

def filter(event)
	require "date"
	host = event.get("[beat][name]")
	logpath = event.get("source")
	beacon_id = event.get("beacon_id")
	timestring = event.get("@timestamp").time.localtime.strftime("%I%M%S")
	temppath = logpath.split('/cobaltstrike')
	temppath2 = temppath[1].split(/\/([^\/]*)$/)
	screenshoturl = "/cslogs/" + "#{host}" + "#{temppath2[0]}" + "/screenshots/screen_" + "#{timestring}" + "_" + "#{beacon_id}" + ".jpg"
	thumburl = "/cslogs/" + "#{host}" + "#{temppath2[0]}" + "/screenshots/screen_" + "#{timestring}" + "_" + "#{beacon_id}" + ".jpg.thumb.jpg"
	event.tag("_rubyparseok")
    	event.set("screenshotfull", screenshoturl)
	event.set("screenshotthumb", thumburl)
	return [event]
end
