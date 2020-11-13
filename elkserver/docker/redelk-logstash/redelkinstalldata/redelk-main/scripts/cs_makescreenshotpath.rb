#
# Part of RedELK
# Script to have logstash insert extra fields pointing to the Cobalt Strike screenshots
# Cobalt Strike 4.2 and higher
#
# Author: Outflank B.V. / Marc Smeets
#

def filter(event)
  host = event.get("[agent][name]")
  logpath = event.get("[log][file][path]")
  filename = event.get("[screenshot][file_name]")
  temppath = logpath.split('/cobaltstrike')
  temppath2 = temppath[1].split(/\/([^\/]*)$/)
  screenshoturl = "/c2logs/" + "#{host}" + "#{temppath2[0]}" + "/screenshots/"+ "#{filename}"
  thumburl = "/c2logs/" + "#{host}" + "#{temppath2[0]}" + "/screenshots/"+ "#{filename}" + ".thumb.jpg"
  event.tag("_rubyparseok")
  event.set("[screenshot][full]", screenshoturl)
  event.set("[screenshot][thumb]", thumburl)
  return [event]
end