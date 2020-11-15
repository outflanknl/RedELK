#
# Part of RedELK
# Script to have logstash insert extra fields pointing to the Cobalt Strike screenshots
# before Cobalt Strike 4.2
#
# Author: Outflank B.V. / Marc Smeets
#

def filter(event)
  require 'time'
  host = event.get("[agent][name]")
  logpath = event.get("[log][file][path]")
  implant_id = event.get("[implant][id]")
  timefromcs = event.get("[c2][timestamp]") + " UTC"
  timestring =  Time.parse(timefromcs).strftime("%I%M%S")
  temppath = logpath.split('/cobaltstrike')
  temppath2 = temppath[1].split(/\/([^\/]*)$/)
  screenshoturl = "/c2logs/" + "#{host}" + "#{temppath2[0]}" + "/screenshots/screen_" + "#{timestring}" + "_" + "#{implant_id}" + ".jpg"
  thumburl = "/c2logs/" + "#{host}" + "#{temppath2[0]}" + "/screenshots/screen_" + "#{timestring}" + "_" + "#{implant_id}" + ".jpg.thumb.jpg"
  event.tag("_rubyparseok")
  event.set("[screenshot][full]", screenshoturl)
  event.set("[screenshot][thumb]", thumburl)
  return [event]
end
