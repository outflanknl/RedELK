#
# Part of RedELK
# Script to make a json object to be stored as nested object of all found security tools
#
# Author: Outflank B.V. / Marc Smeets
#

def filter(event)
	string = event.get("[bluecheck][sectools]")
	string2 = string.gsub("ProcessID","{ \"ProcessID\"")
	string3 = string2.gsub(" Vendor",", \"Vendor\"")
	string4 = string3.gsub(" Product",", \"Product\"")
	string5 = string4.gsub(",{","},{")
	string6 = string5.gsub(": ",": \"")
	string7 = string6.gsub(", ","\", ")
	string8 = string7.gsub("},","\"},")
	string9 = "["+string8+"\" }]"
	json = JSON.parse(string9)
	event.tag("_rubyparseok")
	event.set("[bluecheck][sectools]", json)
	return [event]
end
