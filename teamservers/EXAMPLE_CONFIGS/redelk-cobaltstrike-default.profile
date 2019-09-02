#
# Part of RedELK
# Example Cobalt Strike profile that makes it look like default. 
#
# Authors: Mark Bergman & Marc Smeets / Outflank B.V.
#

# This profile for your Cobalt Strike teamserver is aligned with the config examples for HAProxy and Apache.

set sleeptime "5000";
set jitter    "10";
set useragent "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0;  rv:11.0) like Gecko";


http-config {
	set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
        header "Server" "Apache";
		header "Keep-Alive" "timeout=5, max=100";
        header "Connection" "Keep-Alive";
    # X-Forwarded-For setting is available since Cobalt Strike v3.14. Comment out if you are using an older version.
	set trust_x_forwarded_for "true";
}

http-get {
	set uri "/dpixel";

	client {
		header "Accept" "*/*";
		header "Pragma" "no-cache";
		header "Connection" "Keep-Alive";
		metadata {
        	base64;
        	header "Cookie";
		}
	}

	server {
		header "Content-Type" "application/octet-stream";

		output {
			print;
		}
	}
}

http-post {
	set uri "/submit.php";
	client {
		header "Content-Type" "application/octet-stream";
  
      id {
        #netbios;
	    parameter "id";
      }

	  output {
		print;
      }
	}

	server {
		header "Content-Type" "text/html";

		output {
			print;
		}
	}
}
