# Test1

each module needs to have
- version() function
	info:
	{
		'version':0.1,
	 	'name':'test1 module',
	 	'descriptoin':'test1 module description',
	 	'type':'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
	}

- run() function, just run what you need to run.
	returns:
	{
		'info':$info,
		'hits':
		{
			hits:[]  #list of ID fields in ES
			total:999   # number of hits
		}
		'indices':[] # list of indices that the hits are in
	}


	The list of hits contain per hit:
	{
		'id': {Elastic ID}
		'source':{full line}
		fields:{fields we want to report}
		message:"Alarm on $ip hitting c2_backend and unknown"
	}
