global a: set[addr];
global b: table[addr] of set[string];

event http_header(c:connection, is_orig:bool, name:string, value:string)
	{
	         if (!(c$id$orig_h in a))
	{
	        add a[c$id$orig_h];
	        b[c$id$orig_h]=set();
	}
	       if (name == "USER-AGENT")
	{
	       add b[c$id$orig_h][to_lower(value)];
	}
	}
event zeek_done()
	{
	       for (i in a)
	{
	       if (|b[i]|>=3)
		print fmt("%s is a proxy",i);
	}
	}