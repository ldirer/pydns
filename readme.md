Experimental tiny recursive dns server that answers only the most basic queries (query for an ipv4 address of a domain).

Run the thing:

    python main.py
    
Manually test it:

    dig @127.0.0.1 -p 9000 ldirer.com
    
    ; <<>> DiG 9.16.1-Ubuntu <<>> @127.0.0.1 -p 9000 ldirer.com
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36403
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

    ;; QUESTION SECTION:
    ;ldirer.com.                    IN      A

    ;; ANSWER SECTION:
    ldirer.com.             86400   IN      A       54.89.213.68

    ;; Query time: 656 msec
    ;; SERVER: 127.0.0.1#9000(127.0.0.1)
    ;; WHEN: Wed Sep 09 12:50:11 CEST 2020
    ;; MSG SIZE  rcvd: 54

# Great resources:

* An excellent comic explanation [https://howdns.works/ep1/](https://howdns.works/ep1)
* The RFC (mostly section 4) [https://tools.ietf.org/html/rfc1035](https://tools.ietf.org/html/rfc1035)
* [https://jvns.ca/blog/how-updating-dns-works/](https://jvns.ca/blog/how-updating-dns-works/)
    
# What's going on
    
My rough take on what is supposed to happen when asking for `recurse.com`, ignoring cache:

1. I'll ask the root server for recurse.com.  
2. It'll tell me it doesn't know about recurse.com but it knows about the Top Level Domain server for .com.
3. I'll ask the `.com` server about recurse.com
4. The `.com` server will tell me it doesn't have an ip address BUT it knows about authoritative nameservers (with ip addresses!).
5. (One of) the authoritative name servers gives me the ip address for recurse.com.

# The code

Maybe don't look at it :).
