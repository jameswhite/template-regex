# WTF is this crap? 
I was asked to parse about a year of Cisco ASA logs and 
This simple module just creates a way to abstract a regular expresssion that might loook like: 
    ([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}|[0-9]{2}:[0-9]{2}:[0-9]{2})([+\-][0-9]{2}:[0-9]{2}) (\S+) Built (inbound|outbound) (TCP|UDP) connection ('[0-9]+) for ([^:]+:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+\s+\(([^\)]*)\)) to ([^:]+:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+\s+\(([^\)]*)\))

into template "chunks" that would look something like: 

    [% DATE %]T[% TIME %][% TZ_OFF %] [% HOSTNAME %] [% ASA_CODE %] Built [% DIRECTION %] [% TRANSPORT %] connection [% SESSION %] for [% IFACE_IP_PORT_P %] to [% IFACE_IP_PORT_P %]'

and return the name of the template (and a list of patterns matched by the tokens) It aims to provide a way to normalize your log parsing into the fewest patterns possible.


# Example

So the Log entry:
    2011-01-05T13:36:10.852712-06:00 ciscoasa01 %ASA-6-302015: Built inbound UDP connection 44505947 for servers:192.168.1.91/1846 (192.168.1.91/1846) to inside:192.168.7.4/88 (192.168.7.4/88)

parsed with the yaml:

    regex_tpl:
      DATE: '[0-9]{4}-[0-9]{2}-[0-9]{2}'
      TIME: '[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}|[0-9]{2}:[0-9]{2}:[0-9]{2}'
      # note we don't need parenthesis here becuase all tags are parenthesis-wrapped before being evaluated. 
      TZ_OFF: '[+\-][0-9]{2}:[0-9]{2}'
      HOSTNAME: \S+
      ASA_CODE: '%ASA-[0-9]+-[0-9]+:'
      DIRECTION: inbound|outbound
      TRANSPORT: TCP|UDP
      SESSION: '[0-9]+'
      IFACE_IP_PORT_P: '[^:]+:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+\s+\(([^\)]*)\)'
    log_tpl:
     - name: cisco_asa
       regex: '[% DATE %]T[% TIME %][% TZ_OFF %] [% HOSTNAME %] [% ASA_CODE %] '
       remainder:
        - name: session_buildup
          regex:  'Built [% DIRECTION %] [% TRANSPORT %] connection [% SESSION %] for [% IFACE_IP_PORT_P %] to [% IFACE_IP_PORT_P %]'
  
Returns the anonymous data struct that looks like
    VAR1 = {
              'patterns' => [
                              '2011-01-05',
                              '13:36:10.852712',
                              '-06:00',
                              'ciscoasa01',
                              '%ASA-6-302015:',
                              'inbound',
                              'UDP',
                              '44505947',
                              'servers:192.168.1.91/1846 (192.168.1.91/1846)',
                              '192.168.1.91/1846',
                              'inside:192.168.7.4/88 (192.168.7.4/88)',
                              '192.168.7.4/88'
                            ],
              'name' => 'cisco_asa.session_buildup'
            };

Because the template: 

    [% DATE %]T[% TIME %][% TZ_OFF %] [% HOSTNAME %] [% ASA_CODE %] Built [% DIRECTION %] [% TRANSPORT %] connection [% SESSION %] for [% IFACE_IP_PORT_P %] to [% IFACE_IP_PORT_P %]'

Expands to:

    ([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}|[0-9]{2}:[0-9]{2}:[0-9]{2})([+\-][0-9]{2}:[0-9]{2}) (\S+) Built (inbound|outbound) (TCP|UDP) connection ('[0-9]+) for ([^:]+:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+\s+\(([^\)]*)\)) to ([^:]+:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+\s+\(([^\)]*)\))

and parenthesis around the [%tokens %] are added for you to capture the results.
