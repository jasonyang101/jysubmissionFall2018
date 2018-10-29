import firewall
import sys

f = firewall.Firewall(sys.argv[1])

if f.accept_packet("inbound","tcp",80,"192.168.1.2") == True:
    print "Passed Test Check Port Set"
if f.accept_packet("inbound","udp",53,"192.168.1.2") == True:
    print "Passed Test Check IP Range"
if f.accept_packet("outbound","tcp",10000,"192.168.10.11") == True:
    print "Passed Test Check Port Range Lower Bound"
if f.accept_packet("inbound","tcp",81,"192.168.1.2") == False:
    print "Passed Test Check Port not in Set or Range"
if f.accept_packet("inbound","udp",24,"52.12.48.92") == False:
    print "Passed Test Check IP not in Set or Range"
