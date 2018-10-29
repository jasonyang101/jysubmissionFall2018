import firewall
import sys

f = firewall.Firewall(sys.argv[1])
# Merge Test Cases:
# for both ports and ip addresses: includes intervals that have same start and end
# also intervals that are contiguous, intervals that are overlapping, etc.
port_interval_list = [5,6,10,41,50,71,90,101,300,701,900,1002]
if f.port_range_map["inboundtcp"] == port_interval_list:
    print "Passed Merge Port Test Cases"
ip_interval_list = [318832897,335544320,3232235777,3232236038,3232238081,3232286844]
if f.ip_range_map["inboundudp"] == ip_interval_list:
    print "Passed Merge IP Test Cases"
# Accept Test Cases:
if f.accept_packet("inbound","tcp",80,"192.168.1.2") == True:
    print "Passed Test Check Port Set"
if f.accept_packet("inbound","udp",53,"192.168.1.2") == True:
    print "Passed Test Check IP Range"
if f.accept_packet("inbound","tcp",10,"192.168.1.2") == True:
    print "Passed Test Check Port Range Lower Bound Large"
if f.accept_packet("inbound","tcp",40,"192.168.1.2") == True:
    print "Passed Test Check Port Range Upper Bound Large"
if f.accept_packet("outbound","tcp",10000,"192.168.10.11") == True:
    print "Passed Test Check Port Range Lower Bound Small"
if f.accept_packet("outbound","tcp",20000,"192.168.10.11") == True:
    print "Passed Test Check Port Range Upper Bound Small"
if f.accept_packet("inbound","tcp",81,"192.168.1.2") == False:
    print "Passed Test Check Port not in Set"
if f.accept_packet("inbound","tcp",101,"192.168.1.2") == False:
    print "Passed Test Check Port not in Range"
if f.accept_packet("inbound","udp",24,"52.12.48.92") == False:
    print "Passed Test Check IP not in Set or Range"
