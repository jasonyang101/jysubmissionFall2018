import bisect

# defines an interval class that's mostly used as overhead to sort our list by intervals
# could have simply done this with tuples but still need to put it back into a list so we can bsearch
class Interval(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end

class Firewall(object):
    # set up constructor for the firewall
    def __init__(self, file_path):
        # initialize all 4 maps to include all of the potential types (only 4 total)
        self.port_range_map = {"inboundtcp":[],"inboundudp":[],"outboundtcp":[],"outboundudp":[]}
        self.ip_range_map = {"inboundtcp":[],"inboundudp":[],"outboundtcp":[],"outboundudp":[]}
        self.port_set = {"inboundtcp":set(),"inboundudp":set(),"outboundtcp":set(),"outboundudp":set()}
        self.ip_set = {"inboundtcp":set(),"inboundudp":set(),"outboundtcp":set(),"outboundudp":set()}
        # parse the input, populates the maps with their corresponding values
        with open(file_path) as f:
            rules = f.readlines()
        rules = [line.strip() for line in rules]
        self.parse_input(rules)
        # for each type in here, we look to merge the intervals together
        # this allows for them to be sorted, as well as deletes values from the intervals
        for type in self.port_range_map:
            self.port_range_map[type] = self.merge(self.port_range_map[type])
            # append the starts and ends to a list, and repopulate the map
            value_list = []
            # this allows for us to binary search with integer values
            for i in range(len(self.port_range_map[type])):
                value_list.append(self.port_range_map[type][i].start)
                value_list.append(self.port_range_map[type][i].end+1) # to make it exclusive (i.e. can include the last value)
            # reset the type's value in the map to this new value_list
            self.port_range_map[type] = value_list
        # do the same as above for the ip ranges
        for type in self.ip_range_map:
            self.ip_range_map[type] = self.merge(self.ip_range_map[type])
            value_list = []
            for i in range(len(self.ip_range_map[type])):
                value_list.append(self.ip_range_map[type][i].start)
                value_list.append(self.ip_range_map[type][i].end+1) # to make it exclusive
            self.ip_range_map[type] = value_list
    # this is where we parse the input of the files
    def parse_input(self, rules):
        for rule in rules:
            # split the comma separated values
            curr_rule = rule.split(",")
            # finds the type
            type = curr_rule[0]+curr_rule[1]
            # check if there's a range, if so we add it to the range map
            if("-" in curr_rule[2]):
                startend = curr_rule[2].split("-")
                # create an interval object with the start and end
                interval = Interval(int(startend[0]),int(startend[1]))
                self.port_range_map[type].append(interval)
            # if there's no range, we add it to the set
            else:
                self.port_set[type].add(int(curr_rule[2]))
            # check if there's an ip-range, if so add the start and end to an interval object
            if("-" in curr_rule[3]):
                startend = curr_rule[3].split("-")
                # convert the ip addresses to hex values to integers
                interval = Interval(int(self.convertIPtoHex(startend[0]),16), int(self.convertIPtoHex(startend[1]),16))
                self.ip_range_map[type].append(interval)
            else:
                ip_val = int(self.convertIPtoHex(curr_rule[3]),16)
                self.ip_set[type].add(ip_val)
    # returns a formatted string of hex values
    def convertIPtoHex(self, ip):
        ip_list = ip.split(".")
        return '{:02X}{:02X}{:02X}{:02X}'.format(*map(int,ip_list))
    # merges the intervals together
    def merge(self, intervals):
        # if there's nothing to merge
        if(len(intervals) <= 1):
            return intervals;
        # sort the intervals
        intervals = sorted(intervals,key=lambda Interval: Interval.start)
        # grab the first interval, which is what we'll compare off of
        prev = intervals[0]
        i = 0;
        # loop through the variables, takes O(n) time
        for interval in intervals[1:]:
            # if there's something to merge
            if(interval.start <= prev.end):
                # find new start and end
                interval.start = min(prev.start,interval.start)
                interval.end = max(prev.end, interval.end)
                # delete the previous one
                del intervals[i]
            # look at the next thing to delete
            else:
                i+=1
            # reset the previous
            prev = interval
        # return the updated list of intervals
        return intervals

    # determine whether or not we can accept the packet
    def accept_packet(self, direction, protocol, port, ip_address):
        # grab the type
        type = direction+protocol
        # find the ip_val by converting it
        ip_val = int(self.convertIPtoHex(ip_address),16)
        # if any of these 4 conditions are satisfied, then we know it's a valid packet, can return true
        # subtract one from bisect_right becaues bisect_right returns the rightmost place where we would insert it if it were to be inserted
        # bisect takes log(n) time
        if ((port in self.port_set[type] and ip_val in self.ip_set[type]) \
         or (port in self.port_set[type] and (bisect.bisect_right(self.ip_range_map[type], ip_val)-1)%2 == 0) \
         or ((bisect.bisect_right(self.port_range_map[type],port)%2-1) == 0 and ip_val in self.ip_set[type]) \
         or ((bisect.bisect_right(self.port_range_map[type],port)%2-1) == 0 and (bisect.bisect_right(self.ip_range_map[type],ip_val)-1)%2 == 0)):
            return True
        # otherwise, it's invalid and we can return false
        else:
            return False
