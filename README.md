This is the submission for Jason Yang's Illumio Assessment:

1. Code design/Algorithmic Choices
A relatively naive solution to the given issue that jumped to mind was to partition the four different types (inboundtcp, inboundudp, outboundtcp, outboundudp),
and then I would simply add all of the potential ports to a set, and add all of the ip addresses to a set for each type, including the values within a specific range (for example port value range 5-10 would add 5,6,7...10 to the set as well). This may seem reasonable if our number of entries was relatively small. **However**, given that our input size is approximately 500k to 1 Million entries, it's clear that our space complexity for this would be ridiculous, and it would be nonsensical to add all of these values to a set. Because of the large number of entries, we could expect a large number of collisions, turning set insertion/lookup into *O(n)* time (worst case).

As a result, I've broken my code into two different sessions. Whenever a rule is input, and the port/ip_address are only one value, then we can append these values to a set. However, when a range is input, we create a Tuple of the start and end, and append it to a list. Upon completion of adding all intervals, we sort the intervals by the start time, and then we merge the intervals that overlap together. This overall takes O(nlogn) time to complete. This results in a list in which each alternating index is a start and an end index of intervals. From this, we can binary search for the max value that is less than or equal to our target, which is the packet we're attempting to accept. If the value returned corresponds to an end index (i.e. if the index is odd), then we can see that it doesn't lie within one of the intervals, and we can return False. If it corresponds to a start index, we know that it's within an interval, and we can return True. This lookup takes log(n) time in which n is two times the number of intervals.

While this log(n) lookup time is indeed slower than our O(1) set time, we've abstracted away the need to store each individual port and ip address, and instead we maintain the list of ranges, which is simply a tradeoff between space and time complexity. However, this is still much better than linearly searching for an appropriate range for the target value instead.

This algorithm applies to both the port ranges, as well as the ip_address ranges. For the ip_address, I converted the IP Address to a hex value and then to an integer, such that I can apply the same binary search algorithm as before.

2. Given More Time
In terms of time, the one issue is that my list of intervals currently holds all possible intervals, then merges them together. However, a better solution would be to binary search on the sorted list before inserting and do the deletions/merging of intervals on the fly as opposed to after inserting them all. This was something I looked into but in the interest of time, I was unable to fully complete. While the time would still be maintained as an O(nlogn) solution, it would be an optimization because the maximum number of intervals that would exist in the list would be smaller. This could potentially be done by binary searching for the start of a range, doing the same check as before seeing as to whether or not the returned index is odd or even, then binary searching for the end of the range to see where it would go, and deleting intervals between the two.

3. Testing
My approach with testing the code was to write tests such that I knew every piece of code was functioning as intended. For the most part, the interesting portions of the code were the merging of intervals, as well as the binary searching to ensure that we would always be able to tell when a given ip_address was in a valid range. By running a number of different accept_packet commands, we could easily tell if the intervals had been properly merged. Additionally, my code was tested as it was written, by printing debug outputs to ensure that the merging of intervals was working correctly.

To run the accept_packet test cases, I created two CSV files. The goal was to first ensure that the code works for a majority of cases (given), but also to sniff out the edge cases (such as searching for a lower or upper bound of the interval, searching outside of valid intervals, etc). This can be run using main.py and testcases.py, with passing in various .csv files that are included in this project.

To run the given test cases, simply run "python main.py firewall_rules.csv"
To run my personal testcases, run "python testcases.py firewall_rules_testcases.csv"

4. Teams
I'd be interested in two of the three listed teams. My number one choice would be the policy team, and my number two choice would be the platform team.
