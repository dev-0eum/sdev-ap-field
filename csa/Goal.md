# CSA (Channel Switch Attack)

## Goal
- After capture a beacon frame on the network, resend with inserting 5 bytes of Channel Switch Announcement information into tagged parameter
- New Channael Number is not real channel but temporary number to disconnect 
- Make tagged numbers in sorted

## Constraint
- Should ask me before fixing codes in everytime
- Ignore FCS(Frame Checksum) of captured beacon frame
- In case only indicated only "ap mac", make "AP broadcast frame"
- In case with "station mac", make "AP unicast frame"
- use "sleep()" code to avoid error of using wireless network

## Information
- Claude needs to make code in "src/radiotap.cpp" which has a feature that read bytes from network packet
- Use "csa/include/" and "csa/src/" as base code

### Test
- Build a unit test code into "csa/Test/unit_test{$trial_number}.cpp" with using "pcap_offline()" function to check the code works or not
- Testfile is located in "csa/pcapfile/"

### Result
- The difference of new packet from captured packet is only CSA tag and FCS bytes

### Logs
- The Folder is "csa/logs/"
- Make File named "agent_syslog_{$trial_number}"