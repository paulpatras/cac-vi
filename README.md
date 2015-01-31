# CAC-VI
# Author: Paul Patras

CAC-VI is a Linux application that implements a centralized adaptive algorithm, which can be 
deployed on commodity access points to optimise the performance of video traffic in WLANs based
on the IEEE 802.11 technology.

CAC-VI adjust dynamically the contention parameters of the video (VI) access category. To be 
effective, the DSCP field in the IP header of the the video packets must be set accordingly.

Details about CAC-VI's operation are documented in the flowing research paper:

- P. Patras, A. Banchs, P. Serrano, "A Control Theoretic Scheme for Efficient Video Transmission 
over IEEE 802.11e EDCA WLANs", ACM Transactions on Multimedia Computing, Communications and 
Applications, vol. 8, no. 3, pp. 29:1–29:23, Jul. 2012.
