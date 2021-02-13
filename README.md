# ** PacketPacman
## ** An intrusion detection system


A machine learning powered intrusion detection system 
Currently checks for DDOS SYN attacks 
Run the build file in your server instance or (an instance to which you mirror the network traffic) with sudo privilages.

### ** Procedure:

* Reads the traffic through a raw socket.
* Accumulates the network packets.
* Every 5 sec the accumulated packet data is processed and passed to detector module.
* Detector module is a neural network.
* Detector module returns the a probability for the traffic from a specific IP address to be DDOS.


Note: This project has been recently transferred from gitlab to github and no changes have been made yet to satisfy the requirements for go modules.
Will make changes and also add the script to mirror the traffic soon.
