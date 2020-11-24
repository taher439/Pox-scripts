import sys
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.openflow.libopenflow_01 import *
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

log = core.getLogger()

MAX_PORT = 5

class MySwitch(object):
    def __init__(self):
        core.openflow.addListeners(self)
	
	self.connection = 0

        # commutation table (mac address -> port number)
	self.mac_to_port = {} 
        # (IP source, IP dest) -> TCP destination port
	self.tcp_destport = {} 


    def _handle_ConnectionUp(self, event):
	self.connection = event.connection
	max_ports = len(event.connection.ports)
	log.debug("Switch %s has come up with %i ports",
                  dpid_to_str(event.dpid),
                  max_ports)

        # sw should forward TCP traffic to controller
        self.push_tcp()


    def push_tcp(self):
	msg = of.ofp_flow_mod()
	msg.match.dl_type  = pkt.ethernet.IP_TYPE
	msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        # lower than blocking rule but greater than switching rules 
        msg.priority       = 5
        action = of.ofp_action_output(port = of.OFPP_CONTROLLER)
        msg.actions.append(action)
	self.connection.send(msg)


    def _handle_PacketIn (self, event):
	packet = event.parsed
	if not packet.parsed:
	    log.warning("Ignoring incomplete packet")
	    return

	packet_in = event.ofp

        # if the source is not blocked the message can be switched
        if self.port_scan_detection(packet) == False:
	    self.act_like_switch(packet, packet_in)


    def port_scan_detection(self, packet):
        # Scan detection focuses on TCP SYN
	if (packet.type == pkt.ethernet.IP_TYPE
            and packet.payload.protocol == pkt.ipv4.TCP_PROTOCOL
            and packet.payload.payload.flags == pkt.tcp.SYN_flag):

	    srcip = packet.payload.srcip
	    dstip = packet.payload.dstip
            dstport = packet.payload.payload.dstport
            log.debug("%s explored ports %d on %s", srcip, dstport, dstip)
            
	    if ((srcip,dstip) not in self.tcp_destport):
                self.tcp_destport[(srcip,dstip)] = set()

            # if the element already exists add() does not add the element
	    self.tcp_destport[(srcip,dstip)].add(dstport)

	    if len(self.tcp_destport[(srcip,dstip)]) >= MAX_PORT:
		log.info("%s scanned %d ports on %s => block",
                         srcip, MAX_PORT, dstip)
		self.push_deny_rule(srcip)

                # start from scratch if the rule expires
                del self.tcp_destport[(srcip, dstip)]
                return True

        return False


    def push_deny_rule(self, src_addr):
	msg = of.ofp_flow_mod()
	msg.match.dl_type  = pkt.ethernet.IP_TYPE
	msg.match.nw_src   = src_addr
        # highest priority
        msg.priority       = 10
        msg.idle_timeout   = 600
	self.connection.send(msg)


    def act_like_switch(self, packet, packet_in):
	log.debug("adding addr %s port %s in mac table",
                  str(packet.src),
                  str(packet_in.in_port))
	self.mac_to_port[packet.src] = packet_in.in_port

	if packet.dst in self.mac_to_port:
	    msg = of.ofp_flow_mod()
	    msg.match.dl_dst = packet.dst
            msg.priority     = 1
            msg.hard_timeout = 300
	    action = of.ofp_action_output(port = self.mac_to_port[packet.dst])
	    msg.actions.append(action)
	    self.connection.send(msg)
	    self.resend_packet(packet_in,
                               self.mac_to_port[packet.dst],
                               self.connection)

	else:
	    self.resend_packet(packet_in, of.OFPP_ALL, self.connection)


    def resend_packet (self, packet_in, out_port, connection):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)
        connection.send(msg)

def launch():
    core.registerNew(MySwitch)
