from pox.core import core

from pox.lib.util import dpid_to_str

import pox.lib.packet.ethernet as eth
import pox.lib.packet.llc as llc

from pox.lib.addresses import *

import pox.openflow.libopenflow_01 as of

from pox.lib.recoco import Timer

log = core.getLogger()

# Hello Time 2s per default
TIMER = 2

class MySwitch( object ):

  def __init__( self ):
    core.openflow.addListeners( self )

    # connections to the sw
    self.connection = {}
    self.stp = {}

  def _handle_ConnectionUp( self, event ):
    dpid = event.dpid
    self.connection[ dpid ] = event.connection
    max_ports = len( event.connection.ports )
    log.debug( "sw %s is connected with %i ports",
               dpid_to_str( dpid ), max_ports )

    # set BPDU for this sw
    self.stp[ dpid ] = {}
    self.stp[ dpid ][ 0 ] = [dpid,0,dpid]
    
    for i in range( max_ports - 1 ):
      self.stp[dpid][i+1] = 'D'

    # schedule periodic BPDU
    Timer( TIMER, self.send_bpdu, args = [dpid], recurring=True )


  def send_bpdu( self, dpid ):
    eth_packet = eth()
    eth_packet.dst = EthAddr('01:80:C2:00:00:00')
    eth_packet.src = EthAddr('00:00:00:00:00:01')
    eth_packet.type = 21

    llc_packet = llc()
    llc_packet.dsap = 0x42
    llc_packet.ssap = 0x42
    llc_packet.control = 0x3

    for i in self.stp[dpid]:
      # do not send BPDU over R or B ports
      if i == 0 or self.stp[dpid][i] != 'D':
        continue

      vector = self.stp[dpid][0]
      vector.append( i )

      llc_packet.next = str( vector[0] ) + str( vector[1] ) + \
                        str( vector[2] ) + str( vector[3] )
      eth_packet.set_payload(llc_packet)
    
      msg = of.ofp_packet_out()
      msg.data = eth_packet
      action = of.ofp_action_output(port = i)
      msg.actions.append(action)
      self.connection[dpid].send(msg)

  
  def stprotocol( self, dpid, packet, packet_in ):
    vector = [int( packet.payload.next[0] ),
              1 + int( packet.payload.next[1] ),
              int ( packet.payload.next[2] ),
              int ( packet.payload.next[3] )]

    port_r = packet_in.in_port

    local_vector = self.stp[dpid][0]
    local_vector.append(port_r)

    # update local BPDU and port role
    if self.better( 2, vector, local_vector ):
      self.stp[dpid][0] = [vector[0], vector[1], dpid]
      self.stp[dpid][port_r] = 'R'
      log.debug( "sw%i: port %i changes role to R", dpid, port_r )
      
      for i in self.stp[dpid]:
        if i == 0 or i == port_r:
          continue

        if self.stp[dpid][i] == 'R':
          self.stp[dpid][i] = 'D'
          log.debug( "sw%i: port %i changes role to D", dpid, i )

    # check if we need to bloc a port
    else:
      if self.stp[dpid][port_r] != 'R':
        vector[1] -= 1
        if self.stp[dpid][port_r] != 'B' and self.better(4, vector, local_vector):
          self.stp[dpid][port_r] = 'B'
          log.debug( "sw%i: port %i changes role to B", dpid, port_r )
          self.push_blocked( dpid, port_r )

  # return True if the vector1 is better (lower) than vector2 on the first size elements
  def better( self, size, vector1, vector2 ):
    i = 0
    while i < size and vector1[i] == vector2[i]:
      i += 1

    if i != size:
      if vector1[i] < vector2[i]:
        return True

    return False

  def push_blocked( self, dpid, port ):
    # forward STP traffic from port
    msg = of.ofp_flow_mod()
    msg.priority = 2
    msg.match.in_port = port
    msg.match.dl_dst = EthAddr( '01:80:C2:00:00:00' )
    action = of.ofp_action_output( port = of.OFPP_CONTROLLER )
    msg.actions.append( action )
    self.connection[dpid].send( msg )

    # drop all traffic received on that port (lower priority than the previous rule)
    msg = of.ofp_flow_mod()
    msg.priority = 1
    msg.match.in_port = port
    self.connection[dpid].send( msg )

  def resend_packet( self, packet_in, out_port, dpid ):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection[dpid].send(msg)


  def act_like_hub (self, packet, packet_in, dpid):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports but blocked one
    for i in self.stp:
      if i != 0 and i != packet_in.in_port and self.stp[dpid][i] != 'B':
        log.debug("sw %d resend packet on port %d", dpid, i)
        self.resend_packet(packet_in, i, dpid)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    if packet.dst == EthAddr( '01:80:C2:00:00:00' ) :
      self.stprotocol( event.dpid, packet, packet_in )
    else:
      self.act_like_hub( packet, packet_in, event.dpid )


def launch():
  core.registerNew( MySwitch )
