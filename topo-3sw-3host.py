from mininet.topo import Topo

class MyTopo( Topo ):

    def __init__( self ):
        "Create custom topo"

        # init
        Topo.__init__( self )

        # add hosts
        host1 = self.addHost( 'h1' )
        host2 = self.addHost( 'h2' )
        host3 = self.addHost( 'h3' )

        sw1 = self.addSwitch( 's1' )
        sw2 = self.addSwitch( 's2' )
        sw3 = self.addSwitch( 's3' )

        # add links
        self.addLink( host1, sw1 )
        self.addLink( host2, sw2 )
        self.addLink( host3, sw3 )
        self.addLink( sw1, sw2 )
        self.addLink( sw1, sw3 )
        self.addLink( sw2, sw3 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
