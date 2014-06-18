    #!/usr/local/bin/perl -w

    use RADIUS::Dictionary;
    use RADIUS::Packet;
    use Net::Inet;
    use Net::UDP;
    use Net::LDAP;
    use Fcntl;
    use strict;

    # This is a VERY simple RADIUS authentication server which responds
    # to Access-Request packets with Access-Accept.  This allows anyone
    # to log in.
    my %usuarios;
    #$my @user = ("ABCDEF" ,time()+300 );
    my $username = "nata";
    #$usuarios{$username} = [@user];
    $usuarios{$username}[0] = "ABCDEF";
    $usuarios{$username}[1] = time()+300;
    my $string = "";
    my $time = 0;
    my $secret = "mysecret";  # Shared secret on the term server

    # Parse the RADIUS dictionary file (must have dictionary in current dir)
    my $dict = new RADIUS::Dictionary "dictionary"
      or die "Couldn't read dictionary: $!";

    # Set up the network socket (must have radius in /etc/services)
    my $s = new Net::UDP { thisservice => "radius" } or die $!;
    $s->bind or die "Couldn't bind: $!";
    $s->fcntl(F_SETFL, $s->fcntl(F_GETFL,0) | O_NONBLOCK)
      or die "Couldn't make socket non-blocking: $!";

    #set up the LDAP conection for searching
 #  my $ldap = Net::LDAP->new( '192.168.40.7' ) or die "$@";
  #  my $mesg = $ldap->bind ;    # an anonymous bind
  #  $mesg = $ldap->search( # perform a search
  #                      base   => "dn=airseatrans,dn=com",
  #                      filter => "(&(sn=Daniel))"
  #                    );
  #  print $mesg->code;
  #  $mesg->code && die $mesg->error;
  #  my $entry;
 #foreach $entry ($mesg->entries) { print $entry->get_value("telephoneNumber"); }

    # Loop forever, recieving packets and replying to them
    while (1) {
      my ($rec, $whence);
      # Wait for a packet
      my $nfound = $s->select(1, 0, 1, undef);
      if ($nfound > 0) {
        # Get the data
        $rec = $s->recv(undef, undef, $whence);
        # Unpack it
        my $p = new RADIUS::Packet $dict, $rec;
        if ($p->code eq 'Access-Request') {
          # Print some details about the incoming request (try ->dump here)
          print $p->attr('User-Name'), " logging in with password ",
                $p->password($secret), "\n";
          $username = $p->attr('User-Name');      
          # Create a response packet
          my $rp = new RADIUS::Packet $dict;
          #print "Current User ".$username." ".$usuarios{$username}[0]." ".$usuarios{$username}[1]."\n";
          if ($usuarios{$p->attr('User-Name')}) 
          {
            #usuario ya registrado, es respuesta al challenge
            if($usuarios{$p->attr('User-Name')}[1]>time())
            {
              #verificación para ver si el token no esta expirado
              if($p->password($secret) eq $usuarios{$p->attr('User-Name')}[0])
              {
                #si el password corresponde al token
                print "USER OK".$p->attr('User-Name')."\n";
                $rp->set_code('Access-Accept');
                delete $usuarios{$p->attr('User-Name')};
              }else
              {
                #token y password no corresponden
                print "REJECT PASSWD MAL ".$p->attr('User-Name')."\n";
                $rp->set_code('Access-Challenge');
              }
            }else
              {
              #token expirado
              print "REJECT TOKEN EXPIRADO ".$p->attr('User-Name')."; Tiempo ahora:".time()."; Esperaba: ".$usuarios{$p->attr('User-Name')}[1]."\n";
              $rp->set_code('Access-Reject');
              delete $usuarios{$p->attr('User-Name')};
              }
            }
          else{
            #Si el usuario no esta registrado
            #TODO buscar en LDAP telefono para verificar el los ultimos 4 digitos del telefono
            
            #crear token
            for (0..5) { $string .= chr( int(rand(25) + 65) ); } print $string."\n";
             $usuarios{$username}[0] = $string;
             #crear tiempo de expiracion
             $time = time()+300;
             $usuarios{$username}[1] = $time;
             #print "New User with token ".$string." expires at ".$time."\n";
             $string = "";
             $time = 0;
             #print "Current User ".$username." ".$usuarios{$username}[0]." ".$usuarios{$username}[1]."\n";
             $rp->set_code('Access-Challenge');
           }
          $rp->set_identifier($p->identifier);
          $rp->set_authenticator($p->authenticator);
          # (No attributes are needed.. but you could set IP addr, etc. here)
          # Authenticate with the secret and send to the server.
          $s->sendto(auth_resp($rp->pack, $secret), $whence);
        }
        else {
          # It's not an Access-Request
          print "Unexpected packet type recieved.";
          $p->dump;
        }
      }
    }