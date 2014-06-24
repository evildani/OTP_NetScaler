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
    $usuarios{$username}[2] = 0;
    my $string = "";
    my $time = 0;
    my $secret = "mysecret";  # Shared secret on the term server
    
    #lo necesario para LDAP
    my $ldap = Net::LDAP->new( '192.168.254.133' ) or die "$@";
    my $mesg = $ldap->bind( 'cn=admin',
                      password => 'ttikyy09'
                    );

   my $base = "dc=test, dc=com";
   #para el lab usar
   my $attrs = [ 'cn','mail','TelephoneNumber' ];
   #para el telefonica usar
   #my $attrs = [ 'cn','mail','movil' ];
   
    # Parse the RADIUS dictionary file (must have dictionary in current dir)
    my $dict = new RADIUS::Dictionary "dictionary"
      or die "Couldn't read dictionary: $!";

    # Set up the network socket (must have radius in /etc/services)
    my $s = new Net::UDP { thisservice => "radius" } or die $!;
    $s->bind or die "Couldn't bind: $!";
    $s->fcntl(F_SETFL, $s->fcntl(F_GETFL,0) | O_NONBLOCK)
      or die "Couldn't make socket non-blocking: $!";

    # Loop forever, recieving packets and replying to them
while (1) 
    {
    	my ($rec, $whence);
    	# Wait for a packet
    	my $nfound = $s->select(1, 0, 1, undef);
    			if ($nfound > 0) 
    			{
    				# Get the data
    				$rec = $s->recv(undef, undef, $whence);
    				# Unpack it
    				my $p = new RADIUS::Packet $dict, $rec;
    				if ($p->code eq 'Access-Request') 
    				{
    					my $rp = new RADIUS::Packet $dict;
    					if(length($p->password($secret))==4 || length($p->password($secret))==6)
    					{
    						# Print some details about the incoming request (try ->dump here)
    						print $p->attr('User-Name'), " logging in with password ",
    						$p->password($secret), "\n";
    								#$username = $p->attr('User-Name');      
    								# Create a response packet
    								
    								#print "Current User ".$username." ".$usuarios{$p->attr('User-Name')}[0]." ".$usuarios{$p->attr('User-Name')}[1]."\n";
    								if ($usuarios{$p->attr('User-Name')}) 
    								{
    									#usuario ya registrado, es respuesta al challenge
    									if($usuarios{$p->attr('User-Name')}[1]>time())
    									{
    										#verificación para ver si el token no esta expirado
    										if($p->password($secret) eq $usuarios{$p->attr('User-Name')}[0])
    										{
    											#si el password corresponde al token
    											print "Access-Accept:: USER PASSWD OK".$p->attr('User-Name')."\n";
    											$rp->set_code('Access-Accept');
    											$usuarios{$p->attr('User-Name')}[2] = "0";
    											$usuarios{$p->attr('User-Name')}[1] = "0";
    											delete $usuarios{$p->attr('User-Name')};
    										}else
    										{
    											#token y password no corresponden
    											print STDERR "PASSWD MAL ".$p->attr('User-Name')." Numero de intentos fallidos: ".$usuarios{$p->attr('User-Name')}[2]." > 3 \n";
    											#aumenta el contador de errores.
    											if($usuarios{$p->attr('User-Name')}[2]>3)
    											{
    												print STDERR "Access-Reject:: demasiados intentos fallidos: ".$usuarios{$p->attr('User-Name')}[2]."\n";
    												$rp->set_code('Access-Reject');
    												$usuarios{$p->attr('User-Name')}[2] = "0";
                                                                                                $usuarios{$p->attr('User-Name')}[1] = "0";
    												delete $usuarios{$p->attr('User-Name')};
    											}else{
    												$usuarios{$p->attr('User-Name')}[2]++;
    												print "Access-Challenge por intento errado.\n";
    												$rp->set_code('Access-Challenge');
    											}
    										}
    									}else
    									{
    										#token expirado
    										print STDERR "Access-Reject:: REJECT TOKEN EXPIRADO ".$p->attr('User-Name')."; Tiempo ahora:".time()."; Esperaba: ".$usuarios{$p->attr('User-Name')}[1]."\n";
    										$rp->set_code('Access-Reject');
    										$usuarios{$p->attr('User-Name')}[2] = "0";
    										$usuarios{$p->attr('User-Name')}[1] = "0";
    										delete $usuarios{$p->attr('User-Name')};
    									}
    								}
    								else{
    									#Si el usuario no esta registrado
    									#buscar en LDAP telefono para verificar el los ultimos 4 digitos del telefono
    									my $filter = "uid=".$p->attr('User-Name');
    									$mesg = $ldap->search ( base    => "$base",
    											scope   => "sub",
    											filter  => $filter,
    											attrs   =>  $attrs
    											);

    									print "MSG: ".$mesg->code."\n";

    									my $entry;
    									foreach $entry ($mesg->entries) { 
    										print "DN=".$entry->dn()."\n";
    										if(!$entry->exists("TelephoneNumber"))
    										{
    											print STDERR "Access-Reject:: ".$p->attr('User-Name')." No hay Telefono registrado en LDAP\n";
    											$rp->set_code('Access-Reject');
    										}else
    										{
    											print "Phone: ".$entry->get_value("telephoneNumber")."\n";
    											my $phone = $entry->get_value("telephoneNumber");
    											$phone = substr($phone, -4);
    											print "ultimos 4 digitos son: ".$phone." al compara con password: ".$p->password($secret)."\n";
    											if($p->password($secret) eq $phone)
    											{ 
    												print "New User Start\n";
    												#crear token
    												my $string = "";
    												for (0..5) { $string .= chr( int(rand(25) + 65) ); } print $string."\n";
    												#print "CHECK Access-Challenge:: Current User ".$p->attr('User-Name')." OTP: ".$usuarios{$p->attr('User-Name')}[0]." Time: ".$usuarios{$p->attr('User-Name')}[1]." Intentos: ".$usuarios{$p->attr('User-Name')}[2]."\n";
    												$usuarios{$p->attr('User-Name')}[2] = 0;
    												$usuarios{$p->attr('User-Name')}[0] = $string;
    												#crear tiempo de expiracion
    												my $time = time()+300;
    												$usuarios{$p->attr('User-Name')}[1] = $time;

    												#print "New User with token ".$string." expires at ".$time."\n";
    												$string = "";
    												$time = 0;
    												print "Access-Challenge:: Current User ".$p->attr('User-Name')." OTP: ".$usuarios{$p->attr('User-Name')}[0]." Time: ".$usuarios{$p->attr('User-Name')}[1]." Intentos: ".$usuarios{$p->attr('User-Name')}[2]."\n";
    												$rp->set_code('Access-Challenge');
    											}else
    											{
    												print STDERR "Access-Reject:: Current User ".$p->attr('User-Name')." Password has wrong format\n";
    												$rp->set_code('Access-Reject');
    											}
    										} #cierra si no existe el telefono
    									} #cierra el for each de las entradas del telefono
    								} #cierra el if si el usuario no esta registrado, es nuevo.
    					}else #cierra if del formato para password
    					{
    						if ($usuarios{$p->attr('User-Name')}){
    							if($usuarios{$p->attr('User-Name')}[2]>3){
                                                              $rp->set_code('Access-Reject');
                                                              $usuarios{$p->attr('User-Name')}[2] = "0";
                                                              $usuarios{$p->attr('User-Name')}[1] = "0";
                                                              delete $usuarios{$p->attr('User-Name')};
                                                              print STDERR "Access-Reject por intentos errados en password de formato errado.\n";
                                                              $rp->set_code('Access-Reject'); 
    							}
    							else{
                                                              $usuarios{$p->attr('User-Name')}[2]++;
                                                              print STDERR "Access-Challenge por intento errado con password de formato errado.\n";
                                                              $rp->set_code('Access-Challenge');
                                                        }
    						}else{
                                                        #password has incorrect format
                                                        print STDERR "Password is not 4-digit or 6-alpha\n";
                                                        $rp->set_code('Access-Reject'); 
                                                }
    					}
    					$rp->set_identifier($p->identifier);
    					$rp->set_authenticator($p->authenticator);
    					# (No attributes are needed.. but you could set IP addr, etc. here)
    					# Authenticate with the secret and send to the server.
    					#print STDERR "Sendto\n";
    					$s->sendto(auth_resp($rp->pack, $secret), $whence);
    				} #cierra el if(packet Accept-Request
    				else {
                                        # It's not an Access-Request
    					print STDERR "Unexpected packet type recieved.";
    					$p->dump;
    				} #cierra else del if(packet Accept-Request
    			}#cierra if nFound
    } #cierra while