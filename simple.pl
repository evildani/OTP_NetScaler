#!/usr/local/bin/perl -w
    #para iniciar en modo normal "perl simple.pl > /tmp/otp.log 2> /dev/null"
    #para iniciar en modo debug "perl simple.pl > /tmp/otp.debug 2> /tmp/otp.debug"
    ## para ver el log usar "tail -f /tmp/otp.debug"
   

    use RADIUS::Dictionary;
    use RADIUS::Packet;
    use Net::Inet;
    use Net::UDP;
    use Net::LDAP;
    use LWP::UserAgent;
    use HTTP::Request::Common qw{ POST };
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
    my $secret = "mysecret";  # Shared secret on the term server
    
    #lo necesario para LDAP TMOVILES
    my $ldapTMOV = Net::LDAP->new( 'ldaps://10.204.160.10' ) or die "$@";
    my $mesgTMOV = $ldapTMOV->bind( '1',  #TODO
                      password => '1'  #TODO
                    );
   my $baseTMOV = "dc=tmoviles,dc=com,dc=ar";
   #lo necesario para LDAP TASA
   my $ldapTASA = Net::LDAP->new( 'ldaps://10.249.20.161' ) or die "$@";
   my $mesgTASA = $ldapTASA->bind( '2',  #TODO
			password => '2'   #TODO
		);
   my $baseTASA = "dc=tasa,dc=telefonica,dc=com,dc=ar";
   #para el lab usar
   #my $attrs = [ 'cn','mail','TelephoneNumber' ];
   #para el telefonica usar
   my $attrs = [ 'cn','mail','mobile' ];
   #para Telefonica usar
   #my my $filter = "samAccountName=".$p->attr('User-Name'); = "samAccountName=".$p->attr('User-Name');
   #para lab usar
   #my $filter = "uid=".$p->attr('User-Name');


   
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
    					print STDERR "Received Access-Request\n";
    					my $rp = new RADIUS::Packet $dict;
    					if(length($p->password($secret))==4 || length($p->password($secret))==6)
    					{
    						# Print some details about the incoming request (try ->dump here)
    						print $p->attr('User-Name'), " logging in with password ",
						$p->password($secret), "\n";
    						#print "Current User ".$username." ".$usuarios{$p->attr('User-Name')}[0]." ".$usuarios{$p->attr('User-Name')}[1]."\n";
    						if ($usuarios{$p->attr('User-Name')}) 
    						{
    							print "Returning user: ".$p->attr('User-Name')."\n";
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
    										}else
    										{
    											$usuarios{$p->attr('User-Name')}[2]++;
    											print STDERR "Access-Challenge por intento errado.\n";
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
    						}else #SI EL USUARIO NO EXISTE, es usuario nuevo
    						{	print "Regisstrando Usuario\n";
    							#filtro para buscar en AD
    							my $filter = "samAccountName=".$p->attr('User-Name');
    							#buscar en LDAP telefono para verificar el los ultimos 4 digitos del telefono y poder enviar SMS
    							$mesgTMOV = $ldapTMOV->search ( base    => $baseTMOV,
											scope   => "sub",
    											filter  => $filter,
    											attrs   =>  $attrs
    											);
							print STDERR "MSG: ".$mesgTMOV->code."\n";
							my $entry;
    							my $telephone = 0; #inicia en 0, la busqueda debe cambiarlo
    							foreach $entry ($mesgTMOV->entries) 
    							{ 
								print STDERR "LDAP Busqueda DN=".$entry->dn()."\n";
    								if(!$entry->exists("mobile"))
    								{
    									print STDERR "TMOVILES ".$p->attr('User-Name')." No hay Telefono registrado en LDAP\n";
    									#$rp->set_code('Access-Reject');
    								}else
    								{
    									print STDERR "Telefono del usuarios: ".$entry->get_value("mobile")."\n";
    									$telephone = $entry->get_value("mobile");
    									print STDERR "telefono es: ".$telephone." al compara con password: ".$p->password($secret)."\n";	
    								}
    							}
    							if($telephone == 0)
    							{
    								$mesgTASA = $ldapTASA->search ( base    => $baseTASA,
											scope   => "sub",
    											filter  => $filter,
    											attrs   =>  $attrs
    											);
								print STDERR "MSG: ".$mesgTMOV->code."\n";
    								
								foreach $entry ($mesgTASA->entries) 
								{ 
									print STDERR "LDAP Busqueda DN=".$entry->dn()."\n";
									if(!$entry->exists("mobile"))
									{
										print STDERR "TASA ".$p->attr('User-Name')." No hay Telefono registrado en LDAP\n";
										#$rp->set_code('Access-Reject');
									}else
									{
										print STDERR "Telefono del usuarios: ".$entry->get_value("mobile")."\n";
										$telephone = $entry->get_value("mobile");
										print STDERR "telefono es: ".$telephone." al compara con password: ".$p->password($secret)."\n";	
									}
								}
    							}
    							if($telephone == 0)
    							{
    								print STDERR "El usuario no tiene telefono en ningun dominio";
    								$rp->set_code('Access-Reject');
    							}	
							if($p->password($secret) eq substr($telephone, -4))
							{ 
    								print STDERR "New User Start\n";
    								#crear token
    								my $string = "";
    								for (0..5) { $string .= chr( int(rand(25) + 65) ); } print $string."\n";
    								#print "CHECK Access-Challenge:: Current User ".$p->attr('User-Name')." OTP: ".$usuarios{$p->attr('User-Name')}[0]." Time: ".$usuarios{$p->attr('User-Name')}[1]." Intentos: ".$usuarios{$p->attr('User-Name')}[2]."\n";
    								$usuarios{$p->attr('User-Name')}[2] = 0;
    								$usuarios{$p->attr('User-Name')}[0] = $string;
    								#crear tiempo de expiracion
    								my $time = time()+300;
    								$usuarios{$p->attr('User-Name')}[1] = $time;
								#####CODIGO PARA ENVIAR SMS#####
								my $uri = 'http://10.167.27.132:4300/cgi-bin/smspost.cgi';
								my $ua  = LWP::UserAgent->new();
								my $request = POST $uri,
										Content => [
										RECIPIENT => $telephone,
										TEXT => $string,
										SOURCE_ADDR=> "314"
										];
								$request->header('Content-Type','application/x-www-form-urlencoded');
								$request->protocol('HTTP/1.0');
								#make the actual POST
								print STDERR "POST as String:\n ".$request->as_string."\n\nSending...\n";
								my $response = $ua->request($request) or die "error conecting to SMS system\n";
								if ($response->code eq 200) 
								{
									$string = "";
									$time = 0;
									print STDERR "Access-Challenge:: Current User ".$p->attr('User-Name')." OTP: ".$usuarios{$p->attr('User-Name')}[0]." Time: ".$usuarios{$p->attr('User-Name')}[1]." Intentos: ".$usuarios{$p->attr('User-Name')}[2]."\n";
									$rp->set_code('Access-Challenge');
								}else 
								{
									$string = "";
									$time = 0;
									print "HTTP POST error code: ", $response->code, "\n";
									print "HTTP POST error message: ", $response->message, "\n";
									$rp->set_code('Access-Reject');
								}
    												#print STDERR "New User with token ".$string." expires at ".$time."\n";
							}else
							{
    								print STDERR "Access-Reject:: Current User ".$p->attr('User-Name')." Password has wrong format\n";
    								$rp->set_code('Access-Reject');
							}
    						} #cierra ELSE si no existe el telefono				
    					}else #cierra if del formato para password
    					{
    						if ($usuarios{$p->attr('User-Name')})
    						{
    							if($usuarios{$p->attr('User-Name')}[2]>3)
    							{
                                                              $rp->set_code('Access-Reject');
                                                              $usuarios{$p->attr('User-Name')}[2] = "0";
                                                              $usuarios{$p->attr('User-Name')}[1] = "0";
                                                              delete $usuarios{$p->attr('User-Name')};
                                                              print STDERR "Access-Reject por intentos errados en password de formato errado.\n";
                                                              $rp->set_code('Access-Reject'); 
    							}else
    							{
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
    					print "Unexpected packet type recieved.";
    					$p->dump;
    				} #cierra else del if(packet Accept-Request
    			}#cierra if nFound
    } #cierra while