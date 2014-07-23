#!/usr/local/bin/perl -w
    #para iniciar en modo normal "perl simple.pl > /tmp/otp.log 2> /dev/null"
    #para iniciar en modo debug "perl simple.pl > /tmp/otp.debug 2> /tmp/otp.debug"
    ## para ver el log usar "tail -f /tmp/otp.debug"
    ##
    ##
    ## ultima versión disponible en https://github.com/evildani/OTP_NetScaler
    ##
   

    use RADIUS::Dictionary;
    use RADIUS::Packet;
    use Net::Inet;
    use Net::UDP;
    use Net::LDAP;
    use LWP::UserAgent;
    use HTTP::Request::Common qw{ POST };
    use Fcntl;
    use strict;

    #archivo de configuración
    open (CONFIG, '/var/tmp/simple.config');
    my %Config;
    while (<CONFIG>) {
    chomp;
    s/#.*//;
    s/^\s+//;
    s/\s+$//;
    next unless length;
    my ($var, $value) = split(/\s*=\s*/, $_, 2);
    $Config{$var} = $value;
    } 

    
    my %usuarios;
    #$my @user = ("ABCDEF" ,time()+300 );
    my $username = "nata";
    #$usuarios{$username} = [@user];
    $usuarios{$username}[0] = "ABCDEF";
    $usuarios{$username}[1] = time()+300;
    $usuarios{$username}[2] = 0;
    my $secret = "mysecret";  # Shared secret on the term server
    my $baseTMOV = "dc=tmoviles,dc=com,dc=ar";
	my $baseTASA = "dc=tasa,dc=telefonica,dc=com,dc=ar";
    
    #inicia la conexion con LDAP de cada dominio
    my $ldapTMOV ;
    my $mesgTMOV;
    my $ldapTASA;
	my $mesgTASA;
   
    #sub start_ldap_tmov($ldapTMOV,$mesgTMOV);
    sub start_ldap_tmov{
    	$ldapTMOV = Net::LDAP->new( $Config{tmov_ldap_uri} ) or die "$@";
		#lo necesario para LDAP TMOVILES
	    $mesgTMOV = $ldapTMOV->bind(  $Config{tmov_ldap_username},
			      password => $Config{tmov_ldap_password} 
			  );
	}
	
	#sub start_ldap_tasa($ldapTASA,$mesgTASA);
   sub start_ldap_tasa{
   		$ldapTASA = Net::LDAP->new($Config{tmov_ldap_uri}) or die "$@";
	   	#lo necesario para LDAP TASA
	   	$mesgTASA = $ldapTASA->bind( $Config{tasa_ldap_username},
				password => $Config{tasa_ldap_password}   
		);
   }
   
  
   ## Inmediatamente arriba estan definidas las funciones, tan solo inician la conexion y hace el bind.
   start_ldap_tasa($ldapTASA,$mesgTASA);
   start_ldap_tmov($ldapTMOV,$mesgTMOV); 
  
   #para el lab usar
   #my $attrs = [ 'cn','mail','TelephoneNumber' ];
   #para el telefonica usar
   my $attrs = [ 'cn','mail','mobile' ];
   #para Telefonica usar
   #my my $filter = "samAccountName=".$p->attr('User-Name'); = "samAccountName=".$p->attr('User-Name');
   #para lab usar
   #my $filter = "uid=".$p->attr('User-Name');


   
    # Parse the RADIUS dictionary file (absolut path to file)
    my $dict = new RADIUS::Dictionary "/var/tmp/dictionary"
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
##__1__##__START    				
    				if ($p->code eq 'Access-Request')   ##__1__##__START
    				{
    					print STDERR "Received Access-Request\n";
    					my $rp = new RADIUS::Packet $dict;
##__2__##__START    					
    					if(length($p->password($secret))==4 || length($p->password($secret))==6) ##__2__##__START
    					{
    						# Print some details about the incoming request (try ->dump here)
    						print $p->attr('User-Name')." logging in with password ".$p->password($secret)."\n";
    						#print "Current User ".$username." ".$usuarios{$p->attr('User-Name')}[0]." ".$usuarios{$p->attr('User-Name')}[1]."\n";
##__3__##__START    						
    						if ($usuarios{$p->attr('User-Name')})  ##__3__##__START
    						{
    							print "Returning user: ".$p->attr('User-Name')."\n";
##__4__##__START					#usuario ya registrado, es respuesta al challenge
    							if($usuarios{$p->attr('User-Name')}[1]>time()) ##__4__##__START
    							{
    								#verificación para ver si el token no esta expirado
    								if($p->password($secret) eq $usuarios{$p->attr('User-Name')}[0]) ##__5__##__START
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
##__10__##__START    								#aumenta el contador de errores.
    										if($usuarios{$p->attr('User-Name')}[2]>3) ##__10__##__START
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
    						}
    						else
    						{ #SI EL USUARIO NO EXISTE, es usuario nuevo ##__9__##__START
    							
##__9__##__START    							
    							print "Registrando Usuario\n";
    							#filtro para buscar en AD
    							my $filter = "samAccountName=".$p->attr('User-Name');
    							my $entry;
    							my $telephone = 0; #inicia en 0, la busqueda debe cambiarlo
    							#buscar en LDAP telefono para verificar el los ultimos 4 digitos del telefono y poder enviar SMS
    							start_ldap_tmov($ldapTMOV,$mesgTMOV);
    							$mesgTMOV = $ldapTMOV->search ( base    => $baseTMOV,
											scope   => "sub",
    											filter  => $filter,
    											attrs   =>  $attrs
    											);
    							if($mesgTMOV->code==81)
    							{
									print "Error en conexion a LDAO TMOV ".$mesgTMOV->code."\n";
								}
								else
								{
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
    							}
    							$ldapTMOV->unbind;
    							## si no es usuario TMOVILES no se encontro un numero telefonico para el por lo cual aun es 0.
    							if($telephone == 0)
    							{
    								start_ldap_tasa($ldapTASA,$mesgTASA);
    								$mesgTASA = $ldapTASA->search ( base    => $baseTASA,
											scope   => "sub",
    											filter  => $filter,
    											attrs   =>  $attrs
    											);
    								if($mesgTASA->code==81)
    								{
										print "Error en conexion LDAO TASA: ".$mesgTASA->code."\n";
									}
									else #else de OK en LDAP
									{
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
									$ldapTASA->unbind;
    							}
    							if($telephone == 0)
    							{
    								print STDERR "El usuario no tiene telefono en ningun dominio\n";
    								$rp->set_code('Access-Reject');
    							}	
    						}
##__6__##__START					
								if($p->password($secret) eq substr($telephone, -4)) ##__6__##__START
								{ 
    								print STDERR "New User Start\n";
    								#crear token
    								my $string = "";
##__7__##__START						##Esta linea genera el TOKEN de 6 caracteres
							#       | cambie este numero para variar la longitud			##__7__##__START
    								for (0..5) { $string .= chr( int(rand(25) + 65) ); } print $string."\n";
    								#print "CHECK Access-Challenge:: Current User ".$p->attr('User-Name')." OTP: ".$usuarios{$p->attr('User-Name')}[0]." Time: ".$usuarios{$p->attr('User-Name')}[1]." Intentos: ".$usuarios{$p->attr('User-Name')}[2]."\n";
    								$usuarios{$p->attr('User-Name')}[2] = 0;
    								$usuarios{$p->attr('User-Name')}[0] = $string;
    								#crear tiempo de expiracion
    								my $time = time()+300;
    								$usuarios{$p->attr('User-Name')}[1] = $time;
##__8__##__START						#####CODIGO PARA ENVIAR SMS#####        				##__8__##__START
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
    								print "Access-Reject:: Current User ".$p->attr('User-Name')." Password y Telefono no corresponden\n";
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
    
    
