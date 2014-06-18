#!/usr/local/bin/perl -w

    use Net::LDAP;
    
    
  my $ldap = Net::LDAP->new( '192.168.254.133' ) or die "$@";
  my $mesg = $ldap->bind( 'cn=admin',
                      password => 'ttikyy09'
                    );

   my $base = "dc=test, dc=com";
   my $attrs = [ 'cn','mail','TelephoneNumber' ];
   $mesg = $ldap->search ( base    => "$base",
                                scope   => "sub",
                                filter  => "sn=castro",
                                attrs   =>  $attrs
                              );
                      
    print "MSG: ".$mesg->code."\n";
    my $entry;
 foreach $entry ($mesg->entries) { 
    print "DN=".$entry->dn()."\n";
    if($entry->exists("TelephoneNumber"))
    {
      print "OK\n";
    }else{
       print "No PHONE\n";
   }
  print "Phone: ".$entry->get_value("telephoneNumber")."\n";
 
   
   }
   