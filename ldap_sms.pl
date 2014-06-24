#!/usr/local/bin/perl -w

    use Net::LDAP;
    
    
  my $ldap = Net::LDAP->new( 'ldaps://10.204.160.10' ) or die "$@";
  my $mesg = $ldap->bind( 'mgiller@tmoviles.com.ar',
                       password => '3z3quiel782300='
                     );
   my $base = "dc=tmoviles,dc=com,dc=ar";
   my $attrs = [ 'cn','mail','mobile' ];
   $mesg = $ldap->search ( base    => "$base",
                                scope   => "sub",
                                filter  => "samAccountName=mgiller",
                                attrs   =>  $attrs
                              );
                      
    print "ERROR: ".$mesg->error." MSG: ".$mesg->code."\n";
    my $entry;
 foreach $entry ($mesg->entries) { 
    print "DN=".$entry->dn()."\n";
    if($entry->exists("mobile"))
    {
      print "OK\n";
    }else{
       print "No PHONE\n";
   }
  print "Phone: ".$entry->get_value("mobile")."\n";
 
   
   }
   
   $ldap->unbind;