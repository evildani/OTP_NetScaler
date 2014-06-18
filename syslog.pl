use Sys::Syslog;                        # all except setlogsock()
use Time::HiRes;
use Log::Dispatch;    #no esta
   # use Sys::Syslog qw(:standard :macros);  # standard functions & macros
    openlog("OTP.","ndelay,pid", "local0");    # don't forget this
    syslog("info", "THIS IS A TEST");
    #$oldmask = setlogmask($mask_priority);
    closelog();
    
 #   use Log::Log4perl;
 # Log::Log4perl->init("log.conf");
  #  my $log = Log::Log4perl->get_logger("My::MegaPackage");

   #     $log->debug("Debug message");
    #    $log->info("Info message");
     #   $log->error("Error message");
