use LWP::UserAgent; 
use HTTP::Request::Common qw{ POST };
#my $data = "RECIPIENT=".$telefono."&&TEXT=".$token."&SOURCE_ADDR=314";#
my $data = "RECIPIENT=1159274817&TEXT=HOLA MARTIN&SOURCE_ADDR=314";
my $uri = 'http://10.244.44.21/cgi-bin/smspost.cgi';
my $ua  = LWP::UserAgent->new();

my $request = POST $uri,
	Content => [
		RECIPIENT => "1159274817",
		TEXT => "HOLA",
		SOURCE_ADDR=> "314"
	];
 

$request->header('Content-Type','application/x-www-form-urlencoded');
#$request->header('Accept', 'text/html,application/xhtml');
#$request->header('User-Agent',$user_agent);
$request->protocol('HTTP/1.0');
my $post_data = "RECIPIENT=1159274817&TEXT=HOLA%20MARTIN&SOURCE_ADDR=314";
print "Lenth ".length($post_data);
#$request->content($post_data);
#print $request->as_string();
#make the actual POST
print "POST as String:\n ".$request->as_string."\n\nSending...";
my $response = $ua->request($request) or die "error\n";
if ($response->is_success) {
    my $message = $response->decoded_content;
    print "Received reply: $message\n";
}
else {
    print "HTTP POST error code: ", $response->code, "\n";
    print "HTTP POST error message: ", $response->message, "\n";
}