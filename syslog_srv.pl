#
#
#
#     	Syslog server service.
#
#

use strict;
use warnings;
use IO::Socket;
use IO::Socket::SSL;
use threads;
use POSIX qw(strftime);
use Getopt::Long; 


#rsyslog options variables.
my $o_help = undef;
my $o_udp = undef;
my $o_tcp = undef;
my $o_tls = undef;
my $o_syslog_port = 514;
my $o_syslog_tls_port = 1514;
my $o_ssl_cert = "";
my $o_ssl_key = "";

#rsyslog server variables.
my $syslog_port = 514;
my $syslog_tls_port = 1514;
my $ssl_crt = "../ssl/logserver.crt";
my $ssl_key = "../ssl/logserver.key";
my $MAXLEN = 4096;

#data process variables.
my @log_cat =(
          "kern.log",
          "user.log",
          "mail.log",
          "daemon.log",
          "auth.log",
          "syslog.log",
          "ipr.log",
          "uucp.log",
          "clockd.log",
          "authpriv.log",
          "ftp.log",
          "ntp.log",
          "audit.log",
          "alert.log",
          "cron.log",
          "local0.log",
          "local1.log",
          "local2.log",
          "local3.log",
          "local4.log",
          "local5.log",
          "local6.log",
          "local7.log"
);
my @log_severity = (
        "Emergency",
        "Alert",
        "Critical",
        "Error",
        "Warning",
        "Notice",
        "Informational",
        "Debugging"
);
my $path = "/home/tchenu/log_m/module";





#
#Setup the options.
#
sub get_options {
	GetOptions(
		"h"=>\$o_help, "help"=>\$o_help,
		"u"=>\$o_udp,  "udp-only"=>\$o_udp,
		"t"=>\$o_tcp, "tcp-only"=>\$o_tcp,
		"s"=>\$o_tls, "tls-only"=>\$o_tcp,
		"p"=>\$o_syslog_port,"port"=>\$o_syslog_port,
		""	

	);
}


#
# information process part.
#

sub get_date {
	return strftime "%e-%m-%Y",localtime;
}

#Cut the msg code in category code and severity code.
sub syslog_code_cutter {
  my $code = $_[0];
  my $code_bin = sprintf("%08b",$code);
  my ($cat_bin,$severity_bin) = $code_bin =~ /^(\d{5})(\d{3})/;
  my $code_cat = oct("0b$cat_bin");
  my $code_serverity = oct("0b$severity_bin");
  return ($log_cat[$code_cat],$log_severity[$code_serverity]);
}

#Setup the dir
sub make_dir {
  my $dirname = $_[0];
  unless(-e $dirname){
    printf "[*] Creating the directory : $dirname\n";
    system("mkdir $dirname");
  }
}
sub syslog_setup_dir {
  my ($hostname,$date) = @_;
  my $path_log = $path;
  $path_log = "$path_log/../centralized_logs";
  make_dir($path_log);
  $path_log = "$path_log/$hostname";
  make_dir($path_log);
  $path_log = "$path_log/$date";
  make_dir($path_log);
  return $path_log;
}

#Put the syslog msg in file
sub syslog_msg_write {
   my ($filename,$msg) = @_;
   open(my $FH , ">>", $filename);
   printf $FH "$msg";
   close($FH);

}

#Extract data with regex <code>Month day time hostname msg_data return array
sub syslog_regex_process {
        my $data = $_[0];
        my @regex_data = $data =~ /^<(\d+)>(\S*) (\S*) (\S*) (\S*) (.*)/;
        return @regex_data;
}

sub syslog_process {
    my $syslog_data = $_[0];
    my @syslog_array = syslog_regex_process($syslog_data);
    my $path_log = syslog_setup_dir($syslog_array[4],get_date());
    my ($code_cat, $code_severity) = syslog_code_cutter($syslog_array[0]);
    syslog_msg_write("$path_log/$code_cat","[$code_severity] $syslog_data");
}

#
# server part.
#

#udp service
sub syslog_transport_udp_server {
        my ($socket,$buffer,$client);
        $socket = IO::Socket::INET->new(
                      LocalPort=>$syslog_port,
                      Proto => "udp"
        )or die "[-] echec $!\n";
        while($client = $socket->recv($buffer,$MAXLEN,0)){
            my ($port,$ipaddr) = sockaddr_in($socket->peername);
            $ipaddr = inet_ntoa($ipaddr);
            printf "[*] Accepted connection from $ipaddr:$port\n";
            syslog_process($buffer);
        }
        close($socket);
        threads->exit();

}

#tcp service
sub syslog_transport_tcp_server {
      my ($socket,$client_socket);
      my @clients = ();
      $socket =  IO::Socket::INET->new(
                      LocalPort=>$syslog_port,
                      Proto => "tcp",
                      Reuse => 1,
                      Listen => SOMAXCONN
      )or die "[-] echec $!\n";
      while(1){
        my $client_socket = $socket->accept();
        push(@clients,threads->create(\&handle_connection,$client_socket));
        foreach my $client_thread (@clients){
              if($client_thread->is_joinable()){
                  $client_thread->join();
              }
        }
      }
      close($socket);
      threads->exit();
}

#tls service
sub syslog_transport_tls_server {
        my($tls_socket,$tls_client_socket);
        my @tls_clients = ();
        $tls_socket = IO::Socket::SSL->new(
                  LocalPort=>$syslog_tls_port,
                  Reuse => 1,
                  Listen => SOMAXCONN,
                  SSL_cert_file => $ssl_crt,
                  SSL_key_file => $ssl_key
        )or die "[-] echec $!\n";
        while(1){
          $tls_client_socket = $tls_socket->accept();
          push(@tls_clients,threads->create(\&handle_connection,$tls_client_socket));
          foreach my $client_thread (@tls_clients){
                if($client_thread->is_joinable()){
                    $client_thread->join();
                }
          }
        }
        close($tls_socket);
        threads->exit();
}

#handle tcp and tls connection
sub handle_connection {
        my ($client_socket) = @_;

        my ($port, $ipaddr) = sockaddr_in($client_socket->peername);
        my $host = inet_ntoa($ipaddr);
        printf "[*] Accepted connection at $host:$port\n";
        while(my $buffer = <$client_socket>){
                syslog_process($buffer);
        }
        $client_socket->shutdown(2);
        threads->exit();
}

#
# main part.
#
sub main{
   my @service = ();
   push(@service , threads->create(\&syslog_transport_udp_server));
   push(@service , threads->create(\&syslog_transport_tcp_server));
   push(@service , threads->create(\&syslog_transport_tls_server));
   while(1){
     foreach (@service){
       if($_->is_joinable()){
         $_->join();
       }
     }
   }
}
main();
