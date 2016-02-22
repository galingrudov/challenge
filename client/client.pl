#!/usr/bin/perl -W
use strict;
use warnings;
use Net::RawIP;
use Sys::Info;
use Sys::Info::Constants qw( :device_cpu );
use IO::Socket;
# menu function 
  sub help 
  {
    print "\n client.pl can accept up to three arguments:\n" ,
          " Ip: destination ip in dot format for exml. 192.168.1.1",
          " dest port: \n",
          " local port: if not specified local port will be the same as destination port\n";
  }

# take number of arguments
  my $num_arg = $#ARGV +1;
#collect arguments
  (my $dest, my $dst_port, my $src_port)= @ARGV;

# at least two arguments are expected
  if ($num_arg < 2)
  {
     print "wrong number of arguments";
     help();  
     exit;
  }
  elsif ($num_arg == 2)
  {
# source port is optional. If source port is not added  we will use the destination port as a sorse
    $src_port = $dst_port;
  }




   my $info = Sys::Info->new;
   my $cpu  = $info->device('CPU');
   printf "cpu count = %d\n", $cpu->count;
   my $cpu_str = sprintf("%d",$cpu->count);
   my $n = Net::RawIP->new({
                        ip  => {
#                                saddr => ',
                                daddr => $dest,
                                id=>33
                               },
                       
                        udp => {
                                source => $src_port,
                                dest   => $dst_port,
                                data  => $cpu_str,
                               },
                       });
  $n->send(1,1);

# get eth0 information using unix command 'ifconfig'
  my $IP_eth0 = `ifconfig eth0`;
#catch the adress the result is in the first catch ->$1
  $IP_eth0 =~ /.*inet addr:(.*)  Bcast:/;
  $IP_eth0 = $1;


# Server side information
  server($IP_eth0, $src_port);
  sub server
  {
# copy values of @_ in local variables
# Within a subroutine the array @_ contains the parameters passed to that subroutine. 
    my ($host,$listen_port)= @_;

    my $protocal        = 'udp';
    my $received_data   = undef;

# Creating UDP socket for server
    my $server = IO::Socket::INET->new (
       LocalHost   => $host,
       LocalPort   => $listen_port,
       Proto       => $protocal,
       Type        => SOCK_DGRAM,
       Timeout     => 10000
    ) or die "Socket could not be created, failed with error $!\n";

   print "Waiting for client connection on host $host on port $src_port\n";


   for(my $i =0;$i< $cpu->count;++$i)
   {
     $server->recv($received_data, 1024);
     my $peer_address = $server->peerhost();
     my $peer_port    = $server->peerport();
     my $sock_port    = $server->sockport();
     print "Message was received from: $peer_address,to port:$sock_port, data: $received_data\n";
   }

   print "Closing socket...\n";
   $server->close();
  }
