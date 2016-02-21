#!/usr/bin/perl -W

use Net::RawIP;
use Sys::Info;
   use Sys::Info::Constants qw( :device_cpu );
   my $info = Sys::Info->new;
   my $cpu  = $info->device('CPU');
   printf "cpu = %d", $cpu->count;
   my $cpu_str = sprintf("%d",$cpu->count);
  $n = Net::RawIP->new({
                        ip  => {
                                saddr => '192.168.86.128',
                                daddr => '192.168.0.1',
                                id=>33
                               },
                       
                        udp => {
                                source => 8080,
                                dest   => 9090,
                                data  => $cpu_str,
                               },
                       });
  $n->send(1,1);
