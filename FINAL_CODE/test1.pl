#!/usr/bin/perl

# usage: test.pl topFile command inf

# supported commands: ping, tr, web, unreach, log



#@allinf = ('v1-eth0', 'v2-eth1', 'v3-eth2', 'app1', 'app2');
@allinf = ("app1", "eth0", "eth1", "eth2", "app2");
# ping 10 times
$ping = 'ping -c 10';
# ping only once
$ping30 = 'ping -c 30';
# traceroute, min TTL 10, max TTL 20.
$tr = 'traceroute -n -f 10 -m 20 -N 1 -q 1';

$topFile = shift @ARGV;
open(INF, "< $topFile") || die("cannot open topology file!\n");
$n = 0; 
$max = scalar(@allinf);
while($line = <INF>) {
    while ($line =~ s/(\d+\.\d+\.\d+\.\d+)//) {
        $addr{$allinf[$n]} = $1;
        $n++;
        last if($n == scalar(@allinf));
    }
    last if($n == scalar(@allinf));
}
die("not enough IPs\n") if ($n != $max);


$command = shift @ARGV;

if($ARGV[0] eq 'all') {
    if($command eq 'ping' || $command eq 'tr') {
        @ifs = @allinf;
    }
    elsif ($command eq 'web' || $command eq 'unreach') {
        @ifs = ("app1", "app2");
    }
} else {
    @ifs = @ARGV;
}
#print $command, "\n", @ifs, "\n"; exit;

foreach $f(@ifs) {
    $ip = $addr{$f};
    if($command eq 'ping') {
        print "ping $f 10 times: ";
        $ret = `$ping $ip`;
        if($ret =~ /(\d+)\% packet loss/) {;
            print 100-$1, "%\n";
        } else {
            print $ret;
        }
    }

    if($command eq 'tr') {
        print "traceroute $f: ";
        $ret = `$tr $ip | grep $ip | grep -v traceroute`;
        if($ret =~ /$ip/) {
            print "SUCCEED\n$ret\n";
        } else {
            print "failed:\n$ret\n";
        }
    }

    if($command eq 'web') {
#        `/bin/rm -f  index.html Earl_Johnson--Aint_Nobodys_Business.mp3`;
#        `wget -t 0 "http://$ip/index.html" `;
        `wget "http://$ip" -O /dev/null `;
        `wget "http://$ip/big.jpg" -O /dev/null `;
#        `/bin/rm -f index.html Earl_Johnson--Aint_Nobodys_Business.mp3`;
#    `/bin/rm -f congrats.jpg strong_bad_natl_anthem.mp3`;
#    `wget -t 0 -c http://$inf{'app1'}/congrats.jpg`;
#    `wget -c http://$inf{'app1'}/strong_bad_natl_anthem.mp3`;
#    `/bin/rm -f congrats.jpg strong_bad_natl_anthem.mp3`;
    }

#if($command eq 'ftp') {
#    `/bin/rm -f sbnatan.mp3`;
#    `wget -t 0 -c "ftp://$inf{'app1'}/pub/sbnatan.mp3" `;
#    `/bin/rm -f sbnatan.mp3`;
#}
}

#if($command eq 'log') {
#    $ip = $addr{"app1"};
#    print "Make sure you've started the router with logging turned on by -l\n";
#    print "sleeping for 30 seconds...\n";
#    sleep 30;
#    `/bin/rm -f  index.html`;
#    `wget "http://$ip/index.html" `;
#    print "sleeping for 20 seconds...\n";
#    sleep 20;
#    `/bin/rm -f  index.html`;
#    `wget "http://$ip/index.html" `;
#    `/bin/rm -f  index.html`;
#}

if($command eq 'unreach') {
    $ip = $addr{"app1"};
    print "Make sure you've started the router with modified rtable\n";
    print "ping $ip, taking more than 30 seconds: ";
    $ret = `$ping30 $ip`;
    if($ret =~ /Destination Host Unreachable/i) {
        print "Received ICMP Host Unreachable\n";
    } else {
        print "Error\n";
        print $ret;
    }
# making TCP connection to eth0
    $ip = $addr{"eth0"};
    `wget --connect-timeout=2 --tries=1 http://$ip`;
}
      
