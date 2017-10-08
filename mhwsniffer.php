<?php
/*
   PHP Packet Sniffer based on David Eder 2006
   Test sniffing, filtering for leaderboard 
   RaspberryPi - Rasbian Stretch
    - listen UDP-Broadcast
    - print to STDOUT
    - start: sudo php mhwsniffer.php > /tmp/udp.log 
   DL6MHW - Oct 2017 
*/
  define('SOL_ICMP', 1);

  #Sniffer status only contains a sequence number to reduce sync later
  include "sniffer_status.php";

  $sniffer = new sniffer($last_seq_nr);
  $sniffer->add_protocol(SOL_UDP, 'print_r');
  $sniffer->listen();
 
  if(!defined('SOL_ICMP')) define('SOL_ICMP', 1);
  class sniffer
  {
    var $addr;
    var $sockets = array();
    var $callback = array();
    var $seq_nr = 0;
    function sniffer($snr)
    {
      $this->seq_nr=$snr;
      $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
      socket_connect($socket, '64.0.0.0', 0);
      socket_getsockname($socket, $this->addr, $port);
      socket_close($socket);
      $this->callback['default'] = 'print_r';
    }

    function add_protocol($protocol, $callback)
    {
      if($sock = @socket_create(AF_INET, SOCK_RAW, $protocol))
      {
        socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1);
        $this->sockets[] = $sock;
        $this->callback[$protocol] = $callback;
        return true;
      }
      return false;
    }

    function listen()
    {
      $w = $e = NULL;
      do
      {
        $active = $this->sockets;
        socket_select($active, $w, $e, NULL);
        foreach($active as $sock)
        {
          $ip = array();
          if(socket_recv($sock, $packet, 65536, 0))
          {
            #print_r($ip);
            #print "$packet\n";
            $this->decode($packet);
          }
        }
      } while(true);
    }

    function decode($packet)
    {
      // decode ip header
      # MHW: this ist the original code analyzing the ip header
      $ip['version'] = ord($packet{0}) >> 4;
      $ip['ihl'] = ord($packet{0}) & 0xf;
      $ip['tos'] = ord($packet{1});
      $ip['length'] = (ord($packet{2}) << 8) + ord($packet{3});
      $ip['id'] = (ord($packet{4}) << 8) + ord($packet{5});
      $ip['flags'] = ord($packet{6});
      $ip['fragment_offset'] = ord($packet{7});
      $ip['ttl'] = ord($packet{8});
      $ip['protocol'] = ord($packet{9});
      $ip['checksum'] = (ord($packet{10}) << 8) + ord($packet{11});
      $ip['source'] = ord($packet{12}) . '.' . ord($packet{13}) . '.' . ord($packet{14}) . '.' . ord($packet{15});
      #if ($ip['source']='192.168.1.35') break;
      $ip['dest'] = ord($packet{16}) . '.' . ord($packet{17}) . '.' . ord($packet{18}) . '.' . ord($packet{19});
      $payload = substr($packet, $ip['ihl'] << 2);

      # MHW: here all other (not UDP) protocols are removed 
      switch($ip['protocol'])
      {
        case SOL_UDP:
          # MHW: this is the original code analyzing udp header
          $ip['udp']['src_port'] = (ord($payload{0}) << 8) + ord($payload{1});
          $ip['udp']['dst_port'] = (ord($payload{2}) << 8) + ord($payload{3});
          $ip['udp']['length'] = (ord($payload{4}) << 8) + ord($payload{5});
          $ip['udp']['checksum'] = (ord($payload{6}) << 8) + ord($payload{7});
          $z = getservbyport($ip['udp']['src_port'], 'udp');
          if(!$z) getservbyport($ip['udp']['dst_port'], 'udp');
          if(!$z) $z = 'unknown';
          # MHW: if port ist 9871 (Wintest default broadcast) and specific package 
          # (Wintest only) write package to STDOUT
          if ($ip['udp']['src_port']=='9871' and (
            # real QSOs - most important
            preg_match('/ADDQSO:/',substr($payload, 8)) or
            # QSO Update  
            preg_match('/UPDQSO:/',substr($payload, 8)) or
            # to generate testdata packet spots (wtdxtelnet) simulate QSO 
            preg_match('/RCVDPKT:/',substr($payload, 8))  
          )) {          
            print "[".($this->seq_nr++).":".time()."]".substr($payload, 8)."\n";
            /*
 		        $ip['udp'][$z] = "\n" . $this->hexdump(substr($payload, 8));
                if(is_callable($this->callback[SOL_UDP])) $this->callback[SOL_UDP]($ip);
            */    
            }
          break;
        default:
          $ip[getprotobynumber($ip['protocol'])] = "\n" . $this->hexdump($payload);
          if(is_callable($this->callback['default'])) $this->callback['default']($ip);
          break;
      }
    }

    # MHW: not used
    function full_sniffer($callback)
    {
      foreach(file('/etc/protocols') as $line)
      {
        list($line) = explode('#', $line);
        $line = trim($line);
        if($line == '') continue;
        $line = strtr($line, "\t", ' ');
        while(strpos($line, '  ')) $line = str_replace('  ', ' ', $line);
        list($name, $number) = explode(' ', $line);
        $this->add_protocol($number, $callback);
      }
    }

    # MHW: nice original code, helful for reengineering 
    function hexdump($data)
    {
      $ret = '';
      $ascii = '';
      for($i = 0; $i < strlen($data); $i++)
      {
        $c = ord($data{$i});
        if($c > 31 && $c < 128) $ascii .= $data{$i}; else $ascii .= '.';
        if($i % 16 == 0) $ret .= ' ';
        elseif($i % 8 == 0) $ret .= '   ';
        $ret .= ' ' . str_pad(dechex($c), 2, '0', STR_PAD_LEFT);
        if(($i + 1) % 16 == 0)
        {
          $ret .= "\t$ascii\n";
          $ascii = '';
        }
      }
      while($i % 16 != 0)
      {
        if($i % 8 == 0) $ret .= '    ';
        $ret .= '   ';
        $i++;
      }
      return "$ret\t$ascii\n";
    }
  }
?>
