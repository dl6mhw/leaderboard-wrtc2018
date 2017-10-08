<?php
/*
  DL6MHW, Oct 2017
  - analyze and sync UDP date from /tmp/udp.log to Webservice
  - webservice via on http://dcl.darc.de/~dl6mhw/leaderboard/service.php
  /usr/bin/php /home/pi/sniff/sync_watch.php
  ToDo: 
  - UpdateQSO
  - more log program formats
  - watchdog functionality for sniffer
  - clean/switch big files especially udp.log
  - and/or some complete log transfer 
  - some remote control - web based alive check (stop everthing when webserver is not visible)
  - flexible configuration/ filenames etc. 
*/
  #read the sequence number - only send new QSOs 
  include "/home/pi/sniff/sniffer_status.php";
  print $last_seq_nr;

  $call1='DL6MHW';
  $file = '/tmp/udp.log';
  $file_handle = fopen($file, 'r');
  $msg='';
  while (!feof($file_handle)) {
    $line = fgets($file_handle);
    if (preg_match('/^\[([0-9]+):/',$line,$m)) {
      # only new records
      if ($m[1]>$last_seq_nr) {
       #print "-->$m[1]<--\n";
       $last_seq_nr=$m[1];
       $msg.=decode($line);          
      } 
    }
  }
 
  print "MSG:Body:\n$msg\n";
  
  # Prepare CURL request to Web-Serivce, just with POST
  $post = curl_init();
  $url='http://dcl.darc.de/~dl6mhw/leaderboard/service.php';
   curl_setopt($post, CURLOPT_URL, $url);
   curl_setopt($post, CURLOPT_POST, 1);
   curl_setopt($post, CURLOPT_POSTFIELDS, "msg=$msg");
   curl_setopt($post, CURLOPT_RETURNTRANSFER, 1);
   $result = curl_exec($post);
   curl_close($post);
   fclose($file_handle);
  
  #finally writh seq-number, not the best idea to use in php file 
  $data="<?php\n".'$last_seq_nr='.$last_seq_nr."\n ?>";
  file_put_contents ( 'sniffer_status.php' , $data);


# Decode just splits the MSG and assaign the DATA and generate a server package
function decode($raw) {
# some wtdxtelnet spots - simulatation of QSO data
if (preg_match('/RCVDPKT:(.+)/',$raw,$m)) {
      $pkg=$m[1];
      $fields=preg_split('/\s+/',$pkg);
      #print_r($fields);
      if ($fields[3]!='"DX') return '';
      $call1=$fields[5];
      $call2=$fields[7];
      $qrg=$fields[6]*10;
      $band=qrg2band($qrg);
      $utime=time();
      $txmode='S';
      if ($qrg%2==1) $txmode='C';
      $values="RCVDPKT,$call1,$call2,$qrg,$band,$utime,$txmode";
      print "$values\n";
      return "$values\n";
    }
# a real wintest QSO package, but call1 is fiexed DL6MHW
# some " have to be removed 
if (preg_match('/ADDQSO:(.+)/',$raw,$m)) {
      $pkg=$m[1];
      $pkg=preg_replace('/"/','',$pkg);
      $fields=preg_split('/\s+/',$pkg);
      #print_r($fields);
      # this shut be some real Call or site ID, transformation ID-Call can be
      # implemented on server side
      $call1='DL6MHW';
      $call2=$fields[12];
      $qrg=$fields[4];
      $band=qrg2band($qrg);
      $utime=$fields[3];
      $txmode='S';
      if (substr($fields[14],0,3)=='599') $txmode='C';
      $values="ADDQSO,$call1,$call2,$qrg,$band,$utime,$txmode";
      print "$values\n";
      return "$values\n";
    }
# still no UPDATEQSO   
    return NULL;
}

function qrg2band($qrg) {
  if ($qrg <35000) return 160;
  if ($qrg <70000) return 80;
  if ($qrg <140000) return 40;
  if ($qrg <210000) return 20;
  if ($qrg <280000) return 15;
  return 10;
} 


?>