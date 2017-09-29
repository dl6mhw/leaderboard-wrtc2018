<?php
  include "sniffer_status.php";
  print $last_seq_nr;
  
  $file = '/home/pi/sniff/udp.log';
  $file_handle = fopen($file, 'r');
  $msg='';
  while (!feof($file_handle)) {
    $line = fgets($file_handle);
    if (preg_match('/^\[([0-9]+):/',$line,$m)) {
      if ($m[1]>$last_seq_nr) {
       #print "-->$m[1]<--\n";
       $last_seq_nr=$m[1];
       $msg.=$line;
      } 
    }
  }
 
 print $msg;
  $post = curl_init();
  $url='http://dcl.darc.de/~dl6mhw/leaderboard/service.php';
   curl_setopt($post, CURLOPT_URL, $url);
   curl_setopt($post, CURLOPT_POST, 1);
   curl_setopt($post, CURLOPT_POSTFIELDS, "msg=$msg");
   curl_setopt($post, CURLOPT_RETURNTRANSFER, 1);
   $result = curl_exec($post);
   curl_close($post);

  fclose($file_handle);
  #finally writh seq-number 
  $data="<?php\n".'$last_seq_nr='.$last_seq_nr."\n ?>";
  file_put_contents ( 'sniffer_status.php' , $data)

?>