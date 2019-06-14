<?php

/*
 -------------------------------------------------------------------------
 SIEM Sensors plugin for GLPI
 Copyright (C) 2019 by Curtis Conard

 https://github.com/cconard96/siemsensors
 -------------------------------------------------------------------------

 LICENSE

 This file is part of SIEM Sensors.

 SIEM Sensors is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 SIEM Sensors is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with SIEM Sensors. If not, see <http://www.gnu.org/licenses/>.
 --------------------------------------------------------------------------
 */

class SIEMSensors_Sensors {

   /**
    * Attempts to ping a given host
    * 
    * @param type $hosts_id The ID of the monitored host
    * @param name_first Tries to ping the host's name first, and then the each of the IPs.
    *    If false, only the IPs are used.
    * @param type $safe If true, a forward and reverse DNS lookup must match up
    *    in addition to the ping succeeding. This is to ignore stale DNS entries when using DHCP.
    *    Example, a host is offline but another host has the same IP registered.
    *    Only used when pinging the hostname.
    */
   public static function ping(int $hosts_id, $name_first = true, $safe = false, $sensor_params = []) : bool {

      $host = new SIEMHost();
      if (!$host->getFromDB($hosts_id)) {
         return false;
      }
      $hosttype = $host->fields['itemtype'];
      $host_item = new $hosttype();
      if (!$host_item->getFromDB($host->fields['items_id'])) {
         return false;
      }

      if ($name_first) {
         $hostname = $host_item->fields['name'];
         if (($safe && self::dnsrecord_check($hostname)) || !$safe) {
            $ping_result = self::try_ping($hostname);
            if (isset($ping_result['status']) && $ping_result['status'] === 0) {
               self::log_pingresult($hosts_id, $ping_result);
               return true;
            }
         }
      }

      $ips = [];
      //TODO Finish
      return false;
   }

   private static function log_pingresult(int $hosts_id, array $ping_result, $suppress_good = true) : bool {
      $event = new SIEMEvent();
      $event_content = [
         'status' => $ping_result['status']
      ];
      if (isset($ping_result['status']) && $ping_result['status'] === 0) {
         if (isset($ping_result['percent_loss']) && isset($ping_result['min']) &&
               isset($ping_result['avg']) && isset($ping_result['max']) && isset($ping_result['mdev'])) {
            $event_content['percent_loss'] = $ping_result['percent_loss'];
            $event_content['min'] = $ping_result['min'];
            $event_content['avg'] = $ping_result['avg'];
            $event_content['max'] = $ping_result['max'];
            $event_content['mdev'] = $ping_result['mdev'];
         } else {
            //Sensor parse error
            return $event->add([
               'name'      => 'sensor_ping_error',
               'status'    => SIEMEvent::STATUS_NEW,
               'significance' => SIEMEvent::WARNING,
               'date'         => $_SESSION['glpi_currenttime'],
               'content'      => json_encode($event_content),
               'logger'       => 'siemsensors'
            ]);
         }

         if ($suppress_good && isset($ping_result['percent_loss']) && $ping_result['percent_loss']) {
            return true;
         }
         
         return $event->add([
            'name'      => 'sensor_ping_ok',
            'status'    => SIEMEvent::STATUS_NEW,
            'significance' => SIEMEvent::INFORMATION,
            'date'         => $_SESSION['glpi_currenttime'],
            'content'      => json_encode($event_content),
            'logger'       => 'siemsensors'
         ]);
      } else {
         // Host Unreachable
         return $event->add([
            'name'      => 'sensor_ping_bad',
            'status'    => SIEMEvent::STATUS_NEW,
            'significance' => SIEMEvent::EXCEPTION,
            'date'         => $_SESSION['glpi_currenttime'],
            'content'      => json_encode($event_content),
            'logger'       => 'siemsensors'
         ]);
      }
   }

   private static function try_ping($host, int $count = 5) : array {
      $result = [];
      $pingresult = exec("/bin/ping -c {$count} $host", $outcome, $status);
      $result['status'] = $status;
      if (0 !== $status) {
         return $result;
      }

      try {
         $outcome = implode('\n', $outcome);
         if (preg_match('/(received, )(.*?)(packet)/', $outcome, $match) == 1) {
            $result['percent_loss'] = str_replace('%', '', trim($match[2]));
         } else {
            throw RuntimeException('Malformed sensor output');
         }
         if (preg_match('/(rtt)(.*?)(=)(.*?)(ms)/', $outcome, $match) == 1) {
            $values = explode('/', trim($match[4]));
            $result['min'] = $values[0];
            $result['avg'] = $values[1];
            $result['max'] = $values[2];
            $result['mdev'] = $values[3];
         } else {
            throw RuntimeException('Malformed sensor output');
         }
         return $result;
      } catch (RuntimeException $e) {
         $result['error'] = $e;
         return $result;
      }
   }

   private static function dnsrecord_check(string $hostname) : bool {
      $hostname = strtolower($hostname);
      $forward_records = dns_get_record($hostname, [DNS_A, DNS_AAAA]);
      foreach ($forward_records as $record) {
         if (!isset($record['ip'])) {
            continue;
         }
         $ip = $record['ip'];
         $lookup_host = gethostbyaddr($ip);
         if ($lookup_host && $hostname === strtolower($lookup_host)) {
            return true;
         }
      }
   }
}