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

use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;

/**
 * Plugin install process
 *
 * @return boolean
 */
function plugin_siemsensors_install() {
   return true;
}

/**
 * Plugin uninstall process
 *
 * @return boolean
 */
function plugin_siemsensors_uninstall() {
   return true;
}

function plugin_siemsensors_pull_hostevents(int $hosts_id = -1) {
   
}

function plugin_siemsensors_poll_sensor(array $params) {
   if (!isset($params['sensor']) || !isset($params['service_ids'])) {
      return [];
   }

   switch ($params['sensor']) {
      case 'ping':
         return ping($params['service_ids']);
   }
}

function plugin_siemsensors_translateEventName(string $name) : string {
   $event_names = [
      'sensor_ping_ok'  => __('Ping OK', 'siemsensors'),
      'sensor_ping_error'  => __('Ping Failed', 'siemsensors'),
      'sensor_fault'  => __('Sensor fault'),
   ];

   if (array_key_exists($name, $event_names)) {
      return $event_names[$name];
   } else {
      return __($name, 'siemsensors');
   }
   
   return $name;
}

function plugin_siemsensors_translateEventProperties(array $properties) {
   $prop_names = [
      'packet_loss'  => __('Packet loss', 'siemsensors')
   ];

   foreach ($prop_names as $fieldname => $localname) {
      if (array_key_exists($fieldname, $properties)) {
         $properties[$fieldname]['name'] = $localname;
      }
   }
   
   return $properties;
}

function ping(array $service_ids) {
  $defparams = [
     'name_first'      => true,
  ];

  $hosts = [];

  foreach ($service_ids as $services_id) {
     $service = new SIEMService();
     if (!$service->getFromDB($services_id)) {
        return false;
     }

     if (isset($service->fields['sensor_params'])) {
        $sensor_params = json_decode($service->fields['sensor_params'], true);
     } else {
        $sensor_params = $defparams;
     }
     $sensor_params = array_replace($defparams, $sensor_params);
     $hosts_id = $service->fields['hosts_id'];
     $host = new SIEMHost();
     if (!$host->getFromDB($hosts_id)) {
        return [];
     }
     $hosttype = $host->fields['itemtype'];
     $host_item = new $hosttype();
     if (!$host_item->getFromDB($host->fields['items_id'])) {
        return [];
     }

     if ($sensor_params['name_first']) {
        $hosts[$services_id] = $host_item->fields['name'];
     } else {

     }
  }

  $results = tryPing($hosts);
  $eventdatas = [];
  foreach ($results as $services_id => $result) {
     if (!isset($result['_sensor_fault'])) {
        $eventdata = getPingEventData($services_id, $result);
     } else {
        $eventdata = null;
     }
     if ($eventdata != null) {
        $eventdatas[$services_id] = $eventdata;
     }
  }

  return $eventdatas;
}

function getPingEventData(int $services_id, array $ping_result) {
  $event = new SIEMEvent();

  $event_content = [];
   if (isset($ping_result['percent_loss']) && isset($ping_result['min']) &&
         isset($ping_result['avg']) && isset($ping_result['max']) && isset($ping_result['mdev'])) {
      $event_content['percent_loss'] = $ping_result['percent_loss'];
      $event_content['min'] = $ping_result['min'];
      $event_content['avg'] = $ping_result['avg'];
      $event_content['max'] = $ping_result['max'];
      $event_content['mdev'] = $ping_result['mdev'];
   } else {
      //Sensor parse error
      return [
         'name'            => 'sensor_ping_error',
         'status'          => SIEMEvent::STATUS_NEW,
         'significance'    => SIEMEvent::WARNING,
         'date'            => $_SESSION['glpi_currenttime'],
         'content'         => json_encode($event_content),
         '_sensor_fault'   => true
      ];
   }

   return [
      'name'      => 'sensor_ping_ok',
      'status'    => SIEMEvent::STATUS_NEW,
      'significance' => SIEMEvent::INFORMATION,
      'date'         => $_SESSION['glpi_currenttime'],
      'content'      => json_encode($event_content),
   ];
}

function tryPing(array $hosts, int $count = 5) : array {
  $results = [];
  $sub_processes = [];

  foreach ($hosts as $service_id => $host) {
     $result = [];
     $process = new Process(['/bin/ping', "-c $count", $host]);
     $process->run();
     $sub_processes[$service_id] = $process;
  }

  // Wait for pings to finish
  $done = true;
  do {
     foreach ($sub_processes as $process) {
        if ($process->isRunning()) {
           $done = false;
           break;
        }
     }
  } while (!$done);

  // Parse results
  foreach ($sub_processes as $service_id => $process) {
     $exitcode = $process->getExitCode();
     if (0 !== $exitcode) {
        $result = [
           '_sensor_fault'   => true,
           'exit_code'       => $exitcode,
           'error_msg'       => $process->getErrorOutput(),
        ];
        $results[$service_id] = $result;
        continue;
     }

     $pingresult = $process->getOutput();

     try {
        $outcome = $pingresult;

        if (preg_match('/(received, )(.*?)(packet)/', $outcome, $match) === 1) {
           $result['percent_loss'] = str_replace('%', '', trim($match[2]));
        } else {
           throw new RuntimeException('Malformed sensor output');
        }
        if (preg_match('/(rtt)(.*?)(=)(.*?)(ms)/', $outcome, $match) == 1) {
           $values = explode('/', trim($match[4]));
           $result['min'] = $values[0];
           $result['avg'] = $values[1];
           $result['max'] = $values[2];
           $result['mdev'] = $values[3];
           $results[$service_id] = $result;
        } else {
           throw new RuntimeException('Malformed sensor output');
        }
     } catch (RuntimeException $e) {
        $result = [
           '_sensor_fault'   => true,
           'exit_code'       => $exitcode,
           'error_msg'       => $process->getErrorOutput()
        ];
        $results[$service_id] = $result;
     }
  }

  return $results;
}