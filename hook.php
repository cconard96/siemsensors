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

function plugin_siemsensors_pull_serviceevents(int $services_id = -1) {
   
}

function plugin_siemsensors_translateEventName(string $name) : string {
   $event_names = [
      'Ping OK'  => __('Ping OK', 'siemsensors')
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