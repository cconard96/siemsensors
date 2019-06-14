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

define('PLUGIN_SIEMSENSORS_VERSION', '1.0.0');

/**
 * Init hooks of the plugin.
 * REQUIRED
 *
 * @return void
 */
function plugin_init_siemsensors() {
   global $PLUGIN_HOOKS;
   $PLUGIN_HOOKS['csrf_compliant']['siemsensors'] = true;
   $PLUGIN_HOOKS['siem_sensors']['siemsensors'] = [
      'ping' => [
         'name'         => __('Ping'),
         'check_mode'   => SIEMService::CHECK_MODE_ACTIVE,
      ]
   ];
}


/**
 * Get the name and the version of the plugin
 *
 * @return array
 */
function plugin_version_siemsensors() {
   return [
      'name'           => 'SIEM Sensors',
      'version'        => PLUGIN_SIEMSENSORS_VERSION,
      'author'         => '<a href="http://www.github.com/cconard96">Curtis Conard</a>',
      'license'        => 'GPL 2.0+',
      'homepage'       => 'http://www.github.com/cconard96',
      'requirements'   => [
         'glpi' => [
            'min' => '10.0.0',
         ]
      ]
   ];
}

/**
 * Check prerequisites before install
 *
 * @return boolean
 */
function plugin_siemsensors_check_prerequisites() {
   $version = preg_replace('/^((\d+\.?)+).*$/', '$1', GLPI_VERSION);
   if (version_compare($version, '10.0.0', '<')) {
      echo "This plugin requires GLPI >= 10.0.0";
      return false;
   }
   return true;
}

/**
 * Check configuration process
 *
 * @param boolean $verbose Whether to display message on failure. Defaults to false
 *
 * @return boolean
 */
function plugin_siemsensors_check_config($verbose = false) {
   if (true) { // Your configuration check
      return true;
   }

   if ($verbose) {
      echo __('Installed / not configured', 'siemsensors');
   }
   return false;
}