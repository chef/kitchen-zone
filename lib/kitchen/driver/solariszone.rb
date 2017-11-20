# -*- encoding: utf-8 -*-
#
# Author:: Scott Hain (<shain@getchef.com>)
#
# Copyright (C) 2015, Scott Hain
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "shellwords"
require "unix_crypt"

module Kitchen

  module Driver

    class SolarisZone # rubocop:disable Metrics/ClassLength
      attr_accessor :hostname
      attr_accessor :username
      attr_accessor :password
      attr_accessor :global_zone
      attr_accessor :name
      attr_accessor :brand
      attr_accessor :ip
      attr_reader :solaris_version

      def initialize(logger = nil)
        @logger = logger || ::Logger.new(STDOUT)
      end

      def create(master_zone)
        raise Exception, "Can not create global zones" if global?

        generate_hostname
        create_zonecfg
        create_zone
        # create_sc_profile if global_zone.solaris_version == "11"
        create_sc_profile if brand == "solaris"
        install_zone(master_zone.name)
        create_sysidcfg if brand != "solaris"
        boot_zone
        configure_network
        configure_ssh
      end

      def destroy
        raise Exception, "Can not destroy global zones" if global?
        return if !exists?

        generate_hostname
        return_value = zone_connection.exec("zoneadm -z #{name} halt")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        return_value = zone_connection.exec("zoneadm -z #{name} uninstall -F")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        return_value = zone_connection.exec("zonecfg -z #{name} delete -F")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
      end

      def exists?
        raise Exception, "Global zones always exist" if global?
        return_value = zone_connection.exec("zoneadm -z #{name} list")
        if return_value[:stdout].eql? name
          true
        else
          false
        end
      end

      def find_version
        return_value = zone_connection.exec("uname -r")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        @solaris_version = return_value[:stdout].split(".")[1]
      end

      def global?
        global_zone.nil?
      end

      def halt
        raise Exception, "Can not halt global zones" if global?
        logger.debug("[SolarisZone] Halting zone #{@name}")
        return_value = zone_connection.exec("zoneadm -z #{@name} halt")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
      end

      def network_device
        return_value = zone_connection.exec("ifconfig -a | grep IPv4 | cut -d: -f1 | uniq | grep -v lo | grep 0")
        if return_value[:exit_code] == 0
          return return_value[:stdout]
        else
          raise Exception, "Could not execute ifconfig on remote host"
        end
      end

      def running?
        return_value = zone_connection.exec("zoneadm -z #{@name} list -p")
        if return_value[:exit_code] == 0
          zone_state = return_value[:stdout].split(/:/)[2]
          if "running" == zone_state
            true
          else
            false
          end
        else
          raise Exception, return_value[:stdout]
        end
      end

      def sever
        zone_connection.shutdown unless zone_connection.nil?
      end

      def verify_connection
        return_value = zone_connection.exec("")
        return_value[:exit_code]
      rescue SocketError
        logger.error "[SolarisZone] Error connecting to #{@hostname}"
        return 1
      ensure
        sever
      end

      def zone_connection
        opts = Hash.new
        opts[:logger] = logger
        if global?
          hostname = @hostname
          username = @username
          opts[:password] = @password
        else
          hostname = @global_zone.hostname
          username = @global_zone.username
          opts[:password] = @global_zone.password
        end

        @zone_connection ||= SSHZone.new(hostname, username, opts)
      end

      private

      attr_reader :logger

      def boot_zone
        logger.debug("[SolarisZone] Booting zone #{@name}")
        return_value = zone_connection.exec("zoneadm -z #{@name} boot")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        waiting_for_ssh = true
        waiting_too_damn_long = 0
        logger.debug("[SolarisZone] Waiting for SSH service to come up on #{@name}")
        while waiting_for_ssh && waiting_too_damn_long < 10
          return_value = zone_connection.exec("zlogin #{@name} \"svcs -v | grep ssh | grep online 2>&1 > /dev/null\"")
          if return_value[:exit_code] == 0
            waiting_for_ssh = false
          else
            waiting_too_damn_long += 1
            sleep 10
          end
        end
      end

      def create_sc_profile
        return_value = zone_connection.exec("echo #{sc_profile} > /tmp/#{@name}_sc_profile.xml")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
      end

      def create_sysidcfg
        return_value = zone_connection.exec("echo #{sysidcfg} > /zones/#{@name}/root/etc/sysidcfg")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
      end

      def create_zone
        logger.debug("[SolarisZone] Creating zone #{@name}")
        return_value = zone_connection.exec("zonecfg -z #{@name} -f /tmp/#{@name}.cfg")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
      end

      def create_zonecfg
        case brand
        when "native"
          return_value = zone_connection.exec("echo #{zone_cfg_10} > /tmp/#{@name}.cfg")
          raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        when "solaris"
          return_value = zone_connection.exec("echo #{zone_cfg_11} > /tmp/#{@name}.cfg")
          raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        when "solaris10"
          return_value = zone_connection.exec("echo #{zone_cfg_branded} > /tmp/#{@name}.cfg")
          raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        else
          raise Exception, "Unknown version found: #{global_zone.solaris_version}"
        end
      end

      def configure_network
        return_value = zone_connection.exec("echo #{resolve_conf} > /zones/#{@name}/root/etc/resolv.conf")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        return_value = zone_connection.exec("cp /zones/#{@name}/root/etc/nsswitch.dns  /zones/#{@name}/root/etc/nsswitch.conf")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        return_value = zone_connection.exec("perl -pi -e 's/^#(.*enable-cache hosts.*)/\\1/'  /zones/#{@name}/root/etc/nscd.conf")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
      end

      def configure_ssh
        return_value = zone_connection.exec("perl -pi -e 's/(PermitRootLogin) no/\\1 yes/' /zones/#{@name}/root/etc/ssh/sshd_config")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        return_value = zone_connection.exec("perl -pi -e 's%(CONSOLE=/dev/console)%\\#\\1%' /zones/#{@name}/root/etc/default/login")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        return_value = zone_connection.exec("zlogin #{@name} \"svcadm -v restart ssh\"")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        if brand == "solaris"
          return_value = zone_connection.exec("zlogin #{@name} \"rolemod -K type=normal root\"") if brand == "solaris"
          raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
          return_value = zone_connection.exec("perl -pi -e 's/^root/# root/' /zones/#{@name}/root/etc/user_attr")
          raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        end
      end

      def generate_hostname
        if global?
          raise Exception, "Can not generate global zone hostname."
        else
          @hostname = "#{global_hostname.split(".", 2)[0]}-#{@name}-zone.#{global_hostname.split(".", 2)[1]}"
        end
      end

      def global_hostname
        @global_zone.hostname
      end

      def install_zone(master_zone_name)
        arch = zone_connection.exec("uname -i")
        case brand
        when "native"
          logger.debug("[SolarisZone] Installing zone #{@name} - this may take a while")
          return_value = zone_connection.exec("zoneadm -z #{@name} install")
          raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        when "solaris"
          logger.debug("[SolarisZone] Installing zone #{@name} - this may take a while")
          return_value = zone_connection.exec("zoneadm -z #{@name} install -c /tmp/#{@name}_sc_profile.xml") if arch[:stdout] == "sun4v"
          return_value = zone_connection.exec("zoneadm -z #{@name} clone -c /tmp/#{@name}_sc_profile.xml #{master_zone_name}") if arch[:stdout] == "i86pc"
          raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        when "solaris10"
          logger.debug("[SolarisZone] Installing zone #{@name} - this may take a while")
          zone_connection.exec("echo #{sysidcfg} > /tmp/#{@name}_sysidcfg")
          return_value = zone_connection.exec("zoneadm -z #{@name} clone -c /tmp/#{@name}_sysidcfg #{master_zone_name}")
          raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
        end
      end

      def password_hash
        salt = rand(36**6).to_s(36)
        case brand
        when ("solaris10" || "native")
          password.crypt(salt)
        when "solaris"
          ::UnixCrypt::SHA256.build(password, salt)
        end
      end

      def resolve_conf
        Shellwords.escape(
        %Q|domain chef.co
nameserver 8.8.8.8
nameserver 8.8.4.4
search chef.co|).chomp
      end

      def sc_profile
        Shellwords.escape(
        %Q|<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">
<service_bundle type="profile" name="system configuration">
  <service name="system/environment" version="1" type="service">
    <instance name="init" enabled="true">
      <property_group name="environment" type="application">
        <propval name="LANG" type="astring" value="en_US.UTF-8"/>
      </property_group>
    </instance>
  </service>
  <service name="system/console-login" version="1" type="service">
    <instance name="default" enabled="true">
      <property_group name="ttymon" type="application">
        <propval name="terminal_type" type="astring" value="xterm"/>
      </property_group>
    </instance>
  </service>
  <service name="system/timezone" version="1" type="service">
    <instance name="default" enabled="true">
      <property_group name="timezone" type="application">
        <propval name="localtime" type="astring" value="US/Pacific"/>
      </property_group>
    </instance>
  </service>
  <service name="system/config-user" version="1" type="service">
    <instance name="default" enabled="true">
      <property_group name="root_account" type="application">
        <propval name="login" type="astring" value="root"/>
        <propval name="password" type="astring" value="#{password_hash}"/>
        <propval name="type" type="astring" value="role"/>
      </property_group>
    </instance>
  </service>
  <service name="system/identity" version="1" type="service">
    <instance name="node" enabled="true">
      <property_group name="config" type="application">
        <propval name="nodename" type="astring" value="#{@hostname}"/>
      </property_group>
    </instance>
  </service>
  <service name="network/physical" version="1" type="service">
    <instance name="default" enabled="true">
      <property_group name="netcfg" type="application">
        <propval name="active_ncp" type="astring" value="DefaultFixed"/>
      </property_group>
    </instance>
  </service>
  <service name="network/ssh" version="1" type="service">
    <instance enabled="true" name="default"/>
  </service>
  <service version="1" type="service" name="system/name-service/cache">
    <instance enabled="false" name="default"/>
  </service>
  <service version="1" type="service" name="network/smtp">
    <instance enabled="false" name="default"/>
  </service>
  <service version="1" type="service" name="network/dns/client">
    <instance enabled="true" name="default"/>
  </service>
</service_bundle>|).chomp
      end

      def sysidcfg
        Shellwords.escape(
        %Q|system_locale=en_US.UTF-8
terminal=xterm
security_policy=NONE
network_interface=PRIMARY {
hostname=#{@hostname}
}
name_service=NONE
timezone=US/Pacific
root_password=#{password_hash}
nfs4_domain=dynamic
security_policy=none
auto_reg=none|).chomp
      end

      def zone_cfg_10
        Shellwords.escape(
        %Q|create -b
set zonepath=/zones/#{@name}
set autoboot=true
set ip-type=shared
set bootargs="-m verbose"
add net
set address=#{@ip}
set physical=#{@global_zone.network_device}
end
add capped-cpu
set ncpus=4
end
add attr
set name=comment
set type=string
set value="Created by Test Kitchen + #{Time.now}"
end|).chomp
      end

      def zone_cfg_branded
        Shellwords.escape(
        %Q|create -b
      set zonepath=/zones/#{@name}
      set brand=solaris10
      set autoboot=true
      set ip-type=shared
      set bootargs="-m verbose"
      add net
      set address=#{@ip}
      set physical=#{@global_zone.network_device}
      end
      add capped-cpu
      set ncpus=4
      end
      add attr
      set name=comment
      set type=string
      set value="Created by Test Kitchen + #{Time.now}"
      end|).chomp
      end

      def zone_cfg_11
        Shellwords.escape(
        %Q|create -b
set zonepath=/zones/#{@name}
set autoboot=true
set ip-type=shared
set bootargs="-m verbose"
add net
set address=#{@ip}
set physical=#{@global_zone.network_device}
end
add attr
set name=comment
set type=string
set value="Created by Test Kitchen + #{Time.now}"
end|).chomp
      end
    end
  end
end
