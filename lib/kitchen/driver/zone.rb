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

require 'kitchen'
require 'digest/sha2'

module Kitchen

  module Driver

    # Zone driver for Kitchen.
    #
    # @author Scott Hain <shain@getchef.com>
    class Zone < Kitchen::Driver::SSHBase
      default_config :global_zone_hostname, nil
      default_config :global_zone_username, 'root'
      default_config :global_zone_password, nil
      default_config :global_zone_port, '22'
      default_config :master_zone_name, 'master'

      # The first time we run, we need to ensure that we have a 'master' template
      # zone to clone. This can cause the first run to be slower.
      def create(state)
        # Set up global zone information
        gz = SolarisZone.new
        gz.hostname = config[:global_zone_hostname]
        gz.username = config[:global_zone_username]
        gz.password = config[:global_zone_password]

        if gz.verify_connection != 0
          raise Exception, "Could not verify your global zone - verify host, username, and password"
        end

        # Now that we know our global zone is happy, let's create a master zone!
        mz = SolarisZone.new
        mz.global_zone = gz
        mz.name = config[:master_zone_name]
        mz.password = "llama"
        mz.ip = config[:master_zone_ip]

        unless mz.exists?
          logger.debug("[kitchen-zone] #{self} Zone template #{mz.name} not found - creating now.")
          mz.create
          mz.halt
        else
          logger.debug("[kitchen-zone] #{self} Found zone template #{mz.name}")
        end

        if mz.running?
          mz.halt
        end

        # Yay! now let's create our new test zone
        tz = SolarisZone.new
        tz.global_zone = gz
        tz.name = "kitchen"
        tz.password = "tulips"
        tz.ip = config[:test_zone_ip]

        tz.clone_from(mz)

        state[:zone_id] = tz.name
        tz.sever
        mz.sever
        gz.sever
      end

      def converge(state)
        puts "CONVERGE"
      end

      def test(state)
        puts "TEST"
      end

      def destroy(state)
        return if state[:zone_id].nil?

        gz = SolarisZone.new(logger)
        gz.hostname = config[:global_zone_hostname]
        gz.username = config[:global_zone_username]
        gz.password = config[:global_zone_password]

        if gz.verify_connection != 0
          raise Exception, "Could not verify your global zone - verify host, username, and password"
        end

        # Yay! now let's create our new test zone
        tz = SolarisZone.new(logger)
        tz.global_zone = gz
        tz.name = "kitchen"
        tz.password = "tulips"
        tz.ip = config[:test_zone_ip]

        tz.destroy
        state.delete(:zone_id)
      end
    end

    class SolarisZone
      attr_accessor :hostname
      attr_accessor :username
      attr_accessor :password
      attr_accessor :global_zone
      attr_accessor :name
      attr_accessor :ip

      def initialize(logger)
        @logger = logger
      end

#      logger = ::Logger.new(STDOUT)

      def clone_from(master_zone)
        raise Exception, "Can not clone global zones" if global?

        generate_hostname
        create_zonecfg
        create_zone
        clone_zone(master_zone.name)
        create_sysidcfg
        boot_zone
        configure_network
        configure_ssh
      end

      def create
        raise Exception, "Can not create global zones" if global?

        generate_hostname
        create_zonecfg
        create_zone
        install_zone
        create_sysidcfg
        boot_zone
        configure_network
        configure_ssh
      end

      def destroy
        raise Exception, "Can not destroy global zones" if global?
        raise Exception, "Zone #{@name} does not exist" if not exists?

        generate_hostname
        return_value = zone_connection.exec("zoneadm -z #{name} halt")
        raise Exception if return_value[:exit_code] != 0
        return_value = zone_connection.exec("zoneadm -z #{name} uninstall -F")
        raise Exception if return_value[:exit_code] != 0
        return_value = zone_connection.exec("zonecfg -z #{name} delete -F")
        raise Exception if return_value[:exit_code] != 0
        return_value = zone_connection.exec("perl -pi -e 's/#{ip} #{hostname}\\\n//' \"/etc/hosts\"")
        raise Exception if return_value[:exit_code] != 0
      end

      def exists?
        return_value = zone_connection.exec("zoneadm -z #{name} list")
        if return_value[:stdout].eql? name
          true
        else
          false
        end
      end

      def global?
        global_zone.nil?
      end

      def halt
        raise Exception, "Can not halt global zones" if global?
#        logger.debug("Halting zone #{@name}")
        return_value = zone_connection.exec("zoneadm -z #{@name} halt")
        raise Exception if return_value[:exit_code] != 0
      end

      def network_device
        return_value = zone_connection.exec("ifconfig -a | grep IPv4 | cut -d: -f1 | uniq | grep -v lo")
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
        begin
          return_value = zone_connection.exec("")
          return_value[:exit_code]
        rescue SocketError
#          @logger.error "Error connecting to #{@hostname}"
          return 1
        ensure
          sever
        end
      end

      def zone_connection
        opts = { :logger => @logger }
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

      def boot_zone
#        @logger.debug("Booting zone #{@name}")
        return_value = zone_connection.exec("zoneadm -z \"#{@name}\" boot")
        raise Exception if return_value[:exit_code] != 0
        waiting_for_ssh = true
        waiting_for_too_damn_long = 0
#        @logger.debug("Waiting for SSH service to come up on #{@name}")
        while waiting_for_ssh && waiting_for_too_damn_long < 10
          return_value = zone_connection.exec("zlogin #{@name} \"svcs -v | grep ssh | grep online 2>&1 > /dev/null\"")
          if return_value[:exit_code] == 0
            waiting_for_ssh = false
          else
            waiting_for_too_damn_long += 1
            sleep 10
          end
        end
      end

      def clone_zone(master_zone_name)
#        @logger.debug("Cloning #{@name} from #{master_zone_name}")
        return_value = zone_connection.exec("zoneadm -z #{@name} clone #{master_zone_name} 2>&1 | grep -v \"grep: can't open /a/etc/dumpadm.conf\"")
        raise Exception if return_value[:exit_code] != 0
      end

      def create_sysidcfg
        return_value = zone_connection.exec("echo \"#{sysidcfg}\" > /zones/#{@name}/root/etc/sysidcfg")
        raise Exception if return_value[:exit_code] != 0
      end

      def create_zone
#        @logger.debug("Creating zone #{@name}")
        return_value = zone_connection.exec("zonecfg -z #{@name} -f /tmp/#{@name}.cfg")
        raise Exception, return_value[:stdout] if return_value[:exit_code] != 0
      end

      def create_zonecfg
        return_value = zone_connection.exec("echo \"#{zone_cfg}\" > /tmp/#{@name}.cfg")
        raise Exception if return_value[:exit_code] != 0
      end

      def configure_network
        return_value = zone_connection.exec("echo \"#{resolve_conf}\" > /zones/#{@name}/root/etc/resolv.conf")
        raise Exception if return_value[:exit_code] != 0
        return_value = zone_connection.exec("cp /zones/#{@name}/root/etc/nsswitch.dns  /zones/#{@name}/root/etc/nsswitch.conf")
        raise Exception if return_value[:exit_code] != 0
        return_value = zone_connection.exec("perl -pi -e 's/^#(.*enable-cache hosts.*)/\\1/'  \"/zones/#{@name}/root/etc/nscd.conf\"")
        raise Exception if return_value[:exit_code] != 0
        return_value = zone_connection.exec("echo #{@ip} #{@hostname} >> /etc/hosts")
        raise Exception if return_value[:exit_code] != 0
      end

      def configure_ssh
        return_value = zone_connection.exec("perl -pi -e 's/(PermitRootLogin) no/\\1 yes/' \"/zones/#{@name}/root/etc/ssh/sshd_config\"")
        raise Exception if return_value[:exit_code] != 0
        return_value = zone_connection.exec("perl -pi -e 's%(CONSOLE=/dev/console)%\\#\\1%' \"/zones/#{@name}/root/etc/default/login\"")
        raise Exception if return_value[:exit_code] != 0
        return_value = zone_connection.exec("zlogin #{@name} \"svcadm -v restart ssh\"")
        raise Exception if return_value[:exit_code] != 0
      end

      def generate_hostname
        if global?
          raise Exception, "Can not generate global zone hostname."
        else
@hostname = "#{global_hostname.split('.',2)[0]}-#{@name}-zone.#{global_hostname.split('.',2)[1]}"
        end
      end

      def global_hostname
        @global_zone.hostname
      end

      def install_zone
#        logger.debug("Installing zone #{@name}")
        return_value = zone_connection.exec("zoneadm -z #{@name} install")
        raise Exception if return_value[:exit_code] != 0
      end

      def password_hash
        salt = rand(36**6).to_s(36)
        password.crypt(salt)
      end

      def resolve_conf
        "domain chef.co
nameserver 8.8.8.8
nameserver 8.8.4.4
search chef.co".chomp
      end

      def sysidcfg
        "system_locale=en_US.UTF-8
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
auto_reg=none".chomp
      end

      def zone_cfg
        "create -b
set zonepath=/zones/#{@name}
set autoboot=true
set ip-type=shared
set bootargs=\\\"-m verbose\\\"
add inherit-pkg-dir
set dir=/lib
end
add inherit-pkg-dir
set dir=/platform
end
add inherit-pkg-dir
set dir=/sbin
end
add inherit-pkg-dir
set dir=/usr
end
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
set value=\\\"Created by Test Kitchen + #{Time::now}\\\"
end".chomp
      end
    end

    class SSHZone < Kitchen::SSH

      def exec(cmd)
        logger.debug("[SSHZone] #{self} (#{cmd})")
        return_value = exec_with_return(cmd)
      end

      private

      # Execute a remote command and return the command's exit code.
      #
      # @param cmd [String] command string to execute
      # @return [Hash] contains the exit code, stderr and stdout of the command
      # @api private
      def exec_with_return(cmd)
        exit_code = nil
        return_value = Hash.new
        session.open_channel do |channel|

          channel.request_pty

          channel.exec(cmd) do |_ch, _success|

            channel.on_data do |_ch, data|
              return_value[:stdout] = data.chomp
            end

            channel.on_extended_data do |_ch, _type, data|
              return_value[:stderr] = data.chomp
            end

            channel.on_request("exit-status") do |_ch, data|
              return_value[:exit_code] = data.read_long
            end
          end
        end
        session.loop
        return_value
      end

    end
  end
end
