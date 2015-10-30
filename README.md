# Kitchen::Zone

A Test Kitchen Driver for Zone.

## Requirements

There are no software requirements for this driver. That being said, this driver is very opinionated about the hardware setup you are connecting to.

## Installation and Setup

Please read the [Driver usage][driver_usage] page for more details.

## Hardware/OS Requirements
It is assumed that you are running a physical Solaris 10/11 system that has the appropriate patch level (and all the required packages) to support zones.

For **Solaris 10** It is assumed that the sudo package is installed.

## Configuration

There are a number of configuration options that are required in your `.kitchen.yml`.

* `global_zone_hostname` - hostname/IP of the global zone physical machine.
* `global_zone_username` - username of the global zone physical machine. (default `root`)
* `global_zone_password` - password for the global zone physical machine.
* `global_zone_port` - ssh port for global zone physical machine. (default `22`)
* `master_zone_name` - name of the 'master' zone that other zones will be cloned off of (this is essentially a template). (default `master`)
* `master_zone_ip` - ip address of the template zone. this is required during initial setup and must be valid.
* `master_zone_password` - template zone password (default `llama!llama`)
* `test_zone_ip` - ip address of the zone where tests will run.
* `test_zone_password` - test zone password (default `tulips!tulips`)

In addition to these changes, you will need to override the `sudo_command` in both the `provisioner` and `verifier` sections of the `.kitchen.yml`.

For **Solaris 10**:
```
provisioner:
      sudo_command: '/usr/local/bin/sudo -E'
verifier:
      sudo_command: '/usr/local/bin/sudo -E'
```
For **Solaris 11**:
```
provisioner:
      sudo_command: 'sudo -E'
verifier:
      sudo_command: 'sudo -E'
```

#### Full .kitchen.yml Example
```
driver:
  name: zone

provisioner:
  name: chef_zero

platforms:
  - name: solaris-10-sun4v
    provisioner:
      sudo_command: '/usr/local/bin/sudo -E'
    verifier:
      sudo_command: '/usr/local/bin/sudo -E'
    driver:
      global_zone_hostname: 'sol-zone-host01.mysite.co'
      global_zone_user: 'root'
      global_zone_password: 'supersecret'
      master_zone_name: kitchen-master
      master_zone_ip: '192.168.1.100'
      test_zone_ip: '192.168.1.110'
  - name: solaris-11-i86pc
    provisioner:
      sudo_command: 'sudo -E'
    verifier:
      sudo_command: 'sudo -E'
    driver:
      global_zone_hostname: 'sol-zone-host02.mysite.co'
      global_zone_user: 'root'
      global_zone_password: 'supersecret'
      master_zone_name: kitchen-master
      master_zone_ip: '192.168.2.100'
      test_zone_ip: '192.168.2.110'
suites:
< the usual >

```

## Development

* Source hosted at [GitHub][repo]
* Report issues/questions/feature requests on [GitHub Issues][issues]

Pull requests are very welcome! Make sure your patches are well tested.
Ideally create a topic branch for every separate change you make. For
example:

1. Fork the repo
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## Authors

Created and maintained by [Scott Hain][author] (<shain@chef.io>)

## License

Apache 2.0 (see [LICENSE][license])


[author]:           https://github.com/scotthain
[issues]:           https://github.com/test-kitchen/kitchen-zone/issues
[license]:          https://github.com/test-kitchen/kitchen-zone/blob/master/LICENSE
[repo]:             https://github.com/test-kitchen/kitchen-zone
[driver_usage]:     http://docs.kitchen-ci.org/drivers/usage
[chef_omnibus_dl]:  http://www.getchef.com/chef/install/
