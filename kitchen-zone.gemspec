# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "kitchen/driver/zone_version"

Gem::Specification.new do |spec|
  spec.name          = "kitchen-zone"
  spec.version       = Kitchen::Driver::ZONE_VERSION
  spec.authors       = ["Scott Hain"]
  spec.email         = ["shain@chef.io"]
  spec.description   = %q{A Test Kitchen Driver for Zone}
  spec.summary       = spec.description
  spec.homepage      = ""
  spec.license       = "Apache 2.0"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "test-kitchen"
  spec.add_dependency "unix-crypt"

  spec.add_development_dependency "rake"
  spec.add_development_dependency "finstyle",  "1.4.0"
  spec.add_development_dependency "countloc"
  spec.add_development_dependency "rspec"
end
