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

require "kitchen/driver/solariszone"
require "kitchen/driver/zone"

describe Kitchen::Driver::SolarisZone do
  let(:testzone) { Kitchen::Driver::SolarisZone.new }

  context "when operating on a global zone" do
    before(:each) do
      testzone.global_zone = nil
    end

    describe "#global?" do
      it "returns true" do
        expect(testzone.global?).to eq(true)
      end
    end

    describe "#zone_connection" do
      it "creates an ssh connection to the zone" do
        testzone.global_zone = nil
        testzone.hostname = "testhost"
        testzone.username = "testuser"
        testzone.password = "testpass"

        expect(Kitchen::Driver::SSHZone).to receive(:new).with("testhost", "testuser", hash_including(:password => "testpass"))
        testzone.zone_connection
      end
    end

    describe "#exists?" do
      it "returns an exception and nice error message" do
        expect { testzone.exists? }.to raise_error(Exception, "Global zones always exist")
      end
    end
  end

  context "when operating on a child zone" do
    let(:globalzone) { Kitchen::Driver::SolarisZone.new }

    before(:each) do
      testzone.global_zone = globalzone
    end

    describe "#global?" do
      it "returns false if it has a global zone" do
        expect(testzone.global?).to eq(false)
      end
    end

    describe "#zone_connection" do
      it "creates an ssh connection to the zone" do
        globalzone.hostname = "testhost"
        globalzone.username = "testuser"
        globalzone.password = "testpass"
        testzone.global_zone = globalzone

        expect(Kitchen::Driver::SSHZone).to receive(:new).with("testhost", "testuser", hash_including(:password => "testpass"))
        testzone.zone_connection
      end
    end

    describe "#exists?" do
      let(:ssh_double) { double(Kitchen::Driver::SSHZone) }

      before(:each) do
        expect(testzone).to receive(:zone_connection).and_return(ssh_double)
      end

      it "returns true if the zone exists" do
        value = { :stdout => "myzone" }
        testzone.name = "myzone"

        expect(ssh_double).to receive(:exec).with("zoneadm -z myzone list").and_return(value)
        expect(testzone.exists?).to eq(true)
      end

      it "returns false if the zone does not exists" do
        value = { :stdout => nil }
        testzone.name = "myzone"

        expect(ssh_double).to receive(:exec).with("zoneadm -z myzone list").and_return(value)
        expect(testzone.exists?).to eq(false)
      end
    end
  end
end
