# -*- mode: ruby -*-
# vi: set ft=ruby :

$script = <<-SCRIPT
  echo "Provisioning..."
  sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
  echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
  sudo apt-get update
  sudo apt-get -y install bcc-tools libbcc-examples linux-headers-$(uname -r)
  date > /etc/vagrant_provisioned_at
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"
  config.vm.provision "shell", inline: $script
end