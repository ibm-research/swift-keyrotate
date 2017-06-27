# For Windows hosts, STORE may need to be set to './store.vdi'
STORE = 'store.vdi'
SERVICES_IP = "192.168.50.11"
SWIFT_IP = "192.168.50.12"

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"

  config.vm.define "services" do |services|
    services.vm.hostname = "services"
    services.vm.network "private_network", ip: SERVICES_IP
    services.vm.provider "virtualbox" do | v |
      v.memory = 1536
      v.name = "swift-services"
    end
    services.vm.provision :shell, path: "install-services.sh", privileged: false, keep_color: true
  end

  config.vm.boot_timeout = 600
  config.vm.define "swift" do |swift|
    swift.vm.hostname = "swift"
    swift.vm.network "private_network", ip: SWIFT_IP
    swift.vm.provider "virtualbox" do | v |
      v.memory = 4096
      v.name = "swift"
      v.cpus = 2
      unless File.exist?(STORE)
        v.customize ['createhd', '--filename', STORE, '--size', 2 * 1024]
        # For older versions of virtualbox, change 'SCSI' to 'SCSI Controller'
        v.customize ['storageattach', :id, '--storagectl', 'SCSI', '--port', 2, '--device', 0, '--type', 'hdd', '--medium', STORE]
      end
    end
    swift.vm.provision :shell, path: "install-swift.sh", privileged: false, keep_color: true
  end

  config.ssh.forward_x11 = true
end

