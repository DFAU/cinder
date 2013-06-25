#
# Cookbook Name:: cinder
# Recipe:: cinder-volume
#
# Copyright 2012, Rackspace US, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

platform_options = node["cinder"]["platform"]

pkgs = platform_options["cinder_volume_packages"] + platform_options["cinder_iscsitarget_packages"]

pkgs.each do |pkg|
  package pkg do
    action node["osops"]["do_package_upgrades"] == true ? :upgrade : :install
    options platform_options["package_overrides"]
  end
end

include_recipe "cinder::cinder-common"

# set to enabled right now but can be toggled
service "cinder-volume" do
  service_name platform_options["cinder_volume_service"]
  supports :status => true, :restart => true
  action [ :enable ]
  subscribes :restart, "cinder_conf[/etc/cinder/cinder.conf]", :delayed
end

service "iscsitarget" do
  service_name platform_options["cinder_iscsitarget_service"]
  supports :status => true, :restart => true
  action :enable
end

template "/etc/tgt/targets.conf" do
  source "targets.conf.erb"
  mode "600"
  notifies :restart, "service[iscsitarget]", :immediately
end

case node["cinder"]["storage"]["provider"] 
  when "rbd"
    template "/etc/nova/virsh-secret.xml" do
      source "virsh-secret.xml.erb"
      owner "nova"
      group "nova"
      mode 00600
      notifies :restart, "service[cinder-volume]", :delayed
    end
    template "/etc/init/cinder-volume.conf" do
      source "cinder-volume.conf.erb"
      owner "root"
      group "root"
      mode 00644
      notifies :restart, "service[cinder-volume]", :delayed
    end
    bash "cinder-ceph-auth-keyring" do
      user "root"
      code <<-EOH
        ceph auth get-or-create client.volumes > /etc/ceph/ceph.client.#{node["cinder"]["storage"]["rbd"]["rbd_user"]}.keyring
        chown cinder:cinder /etc/ceph/ceph.client.#{node["cinder"]["storage"]["rbd"]["rbd_user"]}.keyring
      EOH
      not_if "test -f /etc/ceph/ceph.client.#{node["cinder"]["storage"]["rbd"]["rbd_user"]}.keyring"
      notifies :restart, "service[cinder-volume]", :delayed
    end
    bash 'load-virsh-keys' do
      user "root"
      code <<-EOH
        ADMIN_KEY=`ceph auth get-or-create-key client.#{node["cinder"]["storage"]["rbd"]["rbd_user"]}`
        virsh secret-define --file /etc/nova/virsh-secret.xml
        virsh secret-set-value --secret #{node["cinder"]["libvirt"]["secret-uuid"]} --base64 "$ADMIN_KEY"
      EOH
      not_if "virsh secret-list | grep -i #{node["cinder"]["libvirt"]["secret-uuid"]}"
      notifies :restart, "service[cinder-volume]", :delayed
    end
  when "emc"
    d = node["cinder"]["storage"]["emc"]
    keys = %w[StorageType EcomServerIP EcomServerPort EcomUserName EcomPassword]
    for word in keys
      if not d.key? word
        msg = "Cinder's emc volume provider was selected, but #{word} was not set.'"
        Chef::Application.fatal! msg
      end
    end
    node["cinder"]["storage"]["emc"]["packages"].each do |pkg|
      package pkg do
        action node["osops"]["do_package_upgrades"] == true ? :upgrade : :install
      end
    end

    template node["cinder"]["storage"]["emc"]["config"] do
      source "cinder_emc_config.xml.erb"
      variables d
      mode "644"
      notifies :restart, "service[iscsitarget]", :immediately
    end
  when "netappnfsdirect"
    node["cinder"]["storage"]["netapp"]["nfsdirect"]["packages"].each do |pkg|
      package pkg do
        action node["osops"]["do_package_upgrades"] == true ? :upgrade : :install
      end
    end

    template node["cinder"]["storage"]["netapp"]["nfsdirect"]["nfs_shares_config"] do
      source "cinder_netapp_nfs_shares.txt.erb"
      mode "0600"
      owner "cinder"
      group "cinder"
      variables(
	     "host" => node["cinder"]["storage"]["netapp"]["nfsdirect"]["server_hostname"],
	     "nfs_export" => node["cinder"]["storage"]["netapp"]["nfsdirect"]["export"]
      )
      notifies :restart, "service[cinder-volume]", :delayed
    end
end
