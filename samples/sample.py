from pynetgear import Netgear

netgear = Netgear('password', 'routerlogin.net', 'admin', 80)

print(netgear.get_attached_devices())
print(netgear.enable_config())
#print(netgear.allow_device('XX:XX:XX:XX'))
print(netgear.disable_config())
