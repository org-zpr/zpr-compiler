define adapter as a device with zpr.adapter.cn

Note: Our node offers PING too
define PingableNode as a service with device.zpr.adapter.cn:'node.zpr.org'

Note: Three services, all offered by same adapter
define WebService as a service with device.zpr.adapter.cn:'service.zpr.org'
define IPerfService as a service with device.zpr.adapter.cn:'service.zpr.org'
define PingableService as a service with device.zpr.adapter.cn:'service.zpr.org'

define SpecialClient as an adapter with device.zpr.adapter.cn:'client.zpr.org'

Note: the SpecialClient can access three services
allow SpecialClient to access WebService
allow SpecialClient to access IPerfService
allow SpecialClient to access PingableService

Note: any connected adapter can ping the node
allow adapter to access PingableNode

allow zpr.adapter.cn:'client.zpr.org' devices to access VisaService

