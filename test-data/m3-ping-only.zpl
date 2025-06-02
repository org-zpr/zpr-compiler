Note: Allow a specific agent to ping another specific agent.
Note: Since we don't yet authenticate users, this policy is expressed using endpoints.


define adapter as a device with zpr.adapter.cn

define ZServicePingable as a service with device.zpr.adapter.cn:'service.zpr.org'

allow zpr.adapter.cn:'client.zpr.org' adapter to access ZServicePingable


