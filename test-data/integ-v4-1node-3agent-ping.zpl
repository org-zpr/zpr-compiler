# three adapters: they can ping each other
# One node, one visa service: they can ping each other

define adapter as a device with zpr.adapter.cn

define A1 as adapter with zpr.adapter.cn:adapter1
define A2 as adapter with zpr.adapter.cn:adapter2
define A3 as adapter with zpr.adapter.cn:adapter3
define Node as adapter with zpr.adapter.cn:node
define Vs as adapter with zpr.adapter.cn:'vs.zpr'

define A1Svc as a service with device.zpr.adapter.cn:adapter1
define A2Svc as a service with device.zpr.adapter.cn:adapter2
define A3Svc as a service with device.zpr.adapter.cn:adapter3
define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'
define PingableNode as a service with device.zpr.adapter.cn:node

allow A1 to access A2Svc
allow A1 to access A3Svc

allow A2 to access A1Svc
allow A2 to access A3Svc

allow A3 to access A1Svc
allow A3 to access A2Svc

allow Node to access PingableVs
allow Vs to access PingableNode

allow zpr.adapter.cn:'client.zpr.org' devices to access VisaService



