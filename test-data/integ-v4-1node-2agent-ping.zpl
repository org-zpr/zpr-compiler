# two adapters: they can ping each other
# One node, one visa service: they can ping each other

define adapter as a endpoint with zpr.adapter.cn

define A1 as adapter with zpr.adapter.cn:adapter1
define A2 as adapter with zpr.adapter.cn:adapter2
define Node as adapter with zpr.adapter.cn:node
define Vs as adapter with zpr.adapter.cn:'vs.zpr'

define A1Svc as a service with endpoint.zpr.adapter.cn:adapter1
define A2Svc as a service with endpoint.zpr.adapter.cn:adapter2
define PingableVs as a service with endpoint.zpr.adapter.cn:'vs.zpr'
define PingableNode as a service with endpoint.zpr.adapter.cn:node

allow A1 to access A2Svc
allow A2 to access A1Svc

allow Node to access PingableVs
allow Vs to access PingableNode

allow zpr.adapter.cn:'client.zpr.org' endpoints to access VisaService



