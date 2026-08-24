# An "over" clause naming a link attribute that IS configured, but with a value that
# no configured link carries. That is most likely a typo ("use" for "usa"), so the
# compiler warns rather than failing: link values are topology data that a later
# configuration edit may legitimately introduce.

define database as a service.

allow redhead users to access database over location:use links.
