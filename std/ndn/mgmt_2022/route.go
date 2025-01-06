package mgmt_2022

type RouteFlag uint64

const (
	RouteFlagNoFlag       RouteFlag = 0
	RouteFlagChildInherit RouteFlag = 1
	RouteFlagCapture      RouteFlag = 2
)

var RouteFlagList = map[RouteFlag]string{
	RouteFlagChildInherit: "child-inherit",
	RouteFlagCapture:      "capture",
}

func (v RouteFlag) String() string {
	if s, ok := RouteFlagList[v]; ok {
		return s
	}
	return "unknown"
}

func (v RouteFlag) IsSet(flags uint64) bool {
	return uint64(v)&flags != 0
}

type RouteOrigin uint64

const (
	RouteOriginApp       RouteOrigin = 0
	RouteOriginStatic    RouteOrigin = 255
	RouteOriginNLSR      RouteOrigin = 128
	RouteOriginPrefixAnn RouteOrigin = 129
	RouteOriginClient    RouteOrigin = 65
	RouteOriginAutoreg   RouteOrigin = 64
	RouteOriginAutoconf  RouteOrigin = 66
)

var RouteOriginList = map[RouteOrigin]string{
	RouteOriginApp:       "app",
	RouteOriginStatic:    "static",
	RouteOriginNLSR:      "nlsr",
	RouteOriginPrefixAnn: "prefixann",
	RouteOriginClient:    "client",
	RouteOriginAutoreg:   "autoreg",
	RouteOriginAutoconf:  "autoconf",
}

func (v RouteOrigin) String() string {
	if s, ok := RouteOriginList[v]; ok {
		return s
	}
	return "unknown"
}
