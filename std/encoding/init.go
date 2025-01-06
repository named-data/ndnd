package encoding

var LOCALHOST = NewStringComponent(TypeGenericNameComponent, "localhost")
var LOCALHOP = NewStringComponent(TypeGenericNameComponent, "localhop")

func init() {
	initComponentConventions()
}
