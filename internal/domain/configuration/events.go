package configuration

// BindingEvent is a single validated API watch transition. It is not a current
// complete projection or a permission grant. Bookmarks carry only a cursor.
type BindingEvent struct {
	Type, ResourceVersion string
	Binding               *Binding
}
