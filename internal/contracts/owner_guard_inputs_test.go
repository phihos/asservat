package contracts

import (
	"reflect"
	"testing"
)

// Guard must carry every guard field of the hub-api input, so the federation's
// owner reads (ADR-172) can never prove a different plan.
func TestOwnerDeploymentGuardCarriesEveryGuardField(t *testing.T) {
	var c OwnerDeployment
	v := reflect.ValueOf(&c).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString(v.Type().Field(i).Name)
		case reflect.Pointer, reflect.Slice:
			f.Set(reflect.New(f.Type()).Elem())
			if f.Kind() == reflect.Pointer {
				f.Set(reflect.New(f.Type().Elem()))
			} else {
				f.Set(reflect.MakeSlice(f.Type(), 1, 1))
			}
		}
	}
	c.WorkloadGuard.Name, c.Kubernetes.Endpoint = "guard", "https://api"
	g := reflect.ValueOf(c.Guard())
	for i := range g.NumField() {
		name := g.Type().Field(i).Name
		source, ok := reflect.TypeOf(c).FieldByName(name)
		if !ok || source.Type != g.Type().Field(i).Type || source.Tag != g.Type().Field(i).Tag {
			t.Fatal("guard field not in the hub-api input:", name)
		}
		if !reflect.DeepEqual(g.Field(i).Interface(), v.FieldByName(name).Interface()) {
			t.Fatal("guard field not copied:", name)
		}
	}
}
