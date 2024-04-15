package typeconversionservice

import (
	"fmt"
	"reflect"
	"strings"
)

type DynamicStruct struct{}

func MapToStruct(data map[string]interface{}) (interface{}, error) {
	var fields []reflect.StructField

	for key, value := range data {
		fieldType := reflect.TypeOf(value)
		// Ensure field names start with uppercase letter for export
		fieldName := strings.Title(key)
		fields = append(fields, reflect.StructField{
			Name: fieldName,
			Type: fieldType,
			Tag:  reflect.StructTag(fmt.Sprintf(`json:"%s"`, key)),
		})
	}

	structType := reflect.StructOf(fields)
	structValue := reflect.New(structType).Elem()

	for key, value := range data {
		fieldName := strings.Title(key)
		fieldValue := structValue.FieldByName(fieldName)
		fieldValue.Set(reflect.ValueOf(value))
	}

	return structValue.Interface(), nil
}
