package Protogen

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
)

// GenerateProto generates a Protocol Buffer message definition based on the provided struct.
func GenerateProto(structName string, s interface{}) error {
	// Use reflection to inspect the fields of the struct
	structType := reflect.TypeOf(s)
	var protoMessage string
	protoMessage += "message " + structName + " {\n\n"
	count := 1

	// Iterate over the fields
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		fieldName := field.Name
		fieldType := field.Type.String()
		isArray := field.Type.Kind() == reflect.Slice

		// Handle array types
		if isArray {
			fieldType = strings.TrimPrefix(fieldType, "[]")
			fieldType = "repeated " + fieldType
		}

		// Handle special cases for field types
		switch fieldType {
		case "time.Time":
			fieldType = "google.protobuf.Timestamp"
		case "primitive.ObjectID":
			fieldType = "string"
		}

		jsonTag := field.Tag.Get("json")
		bsonTag := field.Tag.Get("bson")
		validateTag := field.Tag.Get("validate")

		// Remove ",omitempty" from json_name
		jsonName := strings.Split(jsonTag, ",")[0]

		protoMessage += "   " + fieldType + " "
		protoMessage += fieldName + " = " + strconv.Itoa(count) + " [\n     json_name = \"" + jsonName + "\",\n"
		protoMessage += "     (tagger.tags) = \"json:\\\"" + jsonTag + "\\\""

		if len(bsonTag) != 0 {
			protoMessage += " bson:\\\"" + bsonTag + "\\\""
		}
		if len(validateTag) != 0 {
			protoMessage += " validate:\\\"" + validateTag + "\\\""
		}
		protoMessage += " \""
		protoMessage += "\n   ];\n\n"
		count++
	}

	protoMessage += "}"

	// Write the proto message to a file
	file, err := os.Create(structName + ".proto")
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(protoMessage)
	if err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	fmt.Println("Proto message written to " + structName + ".proto")
	return nil
}
