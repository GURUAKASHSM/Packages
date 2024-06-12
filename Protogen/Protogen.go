package Protogen

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// GenerateProto generates a Protocol Buffer message definition based on the provided struct.
func GenerateProto(s interface{}) error {
	// Use reflection to inspect the fields of the struct
	structType := reflect.TypeOf(s)
	structName := structType.Name()
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
		fieldName = ToLowerFirst(fieldName)
        fieldType = strings.TrimPrefix(fieldType, "*")
		jsonTag := field.Tag.Get("json")
		bsonTag := field.Tag.Get("bson")
		validateTag := field.Tag.Get("validate")

		if len(jsonTag) == 0 && len(bsonTag) == 0 && len(validateTag) == 0 {
			protoMessage += "   " + fieldType + " "
			protoMessage += fieldName + " = " + strconv.Itoa(count) + ";\n\n"
			count++
			continue

		}
		var jsonName string
		if len(jsonTag) != 0 {
			jsonName = strings.Split(jsonTag, ",")[0]
		}
		protoMessage += "   " + fieldType + " "

		protoMessage += fieldName + " = " + strconv.Itoa(count) + " [\n     "

		if len(jsonTag) != 0 {
			protoMessage += "json_name = \"" + jsonName + "\",\n"
		}

		protoMessage += "     (tagger.tags) = \""

		if len(jsonTag) != 0{
			protoMessage += "json:\\\"" + jsonTag + "\\\""
		}

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

func ToLowerFirst(str string) string {
	if str == "" {
		return str
	}
	firstRune := []rune(str)[0]
	lowerFirstRune := unicode.ToLower(firstRune)
	return string(lowerFirstRune) + str[1:]
}
