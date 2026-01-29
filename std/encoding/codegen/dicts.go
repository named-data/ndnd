package codegen

import "text/template"

// (AI GENERATED DESCRIPTION): Generates Go code that adds a field to a dictionary, inserting the value directly for required fields or inserting it only if present for optional fields.
func (f *NaturalField) GenToDict() (string, error) {
	g := strErrBuf{}
	if f.opt {
		g.printlnf("if optval, ok := value.%s.Get(); ok {", f.name)
		g.printlnf("\tdict[\"%s\"] = optval", f.name)
		g.printlnf("}")
	} else {
		g.printlnf("dict[\"%s\"] = value.%s", f.name, f.name)
	}
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that extracts an optional or required uint64 field from a dictionary, performs type checking, assigns the value to the field (or unsets it if optional), and emits errors for missing or incompatible entries.
func (f *NaturalField) GenFromDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("if vv, ok := dict[\"%s\"]; ok {", f.name)
	g.printlnf("\tif v, ok := vv.(uint64); ok {")
	if f.opt {
		g.printlnf("\t\tvalue.%s.Set(v)", f.name)
	} else {
		g.printlnf("\t\tvalue.%s = v", f.name)
	}
	g.printlnf("\t} else {")
	g.printlnf("\t\terr = enc.ErrIncompatibleType{Name: \"%s\", TypeNum: %d, ValType: \"uint64\", Value: vv}", f.name, f.typeNum)
	g.printlnf("\t}")
	g.printlnf("} else {")
	if f.opt {
		g.printlnf("\tvalue.%s.Unset()", f.name)
	} else {
		g.printlnf("err = enc.ErrSkipRequired{Name: \"%s\", TypeNum: %d}", f.name, f.typeNum)
	}
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that inserts a StringField into a dictionary, setting the field directly or conditionally based on whether the field is optional.
func (f *StringField) GenToDict() (string, error) {
	g := strErrBuf{}
	if f.opt {
		g.printlnf("if optval, ok := value.%s.Get(); ok {", f.name)
		g.printlnf("\tdict[\"%s\"] = optval", f.name)
		g.printlnf("}")
	} else {
		g.printlnf("dict[\"%s\"] = value.%s", f.name, f.name)
	}
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that extracts a string value from a dictionary, assigns it to the target field (or unsets it if optional), and returns errors for missing or incompatible types.
func (f *StringField) GenFromDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("if vv, ok := dict[\"%s\"]; ok {", f.name)
	g.printlnf("\tif v, ok := vv.(string); ok {")
	if f.opt {
		g.printlnf("\t\tvalue.%s.Set(v)", f.name)
	} else {
		g.printlnf("\t\tvalue.%s = v", f.name)
	}
	g.printlnf("\t} else {")
	g.printlnf("\t\terr = enc.ErrIncompatibleType{Name: \"%s\", TypeNum: %d, ValType: \"string\", Value: vv}", f.name, f.typeNum)
	g.printlnf("\t}")
	g.printlnf("} else {")
	if f.opt {
		g.printlnf("\tvalue.%s.Unset()", f.name)
	} else {
		g.printlnf("err = enc.ErrSkipRequired{Name: \"%s\", TypeNum: %d}", f.name, f.typeNum)
	}
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that inserts a non‑nil binary field into a map as a key/value pair.
func (f *BinaryField) GenToDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlnf("\tdict[\"%s\"] = value.%s", f.name, f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that extracts a binary field from a dictionary, assigns it to the struct’s field (or nil if missing), and emits an error on type mismatch.
func (f *BinaryField) GenFromDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("if vv, ok := dict[\"%s\"]; ok {", f.name)
	g.printlnf("\tif v, ok := vv.([]byte); ok {")
	g.printlnf("\t\tvalue.%s = v", f.name)
	g.printlnf("\t} else {")
	g.printlnf("\t\terr = enc.ErrIncompatibleType{Name: \"%s\", TypeNum: %d, ValType: \"[]byte\", Value: vv}", f.name, f.typeNum)
	g.printlnf("\t}")
	g.printlnf("} else {")
	g.printlnf("\tvalue.%s = nil", f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates code that serializes a boolean field by assigning its value to a dictionary entry (dict[“<fieldName>”] = value.<fieldName>).
func (f *BoolField) GenToDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("dict[\"%s\"] = value.%s", f.name, f.name)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code to extract a boolean value from a dictionary, assign it to the struct field, default to `false` if the key is missing, and return an error if the value is of an incompatible type.
func (f *BoolField) GenFromDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("if vv, ok := dict[\"%s\"]; ok {", f.name)
	g.printlnf("\tif v, ok := vv.(bool); ok {")
	g.printlnf("\t\tvalue.%s = v", f.name)
	g.printlnf("\t} else {")
	g.printlnf("\t\terr = enc.ErrIncompatibleType{Name: \"%s\", TypeNum: %d, ValType: \"bool\", Value: vv}", f.name, f.typeNum)
	g.printlnf("\t}")
	g.printlnf("} else {")
	g.printlnf("\tvalue.%s = false", f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that adds the NameField to a dictionary map only if the field is non‑nil.
func (f *NameField) GenToDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlnf("\tdict[\"%s\"] = value.%s", f.name, f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that extracts a Name field from a dictionary, performing a type assertion to enc.Name, assigning the value to the struct field or nil, and returns the generated code string or an error.
func (f *NameField) GenFromDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("if vv, ok := dict[\"%s\"]; ok {", f.name)
	g.printlnf("\tif v, ok := vv.(enc.Name); ok {")
	g.printlnf("\t\tvalue.%s = v", f.name)
	g.printlnf("\t} else {")
	g.printlnf("\t\terr = enc.ErrIncompatibleType{Name: \"%s\", TypeNum: %d, ValType: \"Name\", Value: vv}", f.name, f.typeNum)
	g.printlnf("\t}")
	g.printlnf("} else {")
	g.printlnf("\tvalue.%s = nil", f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that, if the struct field is non‑nil, inserts its dictionary representation (via ToDict()) into a map.
func (f *StructField) GenToDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlnf("\tdict[\"%s\"] = value.%s.ToDict()", f.name, f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates code to read a value from a map by key, type‑assert it to the field’s struct type, assign it (or nil if absent), and set an error if the type is incompatible.
func (f *StructField) GenFromDict() (string, error) {
	g := strErrBuf{}
	g.printlnf("if vv, ok := dict[\"%s\"]; ok {", f.name)
	g.printlnf("\tif v, ok := vv.(*%s); ok {", f.StructType)
	g.printlnf("\t\tvalue.%s = v", f.name)
	g.printlnf("\t} else {")
	g.printlnf("\t\terr = enc.ErrIncompatibleType{Name: \"%s\", TypeNum: %d, ValType: \"*%s\", Value: vv}",
		f.name, f.typeNum, f.StructType)
	g.printlnf("\t}")
	g.printlnf("} else {")
	g.printlnf("\tvalue.%s = nil", f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a Go code snippet that serializes a sequence field into a dictionary by iterating over its elements and embedding each subfield’s dictionary representation.
func (f *SequenceField) GenToDict() (string, error) {
	// Sequence uses faked encoder variable to embed the subfield.
	// I have verified that the Go compiler can optimize this in simple cases.
	t := template.Must(template.New("SeqInitEncoder").Parse(`{
		{{.Name}}_l := len(value.{{.Name}})
		dictSeq = make([]{{.FieldType}}, {{.Name}}_l)
		for i := 0; i < {{.Name}}_l; i ++ {
			pseudoValue := struct {
				{{.Name}} {{.FieldType}}
			}{
				{{.Name}}: value.{{.Name}}[i],
			}
			pseudoMap = make(map[string]interface{})
			{
				dict := pseudoMap
				value := &pseudoValue
				{{.SubField.GenToDict}}
				_ = dict
				_ = value
			}
			dictSeq[i] = pseudoMap[{{.Name}}]
		}
		dict[\"{{.Name}}\"] = dictSeq
	}
	`))

	var g strErrBuf
	g.executeTemplate(t, f)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Returns a placeholder error string indicating that the SequenceField GenFromDict method is not yet implemented.
func (f *SequenceField) GenFromDict() (string, error) {
	return "ERROR = \"Unimplemented yet!\"", nil
}

// (AI GENERATED DESCRIPTION): Generates Go code that inserts the unsigned integer field into a map, writing it directly for mandatory fields or only when non‑nil for optional ones.
func (f *FixedUintField) GenToDict() (string, error) {
	g := strErrBuf{}
	if f.opt {
		g.printlnf("if value.%s != nil {", f.name)
		g.printlnf("\tdict[\"%s\"] = *value.%s", f.name, f.name)
		g.printlnf("}")
	} else {
		g.printlnf("dict[\"%s\"] = value.%s", f.name, f.name)
	}
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a code block that extracts a fixed‑length unsigned integer from a dictionary, assigns it to a struct field (as a pointer if optional), and returns type‑mismatch or missing‑key errors.
func (f *FixedUintField) GenFromDict() (string, error) {
	digit := ""
	switch f.l {
	case 1:
		digit = "byte"
	case 2:
		digit = "uint16"
	case 4:
		digit = "uint32"
	case 8:
		digit = "uint64"
	}

	g := strErrBuf{}
	g.printlnf("if vv, ok := dict[\"%s\"]; ok {", f.name)
	g.printlnf("\tif v, ok := vv.(%s); ok {", digit)
	if f.opt {
		g.printlnf("\t\tvalue.%s = &v", f.name)
	} else {
		g.printlnf("\t\tvalue.%s = v", f.name)
	}
	g.printlnf("\t} else {")
	g.printlnf("\t\terr = enc.ErrIncompatibleType{Name: \"%s\", TypeNum: %d, ValType: \"%s\", Value: vv}",
		f.name, f.typeNum, digit)
	g.printlnf("\t}")
	g.printlnf("} else {")
	if f.opt {
		g.printlnf("\tvalue.%s = nil", f.name)
	} else {
		g.printlnf("err = enc.ErrSkipRequired{Name: \"%s\", TypeNum: %d}", f.name, f.typeNum)
	}
	g.printlnf("}")
	return g.output()
}
