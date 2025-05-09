package requestId

import (
	"errors"
	"fmt"
	"github.com/simonks2016/emi-encryption/base"
	"github.com/simonks2016/emi-encryption/hash"
	"reflect"
	"sort"
	"strings"
)

func DataModelGenSignature(dataModel any, extraData ...string) string {
	var d = encodeToStrings(dataModel, "signature")
	d = append(d, extraData...)
	//sort strings slice
	sort.Strings(d)
	return hash.M5[string](strings.Join(d, "&&"))
}
func encodeToStrings(dataModel any, excludedField ...string) []string {
	var elements []string
	v := reflect.ValueOf(dataModel)
	t := reflect.TypeOf(dataModel)

	if !v.IsValid() {
		return elements
	}

	// Handle pointer
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		v = v.Elem()
	}

	switch t.Kind() {
	case reflect.Struct:
	ForStruct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			tagName := getTagName(t, i)
			for _, fieldName := range excludedField {
				if tagName == fieldName {
					continue ForStruct
				}
			}
			value := analyzeField(v.Field(i), field.Type)
			elements = append(elements, fmt.Sprintf("%s=%v", tagName, value))
		}
	case reflect.Map:
		// Only support map with string keys
		if t.Key().Kind() != reflect.String {
			panic(errors.New("only support map[string]any for encodeToStrings"))
		}
		for _, key := range v.MapKeys() {
			k := key.String()
			// 检查是否在排除字段中
			skip := false
			for _, f := range excludedField {
				if k == f {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			val := v.MapIndex(key)
			if !val.IsValid() {
				continue
			}
			valStr := analyzeField(val, val.Type())
			elements = append(elements, fmt.Sprintf("%s=%v", k, valStr))
		}
	default:
		panic(errors.New("the input must be a struct, struct pointer, or map[string]any"))
	}

	sort.Strings(elements)
	return elements
}

func analyzeField(v reflect.Value, t reflect.Type) interface{} {
	if !v.IsValid() || (v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface) && v.IsNil() {
		return nil
	}

	switch t.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int64, reflect.Int16, reflect.Int32:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint()
	case reflect.Float32, reflect.Float64:
		if !isFloatButInteger(v) {
			return fmt.Sprintf("%.2f", v.Float())
		} else {
			return fmt.Sprintf("%d", int(v.Float()))
		}
	case reflect.Bool:
		return v.Bool()
	case reflect.Interface:
		return analyzeField(v.Elem(), v.Elem().Type())
	case reflect.Slice:
		return handleSlice(v, v.Type())
	case reflect.Struct:
		return handleStruct(v, v.Type())
	case reflect.Ptr:
		return analyzeField(v.Elem(), v.Type().Elem())
	case reflect.Map:
		return handleMap(v)
	default:
		return nil
	}
}

func handleMap(v reflect.Value) interface{} {
	if v.Len() == 0 {
		return nil
	}

	keys := v.MapKeys()
	var data []string

	for _, key := range keys {
		if key.Kind() != reflect.String {
			continue // only support string keys
		}
		kStr := key.String()
		val := v.MapIndex(key)
		if !val.IsValid() || (val.Kind() == reflect.Ptr && val.IsNil()) {
			continue
		}
		parsed := analyzeField(val, val.Type())
		if parsed != nil {
			data = append(data, fmt.Sprintf("%s=%v", kStr, parsed))
		}
	}
	sort.Strings(data)
	return base.Base64Encode(strings.Join(data, "&&"))
}

func handleSlice(v reflect.Value, t reflect.Type) interface{} {

	var length = v.Len()
	if length <= 0 {
		return nil
	}

	var data = []string{}
	for i := 0; i < length; i++ {

		var f = analyzeField(v.Index(i), v.Index(i).Type())
		//
		if f != nil {
			data = append(data, f.(string))
		}
	}
	if len(data) > 0 {
		//sort
		sort.Strings(data)
		//join
		return base.Base64Encode(strings.Join(data, ","))
	}
	return nil
}

func handleStruct(v reflect.Value, t reflect.Type) interface{} {

	var data []string

	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	for i := 0; i < t.NumField(); i++ {
		var f = analyzeField(v.Field(i), t.Field(i).Type)
		if f == nil {
			continue
		} else {
			data = append(data, fmt.Sprintf("%s=%v", getTagName(t, i), f))
		}
	}
	//sort the string
	sort.Strings(data)
	//join the string
	return base.Base64Encode(strings.Join(data, "&&"))
}

func getTagName(f reflect.Type, i int) string {
	var tagName = f.Field(i).Tag.Get("json")

	if len(tagName) <= 0 {
		tagName = strings.ToLower(f.Field(i).Name)
	}
	return tagName
}

func isFloatButInteger(v reflect.Value) bool {
	if v.Kind() == reflect.Float32 || v.Kind() == reflect.Float64 {
		f := v.Float()
		return f == float64(int64(f)) // 判断是否是整数
	}
	return false
}
