//go:build ignore

package main

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"
)

var (
	targetProg  = flag.String("target_prog", "./hello", "target program to analyze")
	targetsFile = flag.String("targets_json", "./targets_to_find.json", "target offsets to find from target program")
	resultFile  = flag.String("result", "../instrumentor.h", "offsets result file to write to")
)

type targetOffset struct {
	Struct string   `json:"struct"`
	Fields []string `json:"fields"`
}

type targetsForPackage struct {
	Package         string         `json:"package"`
	TargetOffsets   []targetOffset `json:"target_offsets"`
	TargetArrayVars []string       `json:"target_arrays"`
}

func main() {
	exe, err := elf.Open(*targetProg)
	if err != nil {
		log.Fatalf("Open target program: %v", err)
	}
	dwarf, err := exe.DWARF()
	if err != nil {
		log.Fatalf("Parse DWARF sections: %v", err)
	}
	reader := dwarf.Reader()

	fIn, err := os.Open(*targetsFile)
	if err != nil {
		log.Fatalf("Open target offsets file: %v", err)
	}
	fOut, err := os.OpenFile(*resultFile, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Open offsets result file: %v", err)
	}
	targetOffsetsJSONBytes, err := io.ReadAll(fIn)
	if err != nil {
		log.Fatalf("Read target offsets file: %v", err)
	}
	var targets []targetsForPackage
	err = json.Unmarshal(targetOffsetsJSONBytes, &targets)
	if err != nil {
		log.Fatalf("Parse target offsets json: %v", err)
	}

	for _, pkgTarget := range targets {
		for _, structTarget := range pkgTarget.TargetOffsets {
			reader.Seek(0)
			structName := fmt.Sprintf("%s.%s", pkgTarget.Package, structTarget.Struct)
			_, err = findEntryForStruct(reader, structName)
			if err != nil {
				log.Fatalf("Error finding struct %s: %v", structName, err)
			}
			fieldSet := make(map[string]struct{})
			for _, field := range structTarget.Fields {
				fieldSet[field] = struct{}{}
			}
			fieldOffsets, err := findFieldOffsets(reader, fieldSet)
			if err != nil {
				log.Fatalf("Error finding field offsets for struct %s: %v", structName, err)
			}
			for _, fieldOffset := range fieldOffsets {
				fmt.Fprintf(fOut, "#define %s_%s_%s_OFFSET %d\n", strings.ToUpper(pkgTarget.Package), strings.ToUpper(structTarget.Struct), strings.ToUpper(fieldOffset.field), fieldOffset.offset)
			}
		}
		for _, targetArrVar := range pkgTarget.TargetArrayVars {
			reader.Seek(0)
			arrVarName := fmt.Sprintf("%s.%s", pkgTarget.Package, targetArrVar)
			_, err = findEntryForVariable(reader, arrVarName)
			if err != nil {
				log.Fatalf("Error finding array variable %s: %v", arrVarName, err)
			}
			arrTypeOffset, err := findVariableTypeOffset(reader)
			if err != nil {
				log.Fatalf("Error finding type of array variable %s: %v", arrVarName, err)
			}
			reader.Seek(arrTypeOffset)
			arrLen, err := findArrayLength(reader)
			if err != nil {
				log.Fatalf("Error finding length of array %s: %v", arrVarName, err)
			}
			fmt.Fprintf(fOut, "#define %s_%s_LENGTH %d\n", strings.ToUpper(pkgTarget.Package), strings.ToUpper(targetArrVar), arrLen)
		}
	}
}

func findEntryForStruct(reader *dwarf.Reader, structName string) (*dwarf.Entry, error) {
	for {
		entry, err := reader.Next()
		if err != nil {
			log.Fatalf("Error decoding DWARF entry: %v", err)
		}
		if entry == nil {
			break
		}
		if entry.Tag == dwarf.TagStructType {
			nameAttrIdx := slices.IndexFunc(entry.Field, func(field dwarf.Field) bool {
				return field.Attr == dwarf.AttrName
			})
			if nameAttrIdx >= 0 && entry.Field[nameAttrIdx].Val.(string) == structName {
				return entry, nil
			}
		}
	}
	return nil, fmt.Errorf("cannot find DWARF entry for struct")
}

type fieldOffset struct {
	field  string
	offset int64
}

func findFieldOffsets(reader *dwarf.Reader, fieldSet map[string]struct{}) ([]fieldOffset, error) {
	var res []fieldOffset
	for {
		entry, err := reader.Next()
		if err != nil {
			log.Fatalf("Error decoding DWARF entry: %v", err)
		}
		if entry == nil || len(fieldSet) == 0 {
			break
		}
		if entry.Tag == dwarf.TagMember {
			nameAttrIdx := slices.IndexFunc(entry.Field, func(field dwarf.Field) bool {
				return field.Attr == dwarf.AttrName
			})
			locAttrIdx := slices.IndexFunc(entry.Field, func(field dwarf.Field) bool {
				return field.Attr == dwarf.AttrDataMemberLoc
			})
			if nameAttrIdx >= 0 && locAttrIdx >= 0 {
				fieldName := entry.Field[nameAttrIdx].Val.(string)
				if _, ok := fieldSet[fieldName]; ok {
					res = append(res, fieldOffset{
						field:  fieldName,
						offset: entry.Field[locAttrIdx].Val.(int64),
					})
					delete(fieldSet, fieldName)
				}
			}
		}
	}
	if len(fieldSet) > 0 {
		return nil, fmt.Errorf("cannot find offset for fields %v", fieldSet)
	}
	return res, nil
}

func findEntryForVariable(reader *dwarf.Reader, varName string) (*dwarf.Entry, error) {
	for {
		entry, err := reader.Next()
		if err != nil {
			log.Fatalf("Error decoding DWARF entry: %v", err)
		}
		if entry == nil {
			break
		}
		if entry.Tag == dwarf.TagVariable {
			nameAttrIdx := slices.IndexFunc(entry.Field, func(field dwarf.Field) bool {
				return field.Attr == dwarf.AttrName
			})
			if nameAttrIdx >= 0 && entry.Field[nameAttrIdx].Val.(string) == varName {
				return entry, nil
			}
		}
	}
	return nil, fmt.Errorf("cannot find DWARF entry for variable")
}

func findVariableTypeOffset(reader *dwarf.Reader) (dwarf.Offset, error) {
	for {
		entry, err := reader.Next()
		if err != nil {
			log.Fatalf("Error decoding DWARF entry: %v", err)
		}
		if entry == nil {
			break
		}
		typeIdx := slices.IndexFunc(entry.Field, func(field dwarf.Field) bool {
			return field.Attr == dwarf.AttrType
		})
		if typeIdx >= 0 {
			return entry.Field[typeIdx].Val.(dwarf.Offset), nil
		}
	}
	return 0, fmt.Errorf("cannot determine type of variable")
}

// findArrayLength only works for 1-d array for now.
func findArrayLength(reader *dwarf.Reader) (int64, error) {
	for {
		entry, err := reader.Next()
		if err != nil {
			log.Fatalf("Error decoding DWARF entry: %v", err)
		}
		if entry == nil {
			break
		}
		if entry.Tag == dwarf.TagSubrangeType {
			countIdx := slices.IndexFunc(entry.Field, func(field dwarf.Field) bool {
				return field.Attr == dwarf.AttrCount
			})
			if countIdx >= 0 {
				return entry.Field[countIdx].Val.(int64), nil
			}
		}
	}
	return 0, fmt.Errorf("cannot determine length of array type")
}
