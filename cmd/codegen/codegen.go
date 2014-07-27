package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/jfrabaute/libtrace/cmd/codegen/types"
)

// Used to generate the "syscalls" array
//  go run codegen/gensyscallmap.go < codegen/syscall_OS_ARCH.csv > trace_syscalls_gen_OS_ARCH.go
//
// Source:
// linux_386:   http://docs.cs.up.ac.za/programming/asm/derick_tut/syscalls.html (no named params)
// linux_amd64: http://blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64
func main() {
	// Read Stdin
	reader := csv.NewReader(os.Stdin)
	reader.Comma = '\t'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	fmt.Println(`package libtrace

import "reflect"

var syscalls = []*Signature{
`)

	i := 0
	id := 0
	// Output
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		if id, err = strconv.Atoi(rec[0]); err != nil {
			log.Fatal(err)
		}
		for id > i+1 {
			fmt.Printf("\t&unknownSignature, // %d\n", i)
			i++
		}
		out := fmt.Sprintf(`%s&Signature{Id: %s, Name: "%s"`, "\t", rec[0], rec[1][4:])

		out += ", Args: []Arg{"
		for i, arg := range rec[2:] {
			c := false
			p := false
			if len(arg) == 0 {
				break
			}

			if len(arg) > 6 && arg[:6] == "const " {
				arg = arg[6:]
				c = true
			} else if len(arg) > 7 && arg[:7] == "fconst " {
				arg = arg[7:]
				c = true
			}
			pos := strings.LastIndex(arg, "*")
			if pos == -1 {
				pos = strings.LastIndex(arg, " ")
				if pos == -1 {
					log.Fatalf("Unable to read param: '%s' (syscall: %+v)", arg, rec)
				}
			}
			name := strings.Trim(arg[pos:], " ")
			typ := strings.Trim(arg[:pos], " ")

			var t string
			var ok bool

			if name[0] == '*' {
				name = name[1:]
				p = true
			}

			// Special case for "char *"
			if typ == "char" && p {
				typ = "char *"
				p = false
			}

			if strings.Index(typ, "struct ") == 0 || strings.Index(typ, "union ") == 0 {
				t = "reflect.TypeOf(struct{}{})"
			} else if t, ok = types.Types[typ]; !ok {
				log.Fatalf("Unable to find type: '%s'\nrec= %+v", typ, rec)
			}
			if i > 0 {
				out += ","
			}
			out += fmt.Sprintf(`Arg{Name: "%s", Type: %s, Ptr: %v, Const: %v}`, name, t, p, c)
		}
		out += "}"
		out += "},"

		fmt.Println(out)

		i++
	}

	fmt.Println("}")

}

func toTitle(s string) string {
	return strings.ToUpper(s[0:1]) + s[1:]
}
