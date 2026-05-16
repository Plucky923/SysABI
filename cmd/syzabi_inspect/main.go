package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type callInfo struct {
	Index   int      `json:"index"`
	Name    string   `json:"name"`
	Base    string   `json:"base"`
	Variant *string  `json:"variant"`
	Returns *resInfo `json:"returns"`
	Uses    []useInfo `json:"uses"`
}

type resInfo struct {
	Resource string `json:"resource"`
	Symbol   string `json:"symbol"`
}

type useInfo struct {
	Resource      string `json:"resource"`
	Symbol        string `json:"symbol"`
	ProducerIndex int    `json:"producer_index"`
}

type syscallPairs [][]string

type shapeInfo struct {
	CallCount                       int      `json:"call_count"`
	HasResourceLifecycle            bool     `json:"has_resource_lifecycle"`
	HasCrossSubsystemInteraction    bool     `json:"has_cross_subsystem_interaction"`
	HasNegativeResourceUse          bool     `json:"has_negative_resource_use"`
	HasEnvironmentSensitiveSyscall  bool     `json:"has_environment_sensitive_syscall"`
	Families                        []string `json:"families"`
}

type output struct {
	ProgramID                     string      `json:"program_id"`
	NormalizedSyz                 string      `json:"normalized_syz"`
	Arch                          string      `json:"arch"`
	TargetOS                      string      `json:"target_os"`
	SyscallList                   []string    `json:"syscall_list"`
	FullSyscallList               []string    `json:"full_syscall_list"`
	ResourceClasses               []string    `json:"resource_classes"`
	RequiredSyscalls              []string    `json:"required_syscalls"`
	VariantSyscalls               []string    `json:"variant_syscalls"`
	SyscallPairs                  [][]string  `json:"syscall_pairs"`
	SyscallNgrams                 map[string][][]string `json:"syscall_ngrams"`
	Resources                     map[string]resMeta   `json:"resources"`
	Shape                         shapeInfo   `json:"shape"`
	UsesPseudoSyscalls            bool        `json:"uses_pseudo_syscalls"`
	UsesThreadingSensitiveFeature bool        `json:"uses_threading_sensitive_features"`
	CallCount                     int         `json:"call_count"`
	Calls                         []callInfo  `json:"calls"`
}

type resMeta struct {
	Produced      bool  `json:"produced"`
	Consumed      bool  `json:"consumed"`
	ProducerCalls []int `json:"producer_calls"`
	ConsumerCalls []int `json:"consumer_calls"`
}

var familySets = map[string]map[string]struct{}{
	"fs":     {"open": {}, "openat": {}, "close": {}, "read": {}, "write": {}, "pread64": {}, "pwrite64": {}, "lseek": {}, "newfstatat": {}, "fstat": {}, "getdents64": {}, "unlinkat": {}, "mkdirat": {}, "renameat": {}, "renameat2": {}, "linkat": {}, "symlinkat": {}, "readlinkat": {}},
	"mm":     {"mmap": {}, "munmap": {}, "mprotect": {}, "brk": {}, "mremap": {}, "madvise": {}, "msync": {}, "ftruncate": {}},
	"proc":   {"clone": {}, "fork": {}, "vfork": {}, "execve": {}, "wait4": {}, "exit": {}, "exit_group": {}, "getpid": {}, "getppid": {}, "gettid": {}, "set_tid_address": {}},
	"poll":   {"pipe": {}, "pipe2": {}, "poll": {}, "ppoll": {}, "select": {}, "pselect6": {}, "epoll_create": {}, "epoll_create1": {}, "epoll_ctl": {}, "epoll_wait": {}},
	"socket": {"socket": {}, "bind": {}, "listen": {}, "accept": {}, "accept4": {}, "connect": {}, "sendto": {}, "recvfrom": {}, "sendmsg": {}, "recvmsg": {}, "shutdown": {}, "getsockopt": {}, "setsockopt": {}},
}

var environmentSensitiveSyscalls = map[string]struct{}{
	"getrandom": {}, "getcpu": {}, "clock_gettime": {}, "gettimeofday": {},
	"time": {}, "times": {}, "getrusage": {}, "sysinfo": {},
	"uname": {}, "sched_getaffinity": {}, "getpid": {}, "gettid": {},
}

func main() {
	progPath := flag.String("prog", "", "path to a .syz program")
	targetOS := flag.String("os", "linux", "target OS")
	arch := flag.String("arch", "amd64", "target architecture")
	strict := flag.Bool("strict", false, "strict parse mode")
	flag.Parse()

	if *progPath == "" {
		fmt.Fprintln(os.Stderr, "-prog is required")
		os.Exit(1)
	}
	target, err := prog.GetTarget(*targetOS, *arch)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, err := os.ReadFile(*progPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	mode := prog.NonStrict
	if *strict {
		mode = prog.Strict
	}
	p, err := target.Deserialize(data, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse_error: %v\n", err)
		os.Exit(2)
	}

	normalized := strings.TrimSpace(string(p.Serialize())) + "\n"
	sum := sha256.Sum256([]byte(normalized))
	calls := buildCallInfo(p)
	baseCalls := uniqueBaseCalls(p)
	out := output{
		ProgramID:       hex.EncodeToString(sum[:]),
		NormalizedSyz:   normalized,
		Arch:            *arch,
		TargetOS:        *targetOS,
		CallCount:       len(p.Calls),
		SyscallList:     baseCalls,
		FullSyscallList: collectFullCalls(p),
		RequiredSyscalls: baseCalls,
		VariantSyscalls:  collectFullCalls(p),
		SyscallPairs:    buildSyscallPairs(p),
		SyscallNgrams:   map[string][][]string{"3": buildSyscallNgrams(p, 3)},
		Resources:       buildResourceMeta(p),
		Shape:           buildShape(p),
		Calls:           calls,
		ResourceClasses: collectResourceClasses(p),
	}
	out.UsesPseudoSyscalls = hasPseudo(p)
	out.UsesThreadingSensitiveFeature = hasThreadSensitiveProps(p)

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func uniqueBaseCalls(p *prog.Prog) []string {
	seen := make(map[string]struct{})
	var list []string
	for _, call := range p.Calls {
		name := call.Meta.CallName
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func collectFullCalls(p *prog.Prog) []string {
	seen := make(map[string]struct{})
	var list []string
	for _, call := range p.Calls {
		name := call.Meta.Name
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func collectResourceClasses(p *prog.Prog) []string {
	seen := make(map[string]struct{})
	for _, call := range p.Calls {
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			if res, ok := arg.Type().(*prog.ResourceType); ok {
				seen[res.TypeName] = struct{}{}
			}
		})
	}
	var list []string
	for name := range seen {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func hasPseudo(p *prog.Prog) bool {
	for _, call := range p.Calls {
		if strings.HasPrefix(call.Meta.CallName, "syz_") {
			return true
		}
	}
	return false
}

func hasThreadSensitiveProps(p *prog.Prog) bool {
	for _, call := range p.Calls {
		if call.Props.Async || call.Props.FailNth > 0 || call.Props.Rerun > 0 {
			return true
		}
	}
	return false
}

func splitVariant(name string) (string, *string) {
	if idx := strings.IndexByte(name, '$'); idx >= 0 {
		base := name[:idx]
		variant := name[idx+1:]
		return base, &variant
	}
	return name, nil
}

func buildCallInfo(p *prog.Prog) []callInfo {
	var calls []callInfo
	resProducers := make(map[string][]int)
	for i, call := range p.Calls {
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			if res, ok := arg.Type().(*prog.ResourceType); ok {
				resProducers[res.TypeName] = append(resProducers[res.TypeName], i)
			}
		})
	}

	for i, call := range p.Calls {
		base, variant := splitVariant(call.Meta.Name)
		ci := callInfo{
			Index:   i,
			Name:    call.Meta.Name,
			Base:    base,
			Variant: variant,
		}
		// Check if this call returns a resource
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			if res, ok := arg.Type().(*prog.ResourceType); ok {
				if ci.Returns == nil {
					ci.Returns = &resInfo{}
				}
				ci.Returns.Resource = res.TypeName
				sym := "r" + fmt.Sprint(i)
				if res.Dir() == prog.DirOut {
					ci.Returns.Symbol = sym
				}
			}
		})
		// Check if this call uses resources from previous calls
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			if res, ok := arg.Type().(*prog.ResourceType); ok {
				if res.Dir() == prog.DirIn {
					producers := resProducers[res.TypeName]
					prodIdx := -1
					for _, p := range producers {
						if p < i {
							prodIdx = p
						}
					}
					ci.Uses = append(ci.Uses, useInfo{
						Resource:      res.TypeName,
						Symbol:        "r" + fmt.Sprint(prodIdx),
						ProducerIndex: prodIdx,
					})
				}
			}
		})
		calls = append(calls, ci)
	}
	return calls
}

func buildSyscallPairs(p *prog.Prog) [][]string {
	var pairs [][]string
	for i := 0; i < len(p.Calls)-1; i++ {
		pairs = append(pairs, []string{p.Calls[i].Meta.CallName, p.Calls[i+1].Meta.CallName})
	}
	return pairs
}

func buildSyscallNgrams(p *prog.Prog, n int) [][]string {
	var ngrams [][]string
	for i := 0; i <= len(p.Calls)-n; i++ {
		gram := make([]string, n)
		for j := 0; j < n; j++ {
			gram[j] = p.Calls[i+j].Meta.CallName
		}
		ngrams = append(ngrams, gram)
	}
	return ngrams
}

func buildResourceMeta(p *prog.Prog) map[string]resMeta {
	meta := make(map[string]resMeta)
	for i, call := range p.Calls {
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			res, ok := arg.Type().(*prog.ResourceType)
			if !ok {
				return
			}
			m := meta[res.TypeName]
			if res.Dir() == prog.DirOut {
				m.Produced = true
				m.ProducerCalls = append(m.ProducerCalls, i)
			}
			if res.Dir() == prog.DirIn {
				m.Consumed = true
				m.ConsumerCalls = append(m.ConsumerCalls, i)
			}
			meta[res.TypeName] = m
		})
	}
	return meta
}

func buildShape(p *prog.Prog) shapeInfo {
	s := shapeInfo{
		CallCount: len(p.Calls),
	}
	resources := buildResourceMeta(p)
	for _, m := range resources {
		if m.Produced && m.Consumed {
			s.HasResourceLifecycle = true
		}
		if m.Consumed && len(m.ProducerCalls) == 0 {
			s.HasNegativeResourceUse = true
		}
	}
	families := make(map[string]struct{})
	for _, call := range p.Calls {
		base, _ := splitVariant(call.Meta.Name)
		for fam, members := range familySets {
			if _, ok := members[base]; ok {
				families[fam] = struct{}{}
			}
		}
		if _, ok := environmentSensitiveSyscalls[base]; ok {
			s.HasEnvironmentSensitiveSyscall = true
		}
	}
	if len(families) > 1 {
		s.HasCrossSubsystemInteraction = true
	}
	for fam := range families {
		s.Families = append(s.Families, fam)
	}
	sort.Strings(s.Families)
	return s
}
