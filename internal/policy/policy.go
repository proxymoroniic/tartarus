package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

type PolicyFlags struct {
	AllowFileAccess bool `json:"allow_file_access"`
	AllowNetwork    bool `json:"allow_network"`
	AllowExec       bool `json:"allow_exec"`
	AllowSetuid     bool `json:"allow_setuid"`
	AllowPtrace     bool `json:"allow_ptrace"`
}

func (f PolicyFlags) ToBitmap() uint8 {
	var bits uint8
	if f.AllowFileAccess {
		bits |= 1 << 0
	}
	if f.AllowNetwork {
		bits |= 1 << 1
	}
	if f.AllowExec {
		bits |= 1 << 2
	}
	if f.AllowSetuid {
		bits |= 1 << 4
	}
	if f.AllowPtrace {
		bits |= 1 << 5
	}
	return bits
}

type Role struct {
	ID    uint32      `json:"-"` // auto-assigned, not in JSON
	Name  string      `json:"-"` // derived from the map key, not in JSON
	Flags PolicyFlags `json:"flags"`
}

type Policy struct {
	Roles map[string]Role `json:"roles"`
}

func (p Policy) RoleByName(name string) (Role, bool) {
	r, ok := p.Roles[name]
	return r, ok
}

func DefaultPolicy() Policy {
	p := Policy{
		Roles: map[string]Role{
			"restricted": {
				Flags: PolicyFlags{},
			},
			"permissive": {
				Flags: PolicyFlags{
					AllowFileAccess: true,
					AllowNetwork:    true,
					AllowExec:       true,
				},
			},
		},
	}
	p.assignIDs()
	return p
}

func LoadFromFile(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	p.assignIDs()
	return p, nil
}

func (p *Policy) assignIDs() {
	id := uint32(1)
	for name, role := range p.Roles {
		role.ID = id
		role.Name = name
		p.Roles[name] = role
		id++
	}
}
