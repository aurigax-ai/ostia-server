package testkit

import (
	"maps"
	"slices"
)

type Files map[string]map[string]string

type Conflict struct {
	Path   string
	Key    string
	Local  *string
	Remote *string
}

func (f Files) Clone() Files {
	out := Files{}
	for path, keys := range f {
		out[path] = maps.Clone(keys)
	}
	return out
}

func lookup(f Files, path, key string) *string {
	if v, ok := f[path][key]; ok {
		return &v
	}
	return nil
}

func same(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func Merge(base, local, remote Files) (Files, []Conflict) {
	merged := Files{}
	var conflicts []Conflict
	paths := map[string]bool{}
	for _, f := range []Files{base, local, remote} {
		for path := range f {
			paths[path] = true
		}
	}
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		keys := map[string]bool{}
		for _, f := range []Files{base, local, remote} {
			for key := range f[path] {
				keys[key] = true
			}
		}
		out := map[string]string{}
		for _, key := range slices.Sorted(maps.Keys(keys)) {
			b, l, r := lookup(base, path, key), lookup(local, path, key), lookup(remote, path, key)
			var chosen *string
			switch {
			case same(l, r):
				chosen = l
			case same(l, b):
				chosen = r
			case same(r, b):
				chosen = l
			default:
				chosen = l
				conflicts = append(conflicts, Conflict{Path: path, Key: key, Local: l, Remote: r})
			}
			if chosen != nil {
				out[key] = *chosen
			}
		}
		if len(out) > 0 || base[path] != nil || local[path] != nil || remote[path] != nil {
			merged[path] = out
		}
	}
	return merged, conflicts
}

func Equal(a, b Files) bool {
	if len(a) != len(b) {
		return false
	}
	for path, keys := range a {
		other, ok := b[path]
		if !ok || !maps.Equal(keys, other) {
			return false
		}
	}
	return true
}
