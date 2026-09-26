package snmp

import "sort"

func sortStrings(s []string, less func(i, j int) bool) { sort.SliceStable(s, less) }
