//go:build !windows

package platform

import "golang.org/x/sys/unix"

// Info returns operating-system facts for diagnostics.
func Info() map[string]any {
	m := Base()
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		m["kernel"] = unix.ByteSliceToString(u.Release[:])
	}
	return m
}

// DiskFree returns free and total bytes of the filesystem holding path.
func DiskFree(path string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}
