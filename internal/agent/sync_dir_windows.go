//go:build windows

package agent

// syncDirectory is a no-op on Windows. NTFS has no equivalent of fsync on a
// directory handle: metadata (including a completed rename) is journaled by
// the filesystem, and FlushFileBuffers on a directory handle is not supported.
// The durability guarantee available here comes from flushing the DATA of the
// temp file before the rename (see writePrivateFile and
// writeTransactionFileAtomic), which both do.
func syncDirectory(string) error { return nil }
