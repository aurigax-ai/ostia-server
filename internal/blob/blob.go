package blob

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

var ErrNotFound = errors.New("blob not found")

var ErrTooLarge = errors.New("blob too large")

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+){1,2}$`)

type Upload interface {
	Size() int64
	Sum() [32]byte
	Commit() error
	Abort()
}

type Store interface {
	Put(ctx context.Context, key string, r io.Reader, max int64) (Upload, error)
	Open(ctx context.Context, key string) (io.ReadSeekCloser, int64, error)
	Delete(ctx context.Context, key string) error
}

type Disk struct {
	root string
}

func NewDisk(root string) (*Disk, error) {
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o700); err != nil {
		return nil, err
	}
	return &Disk{root: root}, nil
}

func (d *Disk) path(key string) (string, error) {
	if !keyPattern.MatchString(key) {
		return "", fmt.Errorf("invalid blob key %q", key)
	}
	return filepath.Join(d.root, "objects", filepath.FromSlash(key)), nil
}

type diskUpload struct {
	tmp   string
	final string
	size  int64
	sum   [32]byte
}

func (u *diskUpload) Size() int64   { return u.size }
func (u *diskUpload) Sum() [32]byte { return u.sum }
func (u *diskUpload) Abort()        { _ = os.Remove(u.tmp) }
func (u *diskUpload) Commit() error {
	if err := os.MkdirAll(filepath.Dir(u.final), 0o700); err != nil {
		u.Abort()
		return err
	}
	if err := os.Rename(u.tmp, u.final); err != nil {
		u.Abort()
		return err
	}
	return nil
}

func (d *Disk) Put(ctx context.Context, key string, r io.Reader, max int64) (Upload, error) {
	final, err := d.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Join(d.root, "tmp"), "upload-*")
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(&ctxReader{ctx: ctx, r: r}, max+1))
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil && n > max {
		err = ErrTooLarge
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return nil, err
	}
	u := &diskUpload{tmp: f.Name(), final: final, size: n}
	copy(u.sum[:], hash.Sum(nil))
	return u, nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func (d *Disk) Open(_ context.Context, key string) (io.ReadSeekCloser, int64, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

func (d *Disk) Delete(_ context.Context, key string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
