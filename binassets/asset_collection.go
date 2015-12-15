package binassets

import (
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

type asset struct {
	path            string
	data            []byte
	position        int
	assetCollection *AssetCollection
	readDirOffset   int
}

func (a *asset) Stat() (os.FileInfo, error) {
	return a, nil
}

func (a *asset) Name() string {
	return path.Base(a.path)
}

func (a *asset) Size() int64 {
	if a.data == nil {
		return 0
	}
	return int64(len(a.data))
}

func (a *asset) Mode() os.FileMode {
	if a.data == nil {
		return os.ModeDir | 0444
	}
	return 0444
}

func (a *asset) Sys() interface{} {
	return nil
}

func (a *asset) IsDir() bool {
	return a.data == nil
}

func (a *asset) ModTime() time.Time {
	return time.Now()
}

func (a *asset) Close() error {
	return nil
}

func (a *asset) Read(p []byte) (n int, err error) {
	n = copy(p, a.data[a.position:])
	a.position += n
	if len(p) > 0 && n == 0 {
		err = io.EOF
	}
	return
}

func (a *asset) Seek(offset int64, whence int) (n int64, err error) {
	switch whence {
	case 1:
		a.position += int(offset)
	case 2:
		a.position = len(a.data) + int(offset)
	default:
		a.position = int(offset)
	}
	if a.position > len(a.data) {
		a.position = len(a.data)
	}
	if a.position < 0 {
		a.position = 0
	}
	n = int64(a.position)
	return
}

func (a *asset) Readdir(count int) (files []os.FileInfo, err error) {
	files = make([]os.FileInfo, 0)
	if !a.IsDir() {
		err = io.EOF
		a.readDirOffset = 0
		return
	}
	basePath := pathComponents(a.path)
	dirs := map[string]struct{}{}
FindDirs:
	for k, v := range *a.assetCollection {
		if k == a.path || !strings.HasPrefix(k, a.path) {
			continue
		}
		components := pathComponents(k)
		for i, c := range basePath {
			if c != components[i] {
				continue FindDirs
			}
		}
		if len(components) > len(basePath)+1 {
			dirs[path.Join(components[:len(basePath)+1]...)] = struct{}{}
			continue
		}
		newAsset := &asset{data: v, path: k, assetCollection: a.assetCollection}
		info, _ := newAsset.Stat()
		files = append(files, info)
	}
	for d := range dirs {
		newAsset := &asset{data: nil, path: d, assetCollection: a.assetCollection}
		info, _ := newAsset.Stat()
		files = append(files, info)
	}
	files = files[a.readDirOffset:]
	if count > 0 && len(files) > count {
		files = files[:count]
	}
	if len(files) == 0 {
		err = io.EOF
		a.readDirOffset = 0
	}
	a.readDirOffset += len(files)
	return
}

// AssetCollection is a map containing a set of assets and implements http.FileSystem
type AssetCollection map[string][]byte

// Decrypt and validate this AssetCollection witht he given key.
func (c *AssetCollection) Decrypt(key []byte) (err error) {
	for k, v := range *c {
		decrypted, err := Decrypt(key, v)
		if err != nil {
			return err
		}
		(*c)[k] = decrypted
	}
	return
}

func pathComponents(p string) (output []string) {
	components := strings.Split(p, "/")
	output = make([]string, 0, len(components))
	for _, c := range components {
		if c != "" {
			output = append(output, c)
		}
	}
	return
}

// Open implements http.FileSystem.Open()
func (c AssetCollection) Open(path string) (a http.File, err error) {
	data, ok := c[path]
	if ok {
		return &asset{data: data, path: path, assetCollection: &c}, nil
	}
	basePath := pathComponents(path)
FindDir:
	for k := range c {
		components := pathComponents(k)
		if len(components) <= len(basePath) {
			continue
		}
		for i, seg := range basePath {
			if components[i] != seg {
				continue FindDir
			}
		}
		return &asset{data: nil, path: path, assetCollection: &c}, nil
	}
	return nil, os.ErrNotExist
}
