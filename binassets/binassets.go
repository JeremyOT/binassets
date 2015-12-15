package binassets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// Config contains parameters necessary when invoking Pack()
type Config struct {
	// Package is the package to use for the output file
	Package string
	// AssetCollection is the name of the variable that will store the instantiated AssetCollection
	AssetCollection string
	// EncryptionKey, if provided, will be used to encrypt all output data and will be
	// required when loading assets. Use either 16, 24, or 32 bytes to select AES-128,
	// AES-192, or AES-256.
	EncryptionKey []byte
	// OutputPath is the path the asset file will be written to. Must be a .go file.
	OutputPath string
	// SourcePath is the path assets will be read from
	SourcePath string
	// BinAssetsPackage is the path bin assets will be read from - in order to support vendoring
	BinAssetsPackage string
}

type asset struct {
	path            string
	data            []byte
	position        int
	assetCollection *AssetCollection
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
	if !a.IsDir() {
		return nil, nil
	}
	basePath := strings.Split(a.path, "/")
	files = make([]os.FileInfo, 0)
	dirs := map[string]struct{}{}
FindDirs:
	for k, v := range *a.assetCollection {
		if k == a.path || !strings.HasPrefix(k, a.path) {
			continue
		}
		components := strings.Split(k, "/")
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

// Open implements http.FileSystem.Open()
func (c AssetCollection) Open(path string) (a http.File, err error) {
	data, ok := c[path]
	if ok {
		return &asset{data: data, path: path, assetCollection: &c}, nil
	}
	if len(path) == 0 {
		return nil, os.ErrNotExist
	}
	basePath := strings.Split(path, "/")
FindDir:
	for k := range c {
		components := strings.Split(k, "/")
		if len(components) != len(basePath)+1 {
			continue
		}
		for i, c := range basePath {
			if components[i] != c {
				continue FindDir
			}
		}
		return &asset{data: nil, path: path, assetCollection: &c}, nil
	}
	return nil, os.ErrNotExist
}

// Packer packs files based on a Config
type Packer struct {
	config Config
	data   AssetCollection
}

// New creates a new Packer with the given Config
func New(config Config) *Packer {
	if config.AssetCollection == "" {
		config.AssetCollection = "Assets"
	}
	if config.BinAssetsPackage == "" {
		config.BinAssetsPackage = "github.com/JeremyOT/binassets/binassets"
	}
	return &Packer{config: config, data: AssetCollection{}}
}

// Encrypt data with the given key
func Encrypt(key []byte, data []byte) (output []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	for i := 0; i < padding; i++ {
		data = append(data, byte(padding))
	}
	ciphertext := make([]byte, aes.BlockSize+len(data), aes.BlockSize+len(data)+sha256.Size)
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	ciphertext = append(ciphertext, mac.Sum(nil)...)
	output = ciphertext
	return
}

// Decrypt and validate data with the given key
func Decrypt(key []byte, data []byte) (output []byte, err error) {
	if len(data) < (aes.BlockSize*2+sha256.Size) || (len(data)-sha256.Size)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid data length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data[:len(data)-sha256.Size])
	expectedMac := mac.Sum(nil)
	if !hmac.Equal(expectedMac, data[len(data)-sha256.Size:]) {
		return nil, errors.New("Invalid HMAC")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize : len(data)-sha256.Size]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext[:len(ciphertext)-int(ciphertext[len(ciphertext)-1])], nil
}

func (p *Packer) transform(input []byte) (output []byte, err error) {
	if p.config.EncryptionKey != nil {
		return Encrypt(p.config.EncryptionKey, input)
	}
	return input, nil
}

func (p *Packer) packFile(file os.FileInfo, prefix, root string) (err error) {
	if file.IsDir() {
		files, err := ioutil.ReadDir(path.Join(root, file.Name()))
		if err != nil {
			return err
		}
		newPrefix := path.Join(prefix, file.Name())
		newRoot := path.Join(root, file.Name())
		for _, f := range files {
			if err = p.packFile(f, newPrefix, newRoot); err != nil {
				return err
			}
		}
	} else {
		assetPath := path.Join(prefix, file.Name())
		f, err := os.Open(path.Join(root, file.Name()))
		if err != nil {
			return err
		}
		data, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		transformed, err := p.transform(data)
		if err != nil {
			return err
		}
		p.data[assetPath] = transformed
	}
	return
}

// Pack creates a packed .go file based on the assets and options specified in config.
func (p *Packer) Pack() (err error) {
	root, err := os.Stat(p.config.SourcePath)
	if err != nil {
		return err
	}
	if root.IsDir() {
		err = p.packFile(root, "/", path.Dir(p.config.SourcePath))
		if err != nil {
			return
		}
	}
	err = p.packFile(root, "", path.Dir(p.config.SourcePath))
	if err != nil {
		return
	}
	return
}

func (p *Packer) Write() (err error) {
	if path.Ext(p.config.OutputPath) != ".go" {
		return errors.New("Invalid output path: " + p.config.OutputPath)
	}
	output, err := os.Create(p.config.OutputPath)
	if err != nil {
		return err
	}
	serverImport := ""
	if p.config.Package == "main" {
		serverImport = "\n  \"net/http\"\n  \"flag\"\n  \"log\"\n  \"fmt\""
	}
	if _, err = output.WriteString(fmt.Sprintf("package %s\n\nimport (\n  \"%s\"%s\n)\n\nvar %s = binassets.AssetCollection{\n", p.config.Package, p.config.BinAssetsPackage, serverImport, p.config.AssetCollection)); err != nil {
		return
	}
	for path, data := range p.data {
		if _, err = output.WriteString("  \"" + path + "\": []byte(\""); err != nil {
			return
		}
		h := hex.EncodeToString(data)
		for i := 0; i < len(data); i++ {
			if _, err = output.WriteString("\\x" + h[2*i:2*i+2]); err != nil {
				return
			}
		}
		if _, err = output.WriteString("\"),\n"); err != nil {
			return
		}
	}
	if _, err = output.WriteString("\n}\n"); err != nil {
		return
	}
	if p.config.Package == "main" {
		if _, err = output.WriteString(fmt.Sprintf("func main(){\n"+
			"  var port int\n"+
			"  flag.IntVar(&port, \"port\", 80, \"The port to bind to\")\n"+
			"  flag.Parse()\n"+
			"  s := &http.Server{\n"+
			"    Addr:           fmt.Sprintf(\":%%d\", port),\n"+
			"    Handler:        http.FileServer(%s),\n"+
			"  }\n"+
			"  log.Fatal(s.ListenAndServe())\n}\n", p.config.AssetCollection)); err != nil {
			return
		}
	}
	return
}
