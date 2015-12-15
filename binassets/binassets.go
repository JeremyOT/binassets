package binassets

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
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

// Count is the number of files that have been packed with Pack()
func (p *Packer) Count() int {
	return len(p.data)
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
		files, err := ioutil.ReadDir(p.config.SourcePath)
		if err != nil {
			return err
		}
		for _, f := range files {
			if err = p.packFile(f, "/", p.config.SourcePath); err != nil {
				return err
			}
		}
		return nil
	}
	err = p.packFile(root, "", path.Dir(p.config.SourcePath))
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
		if p.config.EncryptionKey != nil {
			serverImport += "\n  \"encoding/hex\""
		}
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
		if _, err = output.WriteString("func main(){\n" +
			"  var port int\n" +
			"  flag.IntVar(&port, \"port\", 80, \"The port to bind to\")\n"); err != nil {
			return
		}
		if p.config.EncryptionKey != nil {
			if _, err = output.WriteString("  var encryptionKeyHex string\n" +
				"  flag.StringVar(&encryptionKeyHex, \"key\", \"\", \"The hex-encoded key to use to decrypt the contained files.\")\n"); err != nil {
				return
			}
		}
		if _, err = output.WriteString("  flag.Parse()\n"); err != nil {
			return
		}
		if p.config.EncryptionKey != nil {
			if _, err = output.WriteString("  if encryptionKeyHex == \"\" {\n" +
				"    panic(\"Missing -key argument.\")\n" +
				"  }\n" +
				"  if encryptionKey, err := hex.DecodeString(encryptionKeyHex); err != nil {\n" +
				"    panic(err)\n" +
				"  } else { \n" +
				"    if err := " + p.config.AssetCollection + ".Decrypt(encryptionKey); err != nil {\n" +
				"      panic(err)\n" +
				"    }\n" +
				"  }\n"); err != nil {
				return
			}
		}
		if _, err = output.WriteString("  s := &http.Server{\n" +
			"    Addr:           fmt.Sprintf(\":%d\", port),\n" +
			"    Handler:        http.FileServer(" + p.config.AssetCollection + "),\n" +
			"  }\n" +
			"  log.Fatal(s.ListenAndServe())\n}\n"); err != nil {
			return
		}
	}
	return
}
