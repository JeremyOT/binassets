package main

import (
	"encoding/hex"
	"flag"
	"log"

	"github.com/JeremyOT/binassets/binassets"
)

func main() {
	config := binassets.Config{}
	flag.StringVar(&config.Package, "-package", "", "The package name to use in the generated file")
	flag.StringVar(&config.AssetCollection, "-variable", "Assets", "Overrides name of the AssetCollection variable in the output file.")
	var keyHex string
	flag.StringVar(&keyHex, "-encryption-key", "", "An option encryption key, hex encoded, that will be used to encrypt all stored data. Before the resulting AssetCollection can be used, its Decrypt(key []byte) method must be called with the key passed here.")
	flag.StringVar(&config.OutputPath, "-output", "", "The path to write to. Must be a .go file.")
	flag.StringVar(&config.SourcePath, "-source", "", "The path to read from. Either a directory or file.")
	flag.StringVar(&config.BinAssetsPackage, "-binassets-package", "github.com/JeremyOT/binassets", "Overrides the import path for generated files to support vendoring.")
	flag.Parse()
	if config.Package == "" {
		panic("Missing required --package flag.")
	}
	if config.OutputPath == "" {
		panic("Missing required --output flag.")
	}
	if config.SourcePath == "" {
		panic("Missing required --source flag.")
	}
	if keyHex != "" {
		if key, err := hex.DecodeString(keyHex); err != nil {
			panic("Invalid encryption key")
		} else {
			config.EncryptionKey = key
		}
	}
	packer := binassets.New(config)
	if err := packer.Pack(); err != nil {
		panic(err)
	}
	if err := packer.Write(); err != nil {
		panic(err)
	}
	log.Printf("Packed files from %s to %s", config.SourcePath, config.OutputPath)
}
