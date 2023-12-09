package main

import (
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <path-to-binary>")
		return
	}

	binaryPath := os.Args[1]
	filePath := findBinaryInPath(binaryPath)
	if filePath == "" {
		fmt.Println("file not found in PATH directories.")
		return
	}

	fmt.Printf("file found at: %s\n", filePath)
	// filePath := os.Args[1]
	file, err := pe.Open(filePath)
	if err != nil {
		fmt.Println("Error opening PE file:", err)
		return
	}
	defer file.Close()

	printDOSHeader(filePath)
	inspectSignature(filePath)
	printCOFFHeader(file)
	printOptionalHeader(file)
	printSectionHeaders(file)
	printExportTable(file)

	signed, signatureSize := isPESigned(file)
	if signed {
		fmt.Printf("\nThe file is digitally signed (%d bytes)\n", signatureSize)
		printSignature(filePath, file)
	} else {
		fmt.Printf("\nThe file is not digitally signed\n")
	}
}

type ImageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

func printExportTable(file *pe.File) {
	// Step 1: Get the RVA of the export table
	var exportTableRVA uint32
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		exportTableRVA = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	case *pe.OptionalHeader64:
		exportTableRVA = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	default:
		fmt.Println("Unknown PE format.")
		return
	}

	var exportSection *pe.Section
	for _, section := range file.Sections {
		if section.VirtualAddress <= exportTableRVA && section.VirtualAddress+section.Size > exportTableRVA {
			exportSection = section
			break
		}
	}

	if exportSection == nil {
		fmt.Println("No export table found.")
		return
	}

	data, err := exportSection.Data()
	if err != nil {
		fmt.Println("Error reading section data:", err)
		return
	}

	offset := exportTableRVA - exportSection.VirtualAddress
	exportData := data[offset:]

	exportDir := (*ImageExportDirectory)(unsafe.Pointer(&exportData[0]))
	nameRVAs := (*[1 << 30]uint32)(unsafe.Pointer(&data[int(exportDir.AddressOfNames)-int(exportSection.VirtualAddress)]))[:exportDir.NumberOfNames]

	println("\nexported functions: ")
	for _, rva := range nameRVAs {
		nameOffset := rva - exportSection.VirtualAddress
		name := cStringToString(&data[nameOffset])
		fmt.Println("\t", name)
	}

}

func inspectSignature(filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	dosSig := make([]byte, 2)
	_, err = f.Read(dosSig)
	if err != nil || string(dosSig) != "MZ" {
		fmt.Println("Invalid or missing DOS header signature.")
		return
	}

	_, err = f.Seek(0x3C, io.SeekStart)
	if err != nil {
		fmt.Println("Error seeking PE offset:", err)
		return
	}

	peOffsetBytes := make([]byte, 4)
	_, err = f.Read(peOffsetBytes)
	if err != nil {
		fmt.Println("Error reading PE offset:", err)
		return
	}

	peOffset := int64(binary.LittleEndian.Uint32(peOffsetBytes))
	_, err = f.Seek(peOffset, io.SeekStart)
	if err != nil {
		fmt.Println("Error seeking PE signature:", err)
		return
	}

	peSig := make([]byte, 4)
	_, err = f.Read(peSig)
	if err != nil || string(peSig) != "PE\000\000" {
		fmt.Println("Invalid or missing PE signature.")
		return
	}
	fmt.Println("\nPE Signature (4 bytes):", peSig)
}

func isPESigned(file *pe.File) (bool, uint32) {
	var dataDirectory []pe.DataDirectory
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDirectory = header.DataDirectory[:]
	case *pe.OptionalHeader64:
		dataDirectory = header.DataDirectory[:]
	default:
		return false, 0
	}

	if len(dataDirectory) > 4 {
		securityEntry := dataDirectory[4]
		if securityEntry.Size > 0 {
			return true, securityEntry.Size
		}
	}
	return false, 0
}

func printSignature(filePath string, peFile *pe.File) {
	signatureBytes, err := getDigitalSignature(filePath)
	if err != nil {
		fmt.Println("\nThe file is not digitally signed or an error occurred.")
	} else {
		fmt.Printf("\nDigital Signature (%d bytes):\n", len(signatureBytes))
		fmt.Println(hex.Dump(signatureBytes))
	}
}

type DOSHeader struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   uint32
}

func printDOSHeader(filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	dosHeader := &DOSHeader{}
	err = binary.Read(f, binary.LittleEndian, dosHeader)
	if err != nil {
		fmt.Println("Error reading DOS header:", err)
		return
	}

	fmt.Println("DOS Header (64 bytes):")
	fmt.Printf("  e_magic: 0x%X\n", dosHeader.E_magic)
	fmt.Printf("  e_lfanew: %d\n", dosHeader.E_lfanew)
}

func printCOFFHeader(file *pe.File) {
	fmt.Println("\nCOFF Header (20 bytes):")
	fmt.Printf("  Machine: 0x%X\n", file.FileHeader.Machine)
	fmt.Printf("  NumberOfSections: %d\n", file.FileHeader.NumberOfSections)
	fmt.Printf("  TimeDateStamp: %d\n", file.FileHeader.TimeDateStamp)
}

func printOptionalHeader(file *pe.File) {
	size := file.FileHeader.SizeOfOptionalHeader
	fmt.Printf("\nOptional Header (%d bytes):\n", size)
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		fmt.Println("  Format: PE32")
		fmt.Printf("  BaseOfData: 0x%X\n", header.BaseOfData)
	case *pe.OptionalHeader64:
		fmt.Println("  Format: PE32+")
	default:
		fmt.Println("  Unknown PE format.")
	}
}

func printSectionHeaders(file *pe.File) {
	totalSize := 40 * int(file.FileHeader.NumberOfSections)
	fmt.Printf("\nSection Headers (%d bytes each, %d bytes total):\n", 40, totalSize)
	for _, section := range file.Sections {
		fmt.Println("  ------------------------")
		fmt.Printf("  Name: %s\n", section.Name)
		fmt.Printf("  VirtualSize: 0x%X\n", section.VirtualSize)
		fmt.Printf("  VirtualAddress: 0x%X\n", section.VirtualAddress)
		fmt.Printf("  Size: %d\n", section.Size)
		fmt.Printf("  Offset: %d\n", section.Offset)
	}
}

func _printHeaders(file *pe.File) {
	fmt.Println("\nCOFF Header:")
	fmt.Printf("  Machine: 0x%X\n", file.FileHeader.Machine)
	fmt.Printf("  NumberOfSections: %d\n", file.FileHeader.NumberOfSections)
	fmt.Printf("  TimeDateStamp: %d\n", file.FileHeader.TimeDateStamp)

	fmt.Println("\nOptional Header:")
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		fmt.Println("  Format: PE32")
		fmt.Printf("  BaseOfData: 0x%X\n", header.BaseOfData)
	case *pe.OptionalHeader64:
		fmt.Println("  Format: PE32+")
	}

	fmt.Println("\nSection Headers:")
	for _, section := range file.Sections {
		fmt.Println("  ------------------------")
		fmt.Printf("  Name: %s\n", section.Name)
		fmt.Printf("  VirtualSize: 0x%X\n", section.VirtualSize)
		fmt.Printf("  VirtualAddress: 0x%X\n", section.VirtualAddress)
		fmt.Printf("  Size: %d\n", section.Size)
		fmt.Printf("  Offset: %d\n", section.Offset)
	}
}

func getDigitalSignature(filePath string) ([]byte, error) {
	file, err := pe.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var dataDirectory []pe.DataDirectory
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDirectory = header.DataDirectory[:]
	case *pe.OptionalHeader64:
		dataDirectory = header.DataDirectory[:]
	default:
		return nil, errors.New("invalid optional header type")
	}

	if len(dataDirectory) <= 4 {
		return nil, errors.New("no security directory present")
	}

	securityEntry := dataDirectory[4]
	if securityEntry.Size == 0 || securityEntry.VirtualAddress == 0 {
		return nil, errors.New("no digital signature present")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	signature := make([]byte, securityEntry.Size)
	_, err = f.Seek(int64(securityEntry.VirtualAddress), io.SeekStart)
	if err != nil {
		return nil, err
	}

	_, err = f.Read(signature)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func cStringToString(cstr *byte) string {
	bytes := make([]byte, 0, 256)
	for p := cstr; *p != 0; p = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 1)) {
		bytes = append(bytes, *p)
	}
	return string(bytes)
}

// findBinaryInPath searches for the given DLL name in all directories listed in the PATH environment variable.
// Returns the full path to the DLL if found, or an empty string if not.
func findBinaryInPath(binaryPath string) string {
	// Check if the binary exists on the exact path that was passed in first.
	if _, err := os.Stat(binaryPath); err == nil {
		return binaryPath
	}

	pathVar, exists := os.LookupEnv("PATH")
	if !exists {
		return ""
	}

	paths := strings.Split(pathVar, string(os.PathListSeparator))
	for _, p := range paths {
		testPath := filepath.Join(p, binaryPath)
		if _, err := os.Stat(testPath); err == nil {
			return testPath
		}
	}

	return ""
}
