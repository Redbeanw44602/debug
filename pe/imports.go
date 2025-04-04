package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
)

type ImageImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	NameRVA            uint32
	FirstThunk         uint32
}

// ImportDirectory entry
type ImportDirectory struct {
	ImageImportDescriptor

	DllName string
}

// name with ascii letters
type ImgImportWithSymbols struct {
	DllName string
	Symbols []ImportSymbol
}

// function in DLL
type ImportSymbol struct {
	// ORDINAL
	Ordinal uint16 // max 0xffff, used if not 0
	// IMAGE_IMPORT_BY_NAME
	Hint uint16
	Name string // ANSI function name
	// _   '\0' byte
}

// ImgDelayDescr entry for delayloaded libraries
type ImgDelayDescr struct {
	GrAttrs,
	RVADLLName,
	RVAHmod,
	RVAIAT,
	RVAINT,
	RVABoundIAT,
	RVAUnloadIAT,
	DwTimeStamp uint32

	DllName string
}

// IAT returns the DataDirectory for the IAT
func (f *File) IAT() *DataDirectory {
	_, idd := f.sectionFromDirectoryEntry(IMAGE_DIRECTORY_ENTRY_IAT)
	return &idd
}

// ImportDirectoryTable - returns the Import Directory Table, a pointer to the section, and the section raw data
func (f *File) ImportDirectoryTable() ([]ImportDirectory, *Section, *[]byte, error) {

	ds, idd := f.sectionFromDirectoryEntry(IMAGE_DIRECTORY_ENTRY_IMPORT)

	// didn't find a section, so no import libraries were found
	if ds == nil {
		return nil, nil, nil, nil
	}

	sectionData, err := ds.Data()
	if err != nil {
		return nil, nil, nil, err
	}

	// seek to the virtual address specified in the import data directory
	d := sectionData[idd.VirtualAddress-ds.VirtualAddress:]

	// start decoding the import directory
	var ida []ImportDirectory
	for len(d) > 0 {
		var dt ImportDirectory
		dt.OriginalFirstThunk = binary.LittleEndian.Uint32(d[0:4])
		dt.TimeDateStamp = binary.LittleEndian.Uint32(d[4:8])
		dt.ForwarderChain = binary.LittleEndian.Uint32(d[8:12])
		dt.NameRVA = binary.LittleEndian.Uint32(d[12:16])
		dt.FirstThunk = binary.LittleEndian.Uint32(d[16:20])
		dt.DllName, _ = getString(sectionData, int(dt.NameRVA-ds.VirtualAddress))
		d = d[20:]
		if dt.OriginalFirstThunk == 0 {
			break
		}
		ida = append(ida, dt)
	}
	return ida, ds, &sectionData, nil
}

// ImportedSymbols returns the names of all symbols
// referred to by the binary f that are expected to be
// satisfied by other libraries at dynamic load time.
// It does not return weak symbols.
func (f *File) ImportedSymbols() ([]string, error) {
	pe64 := f.Machine == IMAGE_FILE_MACHINE_AMD64

	ida, ds, sectionData, err := f.ImportDirectoryTable()
	if err != nil {
		return nil, err
	}

	var all []string
	for _, dt := range ida {
		d := (*sectionData)[:]
		// seek to OriginalFirstThunk
		if dt.OriginalFirstThunk-ds.VirtualAddress > uint32(len(d)) {
			return all, fmt.Errorf("bad object ref start, got %d maxlen %d", dt.OriginalFirstThunk-ds.VirtualAddress, len(d))
		}
		d = d[dt.OriginalFirstThunk-ds.VirtualAddress:]
		for len(d) > 0 {
			if pe64 { // 64bit
				va := binary.LittleEndian.Uint64(d[0:8])
				d = d[8:]
				if va == 0 {
					break
				}
				if va&0x8000000000000000 > 0 { // is Ordinal
					ord := va & 0x00000000000ffff
					all = append(all, "Ordinal #"+strconv.FormatUint(ord, 10)) // add Ordinal #(num)
				} else {
					fn, _ := getString(*sectionData, int(uint32(va)-ds.VirtualAddress+2))
					all = append(all, fn+":"+dt.DllName)
				}
			} else { // 32bit
				va := binary.LittleEndian.Uint32(d[0:4])
				d = d[4:]
				if va == 0 {
					break
				}
				if va&0x80000000 > 0 { // is Ordinal
					ord := va & 0x0000ffff
					all = append(all, "Ordinal #"+strconv.FormatUint(uint64(ord), 10))
				} else {
					fn, _ := getString(*sectionData, int(va-ds.VirtualAddress+2))
					all = append(all, fn+":"+dt.DllName)
				}
			}
		}
	}

	return all, nil
}

// ImportedLibraries returns the names of all libraries
// referred to by the binary f that are expected to be
// linked with the binary at dynamic link time.
func (f *File) ImportedLibraries() ([]string, error) {
	ida, _, _, err := f.ImportDirectoryTable()
	if err != nil {
		return nil, err
	}
	var all []string
	for _, dt := range ida {
		all = append(all, dt.DllName)
	}
	return all, nil
}

func (f File) sectionFromDirectoryEntry(directory uint32) (*Section, DataDirectory) {
	pe64 := f.Machine == IMAGE_FILE_MACHINE_AMD64

	// grab the number of data directory entries
	var ddLength uint32
	if pe64 {
		ddLength = f.OptionalHeader.(*OptionalHeader64).NumberOfRvaAndSizes
	} else {
		ddLength = f.OptionalHeader.(*OptionalHeader32).NumberOfRvaAndSizes
	}

	// check that the length of data directory entries is large
	// enough to include the directory.
	if ddLength < directory+1 {
		return nil, DataDirectory{}
	}

	// grab the directory entry
	var idd DataDirectory
	if pe64 {
		idd = f.OptionalHeader.(*OptionalHeader64).DataDirectory[directory]
	} else {
		idd = f.OptionalHeader.(*OptionalHeader32).DataDirectory[directory]
	}

	// figure out which section contains the directory table
	var ds *Section
	for _, s := range f.Sections {
		if s.VirtualAddress <= idd.VirtualAddress && idd.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			ds = s
			break
		}
	}
	return ds, idd
}

// new dll relative offset for writing section
type newDllDirOffset struct {
	name    uint32 // for name rva
	symbols []uint32 // for oft and first thunk
}

func (f *File) writeNewImportNameSymbolBuffer(dlls []ImgImportWithSymbols) ([]byte, []newDllDirOffset) {
	var importData bytes.Buffer
	var curOffset uint32 // offset of dll name and IMAGE_IMPORT_BY_NAME in buffer

	newOffsets := make([]newDllDirOffset, len(dlls))

	// write name of dlls with 2 bytes alignment
	for i := range dlls {
		newOffsets[i].name = curOffset

		n, _ := importData.Write([]byte(dlls[i].DllName + "\x00"))
		curOffset += uint32(n)

		if curOffset&1 != 0 {
			importData.WriteByte(0) // write to align with 2 bytes
			curOffset++
		}
	}

	// add padding for separating data
	n, _ := importData.Write(make([]byte, align(curOffset, 16)-curOffset))
	curOffset += uint32(n)

	// write data for symbol(function names of each dll)
	for i := range dlls {
		for _, sym := range dlls[i].Symbols {
			if sym.Ordinal == 0 {
				newOffsets[i].symbols = append(newOffsets[i].symbols, curOffset)
				importByName := []byte{}
				importByName = binary.LittleEndian.AppendUint16(importByName, sym.Hint)
				importByName = append(importByName, sym.Name+"\x00"...)

				n, _ = importData.Write(importByName)
				curOffset += uint32(n)

				if n&1 != 0 {
					importData.WriteByte(0)
					curOffset++
				}
			}
		}

		n, _ = importData.Write(make([]byte, align(curOffset, 16)-curOffset))
		curOffset += uint32(n)
	}

	return importData.Bytes(), newOffsets
}

// ImportDelayDirectoryTable - returns the Import Directory Table, a pointer to the section, and the section raw data
func (f *File) ImportDelayDirectoryTable() ([]ImgDelayDescr, *Section, *[]byte, error) {

	ds, idd := f.sectionFromDirectoryEntry(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)

	// didn't find a section, so no import libraries were found
	if ds == nil {
		return nil, nil, nil, nil
	}

	sectionData, err := ds.Data()
	if err != nil {
		return nil, nil, nil, err
	}

	// seek to the virtual address specified in the import data directory
	d := sectionData[idd.VirtualAddress-ds.VirtualAddress:]
	var dida []ImgDelayDescr
	for len(d) > 0 {
		var dt ImgDelayDescr
		idx := 0
		dt.GrAttrs = binary.LittleEndian.Uint32(d[idx*4 : (idx*4)+4])
		idx++
		dt.RVADLLName = binary.LittleEndian.Uint32(d[idx*4 : (idx*4)+4])
		idx++
		dt.RVAHmod = binary.LittleEndian.Uint32(d[idx*4 : (idx*4)+4])
		idx++
		dt.RVAIAT = binary.LittleEndian.Uint32(d[idx*4 : (idx*4)+4])
		idx++
		dt.RVAINT = binary.LittleEndian.Uint32(d[idx*4 : (idx*4)+4])
		idx++
		dt.RVABoundIAT = binary.LittleEndian.Uint32(d[idx*4 : (idx*4)+4])
		idx++
		dt.RVAUnloadIAT = binary.LittleEndian.Uint32(d[idx*4 : (idx*4)+4])
		idx++
		dt.DwTimeStamp = binary.LittleEndian.Uint32(d[idx*4 : (idx*4)+4])
		idx++

		//check for nulls (termination entry) https://github.com/VirusTotal/yara/blob/master/libyara/modules/pe/pe.c#L1163
		if dt.DwTimeStamp|dt.GrAttrs|dt.RVADLLName|dt.RVAHmod|dt.RVAIAT|dt.RVAINT|dt.RVABoundIAT|dt.RVAUnloadIAT|dt.DwTimeStamp == 0 {
			break
		}
		if s, ok := getString(sectionData, int(dt.RVADLLName-ds.VirtualAddress)); ok {
			dt.DllName = s
		}
		d = d[32:]
		dida = append(dida, dt)
	}

	return dida, ds, &sectionData, nil
}

// ImportedDelayLibraries returns the names of all libraries referred to by the binary f
// that are added to the delay imports directory. These libraries are not loaded at initialisation,
// but may be loaded during runtime.
func (f *File) ImportedDelayLibraries() ([]string, error) {
	ida, _, _, err := f.ImportDelayDirectoryTable()
	if err != nil {
		return nil, err
	}
	var all []string
	for _, dt := range ida {
		all = append(all, dt.DllName)
	}
	return all, nil
}
