package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
)

// AddImportWithNewSection adds new section for adding dlls with section name ".goimp"(goimport)
func (f *File) AddImportWithNewSection(dlls []ImgImportWithSymbols) error {
	lastSec := f.Sections[len(f.Sections)-1]

	f.FileHeader.NumberOfSections++

	newSec := &Section{
		SectionHeader: SectionHeader{
			Name:                 ".goimp",
			OriginalName:         [8]uint8{},
			VirtualAddress:       f.SectionAlign(lastSec.VirtualAddress + lastSec.VirtualSize),
			Offset:               f.FileAlign(lastSec.Offset + lastSec.Size),
			PointerToRelocations: 0,
			PointerToLineNumbers: 0,
			NumberOfRelocations:  0,
			NumberOfLineNumbers:  0,
			Characteristics:      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
		},
	}
	copy(newSec.OriginalName[:], newSec.Name)

	// get the imported DLLs in the original file
	origDlls, _, _, err := f.ImportDirectoryTable()
	if err != nil {
		return err
	}

	// array of import image descriptor
	importDescArr := make([]ImageImportDescriptor, len(origDlls)+len(dlls))

	var descSpace uint32
	var oftOffsets, firstThunkOffsets []uint32 // after descriptors

	// set existing dlls info
	for i := range origDlls {
		importDescArr[i] = origDlls[i].ImageImportDescriptor
		descSpace += 20
	}

	descSpace += uint32((len(dlls) + 1) * 20) // make space for indicating end of descriptor array(0 bytes)
	descSpace = align(descSpace, 16)

	newDllBuf, newOffsets := f.writeNewImportNameSymbolBuffer(dlls)
	var thunkSpace uint32

	pe64 := f.FileHeader.SizeOfOptionalHeader == sizeofOptionalHeader64
	var tempOffset uint32

	// get length of buffer to be used for oft and first thunks
	for _, dll := range dlls { // oft
		oftOffsets = append(oftOffsets, tempOffset)
		if pe64 {
			thunkSpace += uint32(8 * (len(dll.Symbols) + 1)) // add 1 for ending thunk
		} else {
			thunkSpace += uint32(4 * (len(dll.Symbols) + 1)) // add 1 for ending thunk
		}
		thunkSpace = align(thunkSpace, 16)
		tempOffset += thunkSpace
	}

	for _, dll := range dlls { // first thunk
		firstThunkOffsets = append(firstThunkOffsets, tempOffset)
		if pe64 {
			thunkSpace += uint32(8 * (len(dll.Symbols) + 1)) // add 1 for ending thunk
		} else {
			thunkSpace += uint32(4 * (len(dll.Symbols) + 1)) // add 1 for ending thunk
		}
		thunkSpace = align(thunkSpace, 16)
		tempOffset += thunkSpace
	}

	frontOffset := descSpace + thunkSpace // dll names are right after, then symbol names

	newThunks := make([]byte, 0) // buffer for oft and first thunk

	// write oft and first thunks with virtual address
	for i := 0; i < 2; i++ {
		for thunkIndex := range dlls {
			var curIndex uint32
			for _, symbol := range dlls[thunkIndex].Symbols {
				for _, symOffset := range newOffsets[curIndex].symbols {
					if pe64 {
						if symbol.Ordinal != 0 {
							newThunks = binary.LittleEndian.AppendUint64(newThunks, uint64(symbol.Ordinal)|0x8000000000000000)
						} else {
							newThunks = binary.LittleEndian.AppendUint64(newThunks, uint64(newSec.VirtualAddress+frontOffset+symOffset))
							curIndex++
						}
					} else {
						if symbol.Ordinal != 0 {
							newThunks = binary.LittleEndian.AppendUint32(newThunks, uint32(symbol.Ordinal)|0x80000000)
						} else {
							newThunks = binary.LittleEndian.AppendUint32(newThunks, newSec.VirtualAddress+frontOffset+symOffset)
							curIndex++
						}
					}
				}
			}

			// add ending thunk with 0 value
			if pe64 {
				newThunks = binary.LittleEndian.AppendUint64(newThunks, 0)
			} else {
				newThunks = binary.LittleEndian.AppendUint32(newThunks, 0)
			}

			padLen := align(uint32(len(newThunks)), 16) - uint32(len(newThunks))
			newThunks = append(newThunks, make([]byte, padLen)...)
		}
	}

	for i := range dlls {
		index := i + len(origDlls)
		importDescArr[index] = ImageImportDescriptor{
			OriginalFirstThunk: newSec.VirtualAddress + descSpace + oftOffsets[i],
			TimeDateStamp:      0,
			ForwarderChain:     0,
			NameRVA:            newSec.VirtualAddress + frontOffset + newOffsets[i].name,
			FirstThunk:         newSec.VirtualAddress + descSpace + firstThunkOffsets[i],
		}
	}

	var secBuffer bytes.Buffer

	// write descriptor part
	binary.Write(&secBuffer, binary.LittleEndian, importDescArr)
	secBuffer.Write(make([]byte, descSpace-uint32(binary.Size(importDescArr))))

	// write oft and first thunk part
	secBuffer.Write(newThunks)

	// write dll name and symbol(function) name part
	secBuffer.Write(newDllBuf)

	virtualSize := descSpace + thunkSpace + uint32(len(newDllBuf))
	secBuffer.Write(make([]byte, f.FileAlign(virtualSize)-virtualSize))

	secReader := bytes.NewReader(secBuffer.Bytes())

	newSec.SectionHeader.VirtualSize = virtualSize
	newSec.SectionHeader.Size = f.FileAlign(virtualSize)
	newSec.Replace(secReader, secReader.Size())

	f.Sections = append(f.Sections, newSec)

	// make dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] point to descriptor array(zero offset from virtual address)
	switch opt := f.OptionalHeader.(type) {
	case *OptionalHeader32:
		opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newSec.VirtualAddress
		opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = newSec.VirtualSize
	case *OptionalHeader64:
		opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newSec.VirtualAddress
		opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = newSec.VirtualSize
	}

	return nil
}

func (peFile *File) Bytes() ([]byte, error) {
	var bytesWritten uint64
	peBuf := bytes.NewBuffer(nil)

	// write DOS header and stub
	binary.Write(peBuf, binary.LittleEndian, peFile.DosHeader)
	bytesWritten += uint64(binary.Size(peFile.DosHeader))
	if peFile.DosExists {
		binary.Write(peBuf, binary.LittleEndian, peFile.DosStub)
		bytesWritten += uint64(binary.Size(peFile.DosStub))
	}

	// write Rich header
	if peFile.RichHeader != nil {
		binary.Write(peBuf, binary.LittleEndian, peFile.RichHeader)
		bytesWritten += uint64(len(peFile.RichHeader))
	}

	// apply padding before PE header if necessary
	if uint32(bytesWritten) != peFile.DosHeader.AddressOfNewExeHeader {
		padding := make([]byte, peFile.DosHeader.AddressOfNewExeHeader-uint32(bytesWritten))
		binary.Write(peBuf, binary.LittleEndian, padding)
		bytesWritten += uint64(len(padding))
	}

	// write PE header
	peMagic := []byte{'P', 'E', 0x00, 0x00}
	binary.Write(peBuf, binary.LittleEndian, peMagic)
	binary.Write(peBuf, binary.LittleEndian, peFile.FileHeader)
	bytesWritten += uint64(binary.Size(peFile.FileHeader) + len(peMagic))

	switch peFile.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_I386:
		// is32bit = true
		optionalHeader := peFile.OptionalHeader.(*OptionalHeader32)
		binary.Write(peBuf, binary.LittleEndian, peFile.OptionalHeader.(*OptionalHeader32))
		bytesWritten += uint64(binary.Size(optionalHeader))
	case IMAGE_FILE_MACHINE_AMD64:
		// is32bit = false
		optionalHeader := peFile.OptionalHeader.(*OptionalHeader64)
		binary.Write(peBuf, binary.LittleEndian, optionalHeader)
		bytesWritten += uint64(binary.Size(optionalHeader))
	default:
		return nil, errors.New("architecture not supported")
	}

	// write section headers
	sectionHeaders := make([]SectionHeader32, len(peFile.Sections))
	for idx, section := range peFile.Sections {
		// write section header
		sectionHeader := SectionHeader32{
			Name:                 section.OriginalName,
			VirtualSize:          section.VirtualSize,
			VirtualAddress:       section.VirtualAddress,
			SizeOfRawData:        section.Size,
			PointerToRawData:     section.Offset,
			PointerToRelocations: section.PointerToRelocations,
			PointerToLineNumbers: section.PointerToLineNumbers,
			NumberOfRelocations:  section.NumberOfRelocations,
			NumberOfLineNumbers:  section.NumberOfLineNumbers,
			Characteristics:      section.Characteristics,
		}

		// if the PE file was pulled from memory, the symbol table offset in the header will be wrong.
		// Fix it up by picking the section that lines up, and use the raw offset instead.
		if peFile.FileHeader.PointerToSymbolTable == sectionHeader.VirtualAddress {
			peFile.FileHeader.PointerToSymbolTable = sectionHeader.PointerToRawData
		}

		sectionHeaders[idx] = sectionHeader

		//log.Printf("section: %+v\nsectionHeader: %+v\n", section, sectionHeader)

		binary.Write(peBuf, binary.LittleEndian, sectionHeader)
		bytesWritten += uint64(binary.Size(sectionHeader))
	}

	// write sections' data
	for idx, sectionHeader := range sectionHeaders {
		section := peFile.Sections[idx]
		sectionData, err := section.Data()
		if err != nil {
			return nil, err
		}
		if sectionData == nil { // for sections that weren't in the original file
			sectionData = []byte{}
		}
		if section.Offset != 0 && bytesWritten < uint64(section.Offset) {
			pad := make([]byte, uint64(section.Offset)-bytesWritten)
			peBuf.Write(pad)
			//log.Printf("Padding before section %s at %x: length:%x to:%x\n", section.Name, bytesWritten, len(pad), section.Offset)
			bytesWritten += uint64(len(pad))
		}
		// if our shellcode insertion address is inside this section, insert it at the correct offset in sectionData
		if peFile.InsertionAddr >= section.Offset && int64(peFile.InsertionAddr) < (int64(section.Offset)+int64(section.Size)-int64(len(peFile.InsertionBytes))) {
			sectionData = append(sectionData, peFile.InsertionBytes[:]...)
			datalen := len(sectionData)
			if sectionHeader.SizeOfRawData > uint32(datalen) {
				paddingSize := sectionHeader.SizeOfRawData - uint32(datalen)
				padding := make([]byte, paddingSize)
				sectionData = append(sectionData, padding...)
				//log.Printf("Padding after section %s: length:%d\n", section.Name, paddingSize)
			}
		}

		binary.Write(peBuf, binary.LittleEndian, sectionData)
		bytesWritten += uint64(len(sectionData))
	}

	peData := peBuf.Bytes()

	return peData, nil
}

func (peFile *File) WriteFile(destFile string) error {
	f, err := os.Create(destFile)
	if err != nil {
		return err
	}
	defer f.Close()

	peData, err := peFile.Bytes()
	if err != nil {
		return err
	}

	_, err = f.Write(peData)
	if err != nil {
		return err
	}

	return nil
}
