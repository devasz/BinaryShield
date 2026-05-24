#include "pe.h"

#include <algorithm>

PE::PE(std::string path) : path(path) {};

PE::~PE() { close(); }

bool PE::load()
{
	if (!open())
		return 0;

	if (!emitRead())
		return 0;

	close();

	if (!parseHeaders())
		return 0;

	return 1;
}

bool PE::save(std::string path)
{
	// create a new file for writing our protected.exe to
	HANDLE hOutputFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hOutputFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "error while creating output file: " << std::endl;
		return 0;
	}

	// write our protected.exe bytes to new file
	DWORD bytesWritten = 0;
	if (!WriteFile(hOutputFile, bytes.data(), bytes.size(), &bytesWritten, NULL))
	{
		std::cerr << "error while writing to output file: " << std::endl;
		CloseHandle(hOutputFile);
		return 0;
	}

	CloseHandle(hOutputFile);
	return 1;
}

bool PE::addFunctionByRva(DWORD startRva, DWORD endRva)
{
	DWORD startOffset = 0;
	DWORD endOffset = 0;
	if (startRva >= endRva ||
		!tryRvaToFileOffset(startRva, startOffset) ||
		!tryRvaToFileOffset(endRva, endOffset) ||
		startOffset >= endOffset ||
		endOffset > bytes.size())
	{
		std::cerr << "invalid function RVA range" << std::endl;
		return 0;
	}

	functions.push_back(Function
	(
		startRva,
		endRva,
		std::vector<BYTE>(bytes.begin() + startOffset, bytes.begin() + endOffset)
	));

	return 1;
}

bool PE::virtualizeFunction(Function function)
{
	// todo: check if function can be vm'd (i.e. is sizeof(function->bytes) >= 5)

	if (!vmSection.isInitialised())
		vmSection.initialise(getNewSectionVirtualAddress(), getNewSectionFileOffset());

	if (!function.disassemble())
		return 0;

	if (!function.compileInstructionsToVirtualInstructions())
		return 0;

	if (rvaToFileOffset(function.getEndRva()) - rvaToFileOffset(function.getStartRva()) < 5)
	{
		std::cerr << "function range is too small for a JMP trampoline" << std::endl;
		return 0;
	}

	removeOriginalFunctionBytes(function);

	DWORD bytecodeRva = vmSection.getWritePointerRva();

	// resolve branch instructions now we know bytecode rva
	if (!function.resolveBranchInstructions(bytecodeRva))
		return 0;

	vmSection.addBytes(function.getVirtualInstructionBytes());

	// redirect function to a vm trampoline
	redirectFunctionToVmTramp(function, vmSection.getWritePointerRva());
	vmSection.addVmTramp(bytecodeRva);

	return 1;
}

bool PE::virtualizeFunctions()
{
	// iterate over each function and virtulize it
	for (int i = 0; i < functions.size(); i++)
	{
		if (!virtualizeFunction(functions[i]))
			return 0;
	}

	return 1;
}

bool PE::addVmSection() { return addSection(".vdata", 0x60000020, vmSection.getBytes()); }

DWORD PE::rvaToFileOffset(DWORD rva)
{
	DWORD offset = 0;
	if (tryRvaToFileOffset(rva, offset))
		return offset;

	return 0x0; // this should never happen, throw exception here
}

bool PE::tryRvaToFileOffset(DWORD rva, DWORD& offset)
{
	// find section rva lies within and calculate file offset
	for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		DWORD sectionSize = std::max(pSectionHeader[i].Misc.VirtualSize, pSectionHeader[i].SizeOfRawData);
		if (rva >= pSectionHeader[i].VirtualAddress &&
			rva < pSectionHeader[i].VirtualAddress + sectionSize)
		{
			offset = (rva - pSectionHeader[i].VirtualAddress) + pSectionHeader[i].PointerToRawData;
			return 1;
		}
	}

	return 0;
}

DWORD PE::fileOffsetToRva(DWORD offset)
{
	// find section rva lies within and calculate rva
	for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		if (offset >= pSectionHeader[i].PointerToRawData &&
			offset < pSectionHeader[i].PointerToRawData + (pSectionHeader[i].SizeOfRawData))
		{
			return (offset - pSectionHeader[i].PointerToRawData) + pSectionHeader[i].VirtualAddress;
		}
	}

	// this should never happen
	return 0x0;
}

bool PE::parseHeaders()
{
	// verify we have a pe via the dos header
	pDosHeader = (PIMAGE_DOS_HEADER)bytes.data();
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cerr << "invalid dos header" << std::endl;
		return 0;
	}

	// verify we havea valid pe via the nt header
	pNtHeader = (PIMAGE_NT_HEADERS)(bytes.data() + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cerr << "invalid nt header" << std::endl;
		return 0;
	}

	// pSectionHeader is a pointer to the start of an array of type IMAGE_SECTION_HEADER
	pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)&pNtHeader->OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);

	return 1;
}

bool PE::open()
{
	hFile = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "error while oppening input file: " << std::endl;
		return 0;
	}

	return 1;
}

void PE::close()
{
	// if already closed, ignore, else close handle to file and set hFile to nullptr
	if (hFile != nullptr)
	{
		CloseHandle(hFile);
		hFile = nullptr;
	}
}

bool PE::emitRead()
{
	// get file size
	DWORD size = GetFileSize(hFile, NULL);
	if (size == INVALID_FILE_SIZE)
	{
		std::cerr << "error while getting input file size: " << std::endl;
		return 0;
	}

	// resize our bytes vector to size of binary
	bytes.resize(size);

	// read raw file bytes into our bytes vector
	DWORD bytesRead;
	if (!ReadFile(hFile, bytes.data(), size, &bytesRead, NULL))
	{
		std::cerr << "error while reading input file: " << std::endl;
		return 0;
	}

	return 1;
}

bool PE::addSection(std::string name, DWORD flags, std::vector<BYTE> bytes)
{
	DWORD newSectionHeaderEnd =
		pDosHeader->e_lfanew +
		sizeof(DWORD) +
		sizeof(IMAGE_FILE_HEADER) +
		pNtHeader->FileHeader.SizeOfOptionalHeader +
		(pNtHeader->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER);

	if (newSectionHeaderEnd > pNtHeader->OptionalHeader.SizeOfHeaders)
	{
		std::cerr << "not enough PE header space for new section" << std::endl;
		return 0;
	}

	// get next section's file offset
	DWORD newSectionFO = getNewSectionFileOffset();

	// create IMAGE_SECTION_HEADER for new section
	PIMAGE_SECTION_HEADER pNewSectionHeader = &pSectionHeader[pNtHeader->FileHeader.NumberOfSections];
	pNewSectionHeader->Characteristics = flags;
	pNewSectionHeader->Misc.VirtualSize = align(bytes.size(), pNtHeader->OptionalHeader.SectionAlignment);
	pNewSectionHeader->SizeOfRawData = align(bytes.size(), pNtHeader->OptionalHeader.FileAlignment);
	pNewSectionHeader->VirtualAddress = getNewSectionVirtualAddress();
	pNewSectionHeader->PointerToRawData = newSectionFO;
	CopyMemory(pNewSectionHeader->Name, name.c_str(), std::min(name.size(), static_cast<size_t>(IMAGE_SIZEOF_SHORT_NAME)));

	// increase section count in the file header, and update size of image
	pNtHeader->FileHeader.NumberOfSections += 1;
	pNtHeader->OptionalHeader.SizeOfImage = pNewSectionHeader->VirtualAddress + pNewSectionHeader->Misc.VirtualSize;

	// resize our bytes vector to fit our new section bytes in
	this->bytes.resize(newSectionFO + pNewSectionHeader->SizeOfRawData);

	// actually copy the section bytes into our bytes vector
	std::copy(bytes.begin(), bytes.end(), this->bytes.begin() + newSectionFO);

	// parse section headers again (likely not required as we only store pointers to headers)
	if (!parseHeaders())
		return 0;

	return 1;
}

DWORD PE::getNewSectionVirtualAddress()
{
	// return the next section's "virtual address", which is actually its relative virtual address
	return align
	(
		pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1].VirtualAddress + pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1].Misc.VirtualSize,
		pNtHeader->OptionalHeader.SectionAlignment
	);
}

DWORD PE::getNewSectionFileOffset()
{
	// return the next section's file offset
	return align
	(
		std::max<DWORD>
		(
			pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1].PointerToRawData + pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1].SizeOfRawData,
			bytes.size()
		),
		pNtHeader->OptionalHeader.FileAlignment
	);
}

void PE::redirectFunctionToVmTramp(Function function, DWORD vmTrampRva)
{
	std::vector<BYTE> relToVmTrapBytes = convertToByteVector<DWORD>(vmTrampRva - (function.getStartRva() + 5));

	// replace first bytes of instruction with a redirection to the vm trampoline jump
	bytes[rvaToFileOffset(function.getStartRva())] = 0xE9;
	std::copy(relToVmTrapBytes.begin(), relToVmTrapBytes.end(), bytes.begin() + rvaToFileOffset(function.getStartRva() + 1));
}

void PE::removeOriginalFunctionBytes(Function function)
{
	// replace all the original function bytes with 0xCC
	std::fill
	(
		bytes.begin() + rvaToFileOffset(function.getStartRva()),
		bytes.begin() + rvaToFileOffset(function.getEndRva()),
		0xCC
	);
}
