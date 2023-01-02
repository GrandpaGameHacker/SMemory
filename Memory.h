// windows
#include <Windows.h>
#include <tlhelp32.h>

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <thread>
#include <atomic>
#include <memory>
#include <utility>
#include <vector>
#include <iostream>
#include <string>
#include <future>
#include <map>

#include <DbgHelp.h>
#pragma comment(lib,"dbghelp.lib")

#include <algorithm>


struct Process
{
	HANDLE hProcess;
  DWORD dwProcessID;
  std::string ProcessName;

  Process(DWORD dwProcessID)
  {
  	this->dwProcessID = dwProcessID;
  	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
  	if(hProcess = INVALID_HANDLE_VALUE)
		{
			std::cout << "Failed to open process" << std::endl;
		}
  	CheckBits();

  	char szProcessName[MAX_PATH] = "<unknown>";
  	GetModuleBaseNameA(hProcess, NULL, szProcessName, sizeof(szProcessName) / sizeof(char));
  	this->ProcessName = szProcessName;
  }

  Process(const std::string& ProcessName)
  {
		this->dwProcessID = GetProcessID(ProcessName);
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
		if(hProcess == INVALID_HANDLE_VALUE)
		{
			std::cout << "Failed to open process" << std::endl;
		}
		CheckBits();
		char szProcessName[MAX_PATH] = "<unknown>";
  	GetModuleBaseNameA(hProcess, NULL, szProcessName, sizeof(szProcessName) / sizeof(char));
  	this->ProcessName = szProcessName;
	}

	DWORD GetProcessID(const std::string& ProcessName)
	{
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if(hProcessSnap == INVALID_HANDLE_VALUE)
		{
			std::cout << "Failed to create snapshot" << std::endl;

			return 0;
		}
		if(!Process32First(hProcessSnap, &pe32))
		{
			std::cout << "Failed to get first process" << std::endl;
			CloseHandle(hProcessSnap);
			return 0;
		}
		do
		{
			if(ProcessName == pe32.szExeFile)
			{
				CloseHandle(hProcessSnap);
				return pe32.th32ProcessID;
			}
		}while(Process32Next(hProcessSnap, &pe32));
		CloseHandle(hProcessSnap);
		return 0;
	}
    Process(HANDLE hProcess, DWORD dwProcessID, const std::string& ProcessName)
	{
		this->hProcess = hProcess;
		this->dwProcessID = dwProcessID;
		this->ProcessName = ProcessName;
	}

	Process()
	{
		this->hProcess = INVALID_HANDLE_VALUE;
		this->dwProcessID = NULL;
		this->ProcessName = "";
	}

	Process& operator=(const Process& other)
	{
		this->hProcess = other.hProcess;
		this->dwProcessID = other.dwProcessID;
		this->ProcessName = other.ProcessName;
		return *this;
	}

	Process(const Process& other)
	{
		this->hProcess = other.hProcess;
		this->dwProcessID = other.dwProcessID;
		this->ProcessName = other.ProcessName;
	}

	bool IsValid()
	{
		return this->hProcess != INVALID_HANDLE_VALUE;
	}

	bool Is32Bit()
	{
		BOOL bIsWow64 = FALSE;
		typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
		LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
		if (fnIsWow64Process != nullptr)
		{
			if (!fnIsWow64Process(this->hProcess, &bIsWow64))
			{
				return false;
			}
		}
		return true;
	}

	bool IsSameBits()
	{
		bool b64Remote = !Is32Bit();
		bool b64Local = sizeof(void*) == 8;
		return b64Remote == b64Local;
	}

private:
	void CheckBits()
	{
		if(!IsSameBits())
		{
			std::cout << "Process is not the same bits" << std::endl;
			exit(0);
		}
	}

};

struct MemoryRange
{
    uintptr_t start;
    uintptr_t end;
    bool bExecutable, bReadable, bWritable;

    MemoryRange(uintptr_t start, uintptr_t end, bool bExecutable, bool bReadable, bool bWritable)
	{
		this->start = start;
		this->end = end;
		this->bExecutable = bExecutable;
		this->bReadable = bReadable;
		this->bWritable = bWritable;
	}

	bool contains(uintptr_t address)
	{
		return address >= start && address <= end;
	}

	uintptr_t size()
	{
		return end - start;
	}
};

struct MemoryMap
{
	std::vector<MemoryRange> ranges;
	MemoryRange* currentRange = nullptr;

	void Setup(Process* process)
	{
		// Get readable memory ranges
		MEMORY_BASIC_INFORMATION mbi;
		for (uintptr_t address = 0; VirtualQueryEx(process->hProcess, (LPCVOID)address, &mbi, sizeof(mbi)); address += mbi.RegionSize)
		{
			if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READWRITE))
			{
				ranges.push_back(
					MemoryRange(
					(uintptr_t)mbi.BaseAddress,
					(uintptr_t)mbi.BaseAddress + mbi.RegionSize,
					mbi.Protect & PAGE_EXECUTE,
					mbi.Protect & PAGE_READONLY,
					mbi.Protect & PAGE_READWRITE));
			}
		}
	std::cout << "Found " << std::dec << ranges.size() << " memory regions" << std::endl;
	}


};


struct ModuleSection
{
	uintptr_t start;
	uintptr_t end;
	bool bFlagReadonly;
	bool bFlagExecutable;
	std::string name;

	bool contains(uintptr_t address)
	{
		return address >= start && address <= end;
	}

	uintptr_t size()
	{
		return end - start;
	}
};

struct Module
{
	void* baseAddress;
	std::vector<ModuleSection> sections;
	std::string name;
};

struct ModuleMap
{
	std::vector<Module> modules;
	void Setup(Process* process)
	{
		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);
		HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process->dwProcessID);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			std::cout << "Failed to create snapshot" << std::endl;
			return;
		}
		if (!Module32First(hModuleSnap, &me32))
		{
			std::cout << "Failed to get first module" << std::endl;
			CloseHandle(hModuleSnap);
			return;
		}
		do
		{
			modules.push_back(Module());
			Module& module = modules.back();
			module.baseAddress = me32.modBaseAddr;
			module.name = me32.szModule;
			IMAGE_DOS_HEADER dosHeader;
			ReadProcessMemory(process->hProcess, me32.modBaseAddr, &dosHeader, sizeof(dosHeader), nullptr);
			IMAGE_NT_HEADERS ntHeaders;
			ReadProcessMemory(process->hProcess, (void*)((uintptr_t)me32.modBaseAddr + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), nullptr);
			IMAGE_SECTION_HEADER* sectionHeaders = new IMAGE_SECTION_HEADER[ntHeaders.FileHeader.NumberOfSections];
			ReadProcessMemory(process->hProcess, (void*)((uintptr_t)me32.modBaseAddr + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS)), sectionHeaders, sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections, nullptr);
			for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
			{
				IMAGE_SECTION_HEADER& sectionHeader = sectionHeaders[i];
				module.sections.push_back(ModuleSection());
				ModuleSection& section = module.sections.back();
				section.name = (char*)sectionHeader.Name;
				section.start = (uintptr_t)me32.modBaseAddr + sectionHeader.VirtualAddress;
				section.end = section.start + sectionHeader.Misc.VirtualSize;
				section.bFlagExecutable = sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE;
				section.bFlagReadonly = sectionHeader.Characteristics & IMAGE_SCN_MEM_READ;
			}
		} while (Module32Next(hModuleSnap, &me32));
		CloseHandle(hModuleSnap);

		std::cout << "Found " << std::dec << modules.size() << " modules" << std::endl;
	}

	Module* GetModule(const char* name)
	{
		auto it = std::find_if(modules.begin(), modules.end(), [name](const Module& module) { return module.name == name; });
		if (it != modules.end()) return &*it;
		return nullptr;
	}

	Module* GetModule(const std::string& name){
		auto it = std::find_if(modules.begin(), modules.end(), [name](const Module& module) { return module.name == name; });
		if (it != modules.end()) return &*it;
		return nullptr;
	}

	Module* GetModule(uintptr_t address)
	{
		auto it = std::find_if(modules.begin(), modules.end(), [address](const Module& module)
			{ return address >= (uintptr_t)module.baseAddress && address <= (uintptr_t)module.baseAddress + module.sections.back().end; });
		if (it != modules.end()) return &*it;
		return nullptr;
	}
};

struct MemoryBlock
{
	void* blockCopy;
	void* blockAddress;
	size_t blockSize;

	~MemoryBlock()
	{
		free(blockCopy);
	}
};

struct TargetProcess
{
	Process process;
	MemoryMap memoryMap;
	ModuleMap moduleMap;

	void Setup(const std::string& processName)
	{
		process = Process(processName);
		memoryMap.Setup(&process);
		moduleMap.Setup(&process);
	}

	void Setup(DWORD processID)
	{
		process = Process(processID);
		memoryMap.Setup(&process);
		moduleMap.Setup(&process);
	}

	void Setup(Process process)
	{
		this->process = process;
		memoryMap.Setup(&process);
		moduleMap.Setup(&process);
	}

	bool Is64Bit()
	{
		return !process.Is32Bit();
	}


	bool IsValid()
	{
		return process.IsValid();
	}

	Module* GetModule(const std::string& moduleName)
	{
		for (auto& module : moduleMap.modules)
		{
			if (module.name.find(moduleName) != std::string::npos)
			{
				return &module;
			}
		}

		return nullptr;
	};

	MemoryRange* GetMemoryRange(uintptr_t address)
	{
		for (auto& range : memoryMap.ranges)
		{
			if (range.contains(address))
			{
				return &range;
			}
		}

		return nullptr;
	}

	std::vector<MemoryBlock> GetReadableMemory()
	{
		std::vector<std::future<MemoryBlock>> futures;
		std::vector<MemoryBlock> blocks;
		for (auto& range : memoryMap.ranges)
		{
			if (range.bReadable)
			{
				// get a future using async launch lambda
				auto future = std::async(std::launch::async, [&range, &process = process]()
				{
					MemoryBlock block;
					block.blockAddress = (void*)range.start;
					block.blockSize = range.size();
					block.blockCopy = malloc(block.blockSize);
					ReadProcessMemory(process.hProcess, block.blockAddress, block.blockCopy, block.blockSize, NULL);
					return block;
				});
				futures.push_back(std::move(future));
			}
		}

		// wait for all futures to finish
		for (auto& future : futures)
		{
			blocks.push_back(future.get());
		}

		return blocks;
	}

	std::vector<std::future<MemoryBlock>> AsyncGetReadableMemory()
	{
		std::vector<std::future<MemoryBlock>> futures;
		for (auto& range : memoryMap.ranges)
		{
			if (range.bReadable)
			{
				// get a future using async launch lambda
				auto future = std::async(std::launch::async, [&range, &process = process]()
				{
					MemoryBlock block;
					block.blockAddress = (void*)range.start;
					block.blockSize = range.size();
					block.blockCopy = malloc(block.blockSize);
					ReadProcessMemory(process.hProcess, block.blockAddress, block.blockCopy, block.blockSize, NULL);
					return block;
				});
				futures.push_back(std::move(future));
			}
		}
		return futures;
	}


	ModuleSection* GetModuleSection(uintptr_t address)
	{
		for (auto& module : moduleMap.modules)
		{
			for (auto& section : module.sections)
			{
				if (section.contains(address))
				{
					return &section;
				}
			}
		}
		return nullptr;
	}

	void Read(uintptr_t address, void* buffer, size_t size)
	{
		if(!ReadProcessMemory(process.hProcess, (void*)address, buffer, size, NULL))
		{
			printf("ReadProcessMemory failed: %d\n", GetLastError());
		}
	}

	std::future<void*> AsyncRead(uintptr_t address, size_t size)
	{
		return std::async(std::launch::async, [this, address, size]()
		{
			void* buffer = malloc(size);
			ReadProcessMemory(process.hProcess, (void*)address, buffer, size, NULL);
			return buffer;
		});
	}

	template<typename T>
	T Read(uintptr_t address)
	{
		T buffer;
		ReadProcessMemory(process.hProcess, (void*)address, &buffer, sizeof(T), NULL);
		return buffer;
	}

	template<typename T>
	std::future<T> AsyncRead(uintptr_t address)
	{
		return std::async(std::launch::async, [this, address]()
		{
			T buffer;
			ReadProcessMemory(process.hProcess, (void*)address, &buffer, sizeof(T), NULL);
			return buffer;
		});
	}


	void Write(uintptr_t address, void* buffer, size_t size)
	{
		WriteProcessMemory(process.hProcess, (void*)address, buffer, size, NULL);
	}

	void AsyncWrite(uintptr_t address, void* buffer, size_t size)
	{
		auto result = std::async(std::launch::async, [this, address, buffer, size]()
		{
			WriteProcessMemory(process.hProcess, (void*)address, buffer, size, NULL);
		});
	}


	template<typename T>
	void Write(uintptr_t address, T value)
	{
		WriteProcessMemory(process.hProcess, (void*)address, &value, sizeof(T), NULL);
	}

	HANDLE InjectDLL(const std::string& dllPath)
	{
		HANDLE hThread = NULL;
		LPVOID LoadLibraryAAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		LPVOID RemoteString = (LPVOID)VirtualAllocEx(process.hProcess, NULL, dllPath.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(process.hProcess, (LPVOID)RemoteString, dllPath.c_str(), dllPath.size(), NULL);
		hThread = CreateRemoteThread(process.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAAddr, (LPVOID)RemoteString, NULL, NULL);
		return hThread;
	}
};


template <typename T>
class RemoteVariable
{
public:
	RemoteVariable(TargetProcess* process, T value)
	{
		this->process = process;
		this->value = value;
		this->address = (uintptr_t)VirtualAllocEx(process->process.hProcess, NULL, sizeof(T), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		this->Write();
	}

	RemoteVariable(TargetProcess* process, uintptr_t address)
	{
		this->process = process;
		this->address = address;
		this->Read();
	}

	~RemoteVariable()
	{
		VirtualFreeEx(process->process.hProcess, (void*)address, sizeof(T), MEM_RELEASE);
	}

	T operator=(T value)
	{
		this->value = value;
		this->Write();
		return value;
	}

	operator T()
	{
		this->Read();
		return value;
	}

	void Read()
	{
		process->Read(address, &value, sizeof(T));
	}

	void Write()
	{
		process->Write(address, &value, sizeof(T));
	}

	TargetProcess* process;
	uintptr_t address;
	T value;
};

class RemotePointer
{
public:

	RemotePointer()
	{

	}

	RemotePointer(TargetProcess* process, uintptr_t address)
	{
		Setup(process, address);
	}

	RemotePointer(TargetProcess* process, uintptr_t address, uintptr_t offset)
	{
		Setup(process, address, offset);
	}

	RemotePointer(TargetProcess* process, uintptr_t address, std::vector<uintptr_t> offsets)
	{
		Setup(process, address, offsets);
	}

	void Setup(TargetProcess* process, uintptr_t address)
	{
		this->process = process;
		this->address = address;
	}

	void Setup(TargetProcess* process, uintptr_t address, std::vector<uintptr_t> offsets)
	{
		this->process = process;
		this->address = address;
		this->offsets = offsets;
	}

		void Setup(TargetProcess* process, uintptr_t address, uintptr_t offset)
	{
		this->process = process;
		this->address = address;
		this->offsets.push_back(offset);
	}


	RemotePointer operator[](uintptr_t offset)
	{
		offsets.push_back(offset);
		return *this;
	}

	template<typename T>
	T Read()
	{
		T value;
		if(offsets.size() > 0)
		{
			process->Read(GetAddress(), &value, sizeof(T));
		}
		else
		{
			process->Read(address, &value, sizeof(T));
		}
		return value;
	}

	template<typename T>
	void Write(T value)
	{
		if (offsets.size() > 0)
		{
			process->Write(GetAddress(), &value, sizeof(T));
		}
		else
		{
			process->Write(address, &value, sizeof(T));
		}
	}

	template<typename T>
	operator T()
	{
		return Read<T>();
	}

	template<typename T>
	T operator=(T value)
	{
		Write<T>(value);
		return value;
	}

	// function that reads a pointer to a pointer and returns a RemotePointer
	RemotePointer GetPointer()
	{
		return RemotePointer(process, Read<uintptr_t>());
	}

	RemotePointer GetPointer(uintptr_t offset)
	{
		return RemotePointer(process, Read<uintptr_t>(), { offset });
	}

	RemotePointer GetPointer(std::vector<uintptr_t> offsets)
	{
		return RemotePointer(process, Read<uintptr_t>(), offsets);
	}

private:
	uintptr_t GetAddress()
	{
		uintptr_t address = this->address;

		for (auto& offset : offsets)
		{
			address = process->Read<uintptr_t>(address) + offset;
		}

		return address;
	}

	TargetProcess* process;
	uintptr_t address;
	std::vector<uintptr_t> offsets;
};

class RemoteFunction
{
public:
	RemoteFunction(TargetProcess* process, uintptr_t address)
	{
		this->process = process;
		this->address = address;
	}

	HANDLE operator()()
	{
		return CreateRemoteThread(process->process.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)address, NULL, NULL, NULL);
	}

	HANDLE operator()(void *args)
	{
		return CreateRemoteThread(process->process.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)address, args, NULL, NULL);
	}

	// function to allocate arguments for injected code, its up to the injected code to unpack the arguments if it is a struct
	template<typename T>
	void* AllocArgs(T args)
	{
		void* argsAddress = VirtualAllocEx(process->process.hProcess, NULL, sizeof(T), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		process->Write(argsAddress, &args, sizeof(T));
		return argsAddress;
	};

	template<typename T>
	void WaitAndFreeArgs(void* argsAddress, HANDLE hThread)
	{
		WaitForSingleObject(hThread.Get(), INFINITE);
		VirtualFreeEx(process->process.hProcess, argsAddress, sizeof(T), MEM_RELEASE);
	}

private:
	TargetProcess* process;
	uintptr_t address;
};

struct PMD
{
	int mdisp;
	int pdisp;
	int vdisp;
};

struct RTTIBaseClassDescriptor
{
	PMD pmd;
	DWORD attributes;
	DWORD pTypeDescriptor;
};

struct RTTIClassHierarchyDescriptor
{
	DWORD signature;
	DWORD attributes;
	DWORD numBaseClasses;
	DWORD pBaseClassArray;
};

struct RTTICompleteObjectLocator
{
	DWORD signature;
	DWORD offset;
	DWORD cdOffset;
	DWORD pTypeDescriptor;
	DWORD pClassDescriptor;
};

struct RTTITypeDescriptor
{
	DWORD pVFTable;
	DWORD spare;
	char name;
};


struct PotentialClass
{
	uintptr_t CompleteObjectLocator;
	uintptr_t VTable;
};

struct _ParentClass
{
	std::string name;
	uintptr_t offset;
};

struct _Class
{
	uintptr_t CompleteObjectLocator;
	uintptr_t VTable;
	std::string Name;
	std::string MangledName;
	DWORD offset;
	DWORD cdOffset;
	std::vector<_Class> references;
	std::vector<_ParentClass> parents;
	std::vector<uintptr_t> functions;
	bool bMultipleInheritance = false;
	bool bVirtualInheritance = false;
	bool bAmbigious = false;
	bool bStruct = false;
	bool bInterface = false;
};

class RTTI
{
public:
	RTTI(TargetProcess* process, std::string moduleName){
		this->process = process;
		module = process->moduleMap.GetModule(moduleName);
		this->moduleName = moduleName;
		FindValidSections();
		ScanForClasses();
		if(PotentialClasses.size() > 0)
		{
			ValidateClasses();
		}
	}

	_Class& Find(uintptr_t VTable){
		auto it = ClassMap.find(VTable);
		if (it != ClassMap.end())
		{
			return it->second;
		}
	}

	_Class& FindFirst(std::string ClassName)
	{
		for (auto& c : Classes)
		{
			if (c.Name.find(ClassName) != std::string::npos)
			{
				return c;
			}
		}
	}

	std::vector<_Class> FindAll(std::string ClassName)
	{
		std::vector<_Class> classes;
		for (auto& c : Classes)
		{
			if (c.Name.find(ClassName) != std::string::npos)
			{
				classes.push_back(c);
			}
		}
		return classes;
	}

protected:
	void FindValidSections()
	{
		// find valid executable or read only sections
		for (auto& section : module->sections)
		{
			if (section.bFlagExecutable)
			{
				ExecutableSections.push_back(section);
			}
			
			if (section.bFlagReadonly && !section.bFlagExecutable)
			{
				ReadOnlySections.push_back(section);
			}
		}
	}

	bool IsInExecutableSection(uintptr_t address){
		for (auto& section : ExecutableSections)
		{
			if (address >= section.start && address <= section.end)
			{
				return true;
			}
		}
		return false;
	}

	bool IsInReadOnlySection(uintptr_t address){
		for (auto& section : ReadOnlySections)
		{
			if (address >= section.start && address <= section.end)
			{
				return true;
			}
		}
		return false;
	}

	void ScanForClasses()
	{
		uintptr_t* buffer;
		for(auto& section : ReadOnlySections)
		{
			buffer = (uintptr_t*)malloc(section.size());
			process->Read(section.start, buffer, section.size());
			int max = section.size() / sizeof(uintptr_t);
			for (size_t i = 0; i < max; i++)
			{
				if (buffer[i] == 0 || i+1 > max)
				{
					continue;
				}

				if(IsInReadOnlySection(buffer[i]) && IsInExecutableSection(buffer[i + 1]))
				{
					PotentialClass c;
					c.CompleteObjectLocator = buffer[i];
					c.VTable = buffer[i + 1];
					PotentialClasses.push_back(c);
				}
			}
			free(buffer);
		}
		std::cout << "Found " << PotentialClasses.size() << " potential classes in " << moduleName << std::endl;
	}

	void ValidateClasses()
	{
		bool bUse64bit = process->Is64Bit();
		for(PotentialClass c : PotentialClasses)
		{
			RTTICompleteObjectLocator col;
			process->Read(c.CompleteObjectLocator, &col, sizeof(RTTICompleteObjectLocator));

			if (col.signature != 1 && bUse64bit)
			{
				continue;
			}
			else if (col.signature != 0 && !bUse64bit)
			{
				continue;
			}

			if(bUse64bit)
			{
				//not implemented
				std::cout << "64bit not implemented" << std::endl;
			}
			else
			{
				if(!IsInReadOnlySection(col.pTypeDescriptor))
				{
					continue;
				}

				RTTITypeDescriptor td;
				process->Read(col.pTypeDescriptor, &td, sizeof(RTTITypeDescriptor));
				if(!IsInReadOnlySection(td.pVFTable))
				{
					continue;
				}

				PotentialClassesFinal.push_back(c);
			}
		}

		PotentialClasses.clear();
		SortClasses();
		for(PotentialClass c : PotentialClassesFinal)
		{
			  RTTICompleteObjectLocator col;
				process->Read(c.CompleteObjectLocator, &col, sizeof(RTTICompleteObjectLocator));
				RTTIClassHierarchyDescriptor chd;
				process->Read(col.pClassDescriptor, &chd, sizeof(RTTIClassHierarchyDescriptor));

				_Class ValidClass;
				ValidClass.CompleteObjectLocator = c.CompleteObjectLocator;
				ValidClass.VTable = c.VTable;
				char* name = (char*)malloc(256);
				process->Read((uintptr_t)col.pTypeDescriptor + offsetof(RTTITypeDescriptor, name), name, 256);
				ValidClass.MangledName = name;
				ValidClass.Name = DemangleMSVC(name);
				FilterSymbol(ValidClass.Name);
				ValidClass.offset = col.offset;
				ValidClass.cdOffset = col.cdOffset;

				ValidClass.bMultipleInheritance  = (chd.attributes >> 0) & 1;
				ValidClass.bVirtualInheritance  = (chd.attributes >> 1) & 1;
				ValidClass.bAmbigious  = (chd.attributes >> 2) & 1;

				if(ValidClass.MangledName[3] == 'U')
				{
					ValidClass.bStruct = true;
				}

				EnumerateVirtualFunctions(ValidClass);
				Classes.push_back(ValidClass);
				ClassMap.insert(std::pair<uintptr_t, _Class>(ValidClass.VTable, ValidClass));
				free(name);
		}
		std::cout << "Found " << Classes.size() << " valid classes in " << moduleName << std::endl;
	}

	void EnumerateVirtualFunctions(_Class c)
	{
		c.functions.clear();
		uintptr_t* buffer = (uintptr_t*)malloc(0x1000);
		process->Read(c.VTable, buffer, 0x1000);
		for (size_t i = 0; i < 0x1000 / sizeof(uintptr_t); i++)
		{
			if(buffer[i] == 0)
			{
				break;
			}
			if(IsInExecutableSection(buffer[i]))
			{
				c.functions.push_back(buffer[i]);
			}
		}
	}


	std::string DemangleMSVC(char* symbol)
	{
		const std::string VTABLE_SYMBOL_PREFIX = "??_7";
		const std::string VTABLE_SYMBOL_SUFFIX = "6B@";
		char* pSymbol = nullptr;
    if (*static_cast<char*>(symbol + 4) == '?') pSymbol = symbol + 1;
    else if (*static_cast<char*>(symbol) == '.') pSymbol = symbol + 4;
    else if (*static_cast<char*>(symbol) == '?') pSymbol = symbol + 2;
    else
    {
        //report error
        return std::string(symbol);
    }

    std::string modifiedSymbol = pSymbol;
    modifiedSymbol.insert(0, VTABLE_SYMBOL_PREFIX);
    modifiedSymbol.insert(modifiedSymbol.size(), VTABLE_SYMBOL_SUFFIX);
    char buff[0x1000];
    std::memset(buff, 0, 0x1000);
    if (!UnDecorateSymbolName(modifiedSymbol.c_str(), buff, 0x1000, 0))
    {
        //report error
        return std::string(symbol);
    }

    return std::string(buff);
	}

	void SortClasses()
	{
		std::sort(PotentialClassesFinal.begin(), PotentialClassesFinal.end(), [=](PotentialClass a, PotentialClass b)
		{
			char* aName = (char*)malloc(256);
			char* bName = (char*)malloc(256);
			RTTICompleteObjectLocator col1, col2;
			process->Read(a.CompleteObjectLocator, &col1, sizeof(RTTICompleteObjectLocator));
			process->Read(b.CompleteObjectLocator, &col2, sizeof(RTTICompleteObjectLocator));
			process->Read((uintptr_t)col1.pTypeDescriptor + offsetof(RTTITypeDescriptor, name), aName, 256);
			process->Read((uintptr_t)col2.pTypeDescriptor + offsetof(RTTITypeDescriptor, name), bName, 256);
			std::string aNameStr = DemangleMSVC(aName);
			std::string bNameStr = DemangleMSVC(bName);
			free(aName);
			free(bName);
			return aNameStr < bNameStr;
		});
	}

	inline static std::vector<std::string> filters =
	{
		"::`vftable'",
		"const ",
		"::`anonymous namespace'"
	};

	void FilterSymbol(std::string& symbol)
	{
		for (auto& filter : filters)
		{
			StringFilter(symbol, filter);
		}
	}

	void StringFilter(std::string& string, const std::string& substring)
	{
		size_t pos;
		while ((pos = string.find(substring)) != std::string::npos)
		{
			string.erase(pos, substring.length());
		}
	}


	std::string moduleName;
	Module* module;
	TargetProcess* process;
	std::vector<ModuleSection> ExecutableSections;
	std::vector<ModuleSection> ReadOnlySections;
	std::vector<PotentialClass> PotentialClasses;
	std::vector<PotentialClass> PotentialClassesFinal;
	std::vector<_Class> Classes;
	std::map<uintptr_t, _Class> ClassMap;
};