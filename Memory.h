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

constexpr int bufferSize = 0x1000;

struct Process
{
	HANDLE hProcess;
	DWORD dwProcessID;
	std::string ProcessName;

	Process(DWORD dwProcessID)
	{
		this->dwProcessID = dwProcessID;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
		if (hProcess == INVALID_HANDLE_VALUE)
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
		if (hProcess == INVALID_HANDLE_VALUE)
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
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			std::cout << "Failed to create snapshot" << std::endl;

			return 0;
		}
		if (!Process32First(hProcessSnap, &pe32))
		{
			std::cout << "Failed to get first process" << std::endl;
			CloseHandle(hProcessSnap);
			return 0;
		}
		do
		{
			if (ProcessName == pe32.szExeFile)
			{
				CloseHandle(hProcessSnap);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hProcessSnap, &pe32));
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
		typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
		HMODULE Kernel32 = GetModuleHandle(TEXT("kernel32"));

		if (Kernel32 == NULL)
		{
			std::cout << "Failed to get kernel32" << std::endl;
			exit(0);
		}

		LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress((Kernel32), "IsWow64Process");
		if (fnIsWow64Process != nullptr)
		{
			fnIsWow64Process(this->hProcess, &bIsWow64);
			return bIsWow64;
		}
		std::cout << "Error function IsWow64Process does not exist" << std::endl;
		exit(0);
		return false;
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
		if (!IsSameBits())
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
		if (ranges.size() == 0)
		{
			std::cout << "Failed to get memory ranges error code: " << GetLastError() << std::endl;
			exit(0);
		}
		std::cout << "Found " << std::dec << ranges.size() << " memory regions" << std::endl;
	}


};


struct ModuleSection
{
	uintptr_t start = 0;
	uintptr_t end = 0;
	bool bFlagReadonly = false;
	bool bFlagExecutable = false;
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
	void* baseAddress = nullptr;
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

	Module* GetModule(const std::string& name)
	{
		auto it = std::find_if(modules.begin(), modules.end(), [name](const Module& module) { return module.name == name; });
		if (it != modules.end()) return &*it;
		return nullptr;
	}

	Module* GetModule(uintptr_t address)
	{
		auto it = std::find_if(modules.begin(), modules.end(), [address](const Module& module)
			{
				return address >= (uintptr_t)module.baseAddress && address <= (uintptr_t)module.baseAddress + module.sections.back().end;
			});
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
		if (!ReadProcessMemory(process.hProcess, (void*)address, buffer, size, NULL))
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

	void InjectDLLAsync(const std::string& dllPath)
	{
		auto result = std::async(std::launch::async, [this, dllPath]()
			{
				InjectDLL(dllPath);
			});
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

	RemotePointer() : process(nullptr), address(0)
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
		if (offsets.size() > 0)
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

	HANDLE operator()(void* args)
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
	int mdisp = 0; // member displacement
	int pdisp = 0; // vbtable displacement
	int vdisp = 0; // displacement inside vbtable
};

struct RTTIBaseClassDescriptor
{
	DWORD pTypeDescriptor = 0; // type descriptor of the class
	DWORD numContainedBases = 0; // number of nested classes in BaseClassArray
	PMD where; // pointer to member displacement info
	DWORD attributes = 0; // flags, usually 0
};

struct RTTIBaseClassArray
{
	// 0x4000 is the maximum number of inheritance allowed in some standards, but it will never exceed that lol ;)
	// Did this to avoid using C99 Variable Length Arrays, its not in the C++ standard
	DWORD arrayOfBaseClassDescriptors = 0; // describes base classes for the complete class
};

struct RTTIClassHierarchyDescriptor
{
	DWORD signature = 0; // 1 if 64 bit, 0 if 32bit
	DWORD attributes = 0; // bit 0 set = multiple inheritance, bit 1 set = virtual inheritance, bit 2 set = ambiguous
	DWORD numBaseClasses = 0; // number of classes in the BaseClassArray
	DWORD pBaseClassArray = 0; // array of base class descriptors
};

struct RTTICompleteObjectLocator
{
	DWORD signature = 0; // 1 if 64 bit, 0 if 32bit
	DWORD offset = 0; // offset of this vtable in the complete class
	DWORD cdOffset = 0; // constructor displacement offset
	DWORD pTypeDescriptor = 0; // type descriptor of the complete class
	DWORD pClassDescriptor = 0; // class descriptor for the complete class
};

struct RTTITypeDescriptor
{
	uintptr_t pVFTable = 0; // pointer to the vftable
	uintptr_t spare = 0;
	char name = 0; // name of the class
};


struct PotentialClass
{
	uintptr_t CompleteObjectLocator = 0;
	uintptr_t VTable = 0;
};

struct _ParentClassNode;
struct _Class
{
	uintptr_t CompleteObjectLocator = 0;
	uintptr_t VTable = 0;

	std::string Name;
	std::string MangledName;

	DWORD VTableOffset = 0;
	DWORD ConstructorDisplacementOffset = 0;

	std::vector<uintptr_t> functions;

	DWORD numBaseClasses = 0;
	std::vector<std::shared_ptr<_ParentClassNode>> Parents;
	std::vector<std::shared_ptr<_Class>> Interfaces;

	bool bMultipleInheritance = false;
	bool bVirtualInheritance = false;
	bool bAmbigious = false;
	bool bStruct = false;
	bool bInterface = false;
};

struct _ParentClassNode
{
	// basic class info
	std::string Name;
	std::string MangledName;
	DWORD numContainedBases = 0;
	PMD where = { 0,0,0 };
	DWORD attributes = 0;
	// lowest child class (the root of the tree)
	std::shared_ptr<_Class> ChildClass = nullptr;
	// base class of this class (found by looking for class of the same name)
	std::shared_ptr<_Class> Class = nullptr;
	// depth of the class in the tree
	DWORD treeDepth = 0;
};

class RTTI
{
public:
	RTTI(TargetProcess* process, std::string moduleName)
	{
		this->process = process;
		module = process->moduleMap.GetModule(moduleName);
		this->moduleName = moduleName;
		moduleBase = (uintptr_t)module->baseAddress;
		FindValidSections();
		ScanForClasses();
		if (PotentialClasses.size() > 0)
		{
			ValidateClasses();
		}
	}

	std::shared_ptr<_Class> Find(uintptr_t VTable)
	{
		auto it = ClassMap.find(VTable);
		if (it != ClassMap.end())
		{
			return it->second;
		}
	}

	std::shared_ptr<_Class> FindFirst(std::string ClassName)
	{
		for (auto& c : Classes)
		{
			if (c->Name.find(ClassName) != std::string::npos)
			{
				return c;
			}
		}
		return nullptr;
	}

	std::vector<std::shared_ptr<_Class>> FindAll(std::string ClassName)
	{
		std::vector<std::shared_ptr<_Class>> classes;
		for (auto& c : Classes)
		{
			if (c->Name.find(ClassName) != std::string::npos)
			{
				classes.push_back(c);
			}
		}
		return classes;
	}

protected:
	void FindValidSections()
	{
		bool bFound1 = false;
		bool bFound2 = false;
		// find valid executable or read only sections
		for (auto& section : module->sections)
		{
			if (section.bFlagExecutable)
			{
				ExecutableSections.push_back(section);
				bFound1 = true;
			}

			if (section.bFlagReadonly && !section.bFlagExecutable)
			{
				ReadOnlySections.push_back(section);
				bFound2 = true;
			}
		}

		if (!bFound1 || !bFound2)
		{
			std::cout << "Failed to find valid sections for RTTI scan" << std::endl;
		}
	}

	bool IsInExecutableSection(uintptr_t address)
	{
		for (auto& section : ExecutableSections)
		{
			if (address >= section.start && address <= section.end)
			{
				return true;
			}
		}
		return false;
	}

	bool IsInReadOnlySection(uintptr_t address)
	{
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
		for (auto& section : ReadOnlySections)
		{
			buffer = (uintptr_t*)malloc(section.size());
			if (buffer == nullptr)
			{
				std::cout << "Out of memory: line" << __LINE__;
				exit(0);
			}
			process->Read(section.start, buffer, section.size());
			uintptr_t max = section.size() / sizeof(uintptr_t);
			for (size_t i = 0; i < max; i++)
			{
				if (buffer[i] == 0 || i + 1 > max)
				{
					continue;
				}

				if (IsInReadOnlySection(buffer[i]) && IsInExecutableSection(buffer[i + 1]))
				{
					PotentialClass c;
					c.CompleteObjectLocator = buffer[i];
					c.VTable = section.start + (i + 1) * (sizeof(uintptr_t));
					PotentialClasses.push_back(c);
				}
			}
			free(buffer);
		}
		std::cout << "Found " << PotentialClasses.size() << " potential classes in " << moduleName << std::endl;
		PotentialClassesFinal.reserve(PotentialClasses.size());
		Classes.reserve(PotentialClasses.size());
	}

	void ValidateClasses()
	{
		bool bUse64bit = process->Is64Bit();
		for (PotentialClass c : PotentialClasses)
		{
			RTTICompleteObjectLocator col;
			process->Read(c.CompleteObjectLocator, &col, sizeof(RTTICompleteObjectLocator));

			if (bUse64bit)
			{
				if (col.signature != 1)
				{
					continue;
				}

				uintptr_t pTypeDescriptor = col.pTypeDescriptor + moduleBase;

				if (!IsInReadOnlySection(pTypeDescriptor))
				{
					continue;
				}

				RTTITypeDescriptor td;
				process->Read(pTypeDescriptor, &td, sizeof(RTTITypeDescriptor));

				if (!IsInReadOnlySection(td.pVFTable))
				{
					continue;
				}

				PotentialClassesFinal.push_back(c);

			}
			else
			{
				if (col.signature != 0)
				{
					continue;
				}

				if (!IsInReadOnlySection(col.pTypeDescriptor))
				{
					continue;
				}

				RTTITypeDescriptor td;
				process->Read(col.pTypeDescriptor, &td, sizeof(RTTITypeDescriptor));
				if (!IsInReadOnlySection(td.pVFTable))
				{
					continue;
				}

				PotentialClassesFinal.push_back(c);
			}
		}

		PotentialClasses.clear();
		PotentialClasses.shrink_to_fit();
		if (bUse64bit)
		{
			SortClasses64();
			ProcessClasses64();
		}
		else
		{
			SortClasses32();
			ProcessClasses32();
		}


		std::cout << "Found " << Classes.size() << " valid classes in " << moduleName << std::endl;
	}

	void ProcessClasses32()
	{
		std::shared_ptr<_Class> lastClass = nullptr;
		for (PotentialClass c : PotentialClassesFinal)
		{
			RTTICompleteObjectLocator col;
			process->Read(c.CompleteObjectLocator, &col, sizeof(RTTICompleteObjectLocator));
			RTTIClassHierarchyDescriptor chd;
			process->Read(col.pClassDescriptor, &chd, sizeof(RTTIClassHierarchyDescriptor));
			std::shared_ptr<_Class> ValidClass = std::make_shared<_Class>();
			ValidClass->CompleteObjectLocator = c.CompleteObjectLocator;
			ValidClass->VTable = c.VTable;

			char name[bufferSize];
			process->Read((uintptr_t)col.pTypeDescriptor + offsetof(RTTITypeDescriptor, name), name, bufferSize);
			ValidClass->MangledName = name;
			ValidClass->Name = DemangleMSVC(name);
			FilterSymbol(ValidClass->Name);

			ValidClass->VTableOffset = col.offset;
			ValidClass->ConstructorDisplacementOffset = col.cdOffset;
			ValidClass->numBaseClasses = chd.numBaseClasses;

			ValidClass->bMultipleInheritance = (chd.attributes >> 0) & 1;
			ValidClass->bVirtualInheritance = (chd.attributes >> 1) & 1;
			ValidClass->bAmbigious = (chd.attributes >> 2) & 1;

			if (lastClass != nullptr)
			{
				if (lastClass->Name == ValidClass->Name)
				{
					ValidClass->bInterface = true;
				}
			}

			if (ValidClass->MangledName[3] == 'U')
			{
				ValidClass->bStruct = true;
			}
			EnumerateVirtualFunctions(ValidClass);
			Classes.push_back(ValidClass);
			ClassMap.insert(std::pair<uintptr_t, std::shared_ptr<_Class>>(ValidClass->VTable, ValidClass));

			if (!ValidClass->bInterface)
			{
				lastClass = Classes.back();
			}
			else if (lastClass != nullptr)
			{
				lastClass->Interfaces.push_back(ValidClass);
			}
		}
		PotentialClassesFinal.clear();
		PotentialClassesFinal.shrink_to_fit();

		// process super classes
		for (std::shared_ptr<_Class> c : Classes)
		{
			if (c->numBaseClasses > 1)
			{
				// read class array (skip the first one)
				std::unique_ptr<DWORD[]> baseClassArray = std::make_unique<DWORD[]>(0x4000);

				RTTICompleteObjectLocator col;
				process->Read(c->CompleteObjectLocator, &col, sizeof(RTTICompleteObjectLocator));

				RTTIClassHierarchyDescriptor chd;
				process->Read(col.pClassDescriptor, &chd, sizeof(RTTIClassHierarchyDescriptor));
				process->Read(chd.pBaseClassArray, baseClassArray.get(), sizeof(uintptr_t) * c->numBaseClasses - 1);

				DWORD lastdisplacement = 0;
				DWORD depth = 0;

				for (unsigned int i = 0; i < c->numBaseClasses - 1; i++)
				{
					RTTIBaseClassDescriptor bcd;
					std::shared_ptr<_ParentClassNode> node = std::make_shared<_ParentClassNode>();
					process->Read(baseClassArray[i], &bcd, sizeof(RTTIBaseClassDescriptor));

					// process child name
					char name[bufferSize];
					process->Read((uintptr_t)bcd.pTypeDescriptor + offsetof(RTTITypeDescriptor, name), name, bufferSize);
					name[bufferSize - 1] = 0;
					node->MangledName = name;
					node->Name = DemangleMSVC(name);
					node->attributes = bcd.attributes;
					FilterSymbol(node->Name);

					node->ChildClass = c;
					node->Class = FindFirst(node->Name);
					node->numContainedBases = bcd.numContainedBases;
					node->where = bcd.where;

					if (bcd.where.mdisp == lastdisplacement)
					{
						depth++;
					}
					else
					{
						lastdisplacement = bcd.where.mdisp;
						depth = 0;
					}
					node->treeDepth = depth;
					if (c->VTableOffset == node->where.mdisp && c->bInterface)
					{
						c->Name = node->Name;
						c->MangledName = node->MangledName;
					}
					c->Parents.push_back(node);
				}
			}
		}
	}

	void ProcessClasses64()
	{
		for (PotentialClass c : PotentialClassesFinal)
		{
			RTTICompleteObjectLocator col;
			process->Read(c.CompleteObjectLocator, &col, sizeof(RTTICompleteObjectLocator));
			RTTIClassHierarchyDescriptor chd;

			uintptr_t pClassDescriptor = col.pClassDescriptor + moduleBase;
			process->Read(pClassDescriptor, &chd, sizeof(RTTIClassHierarchyDescriptor));

			uintptr_t pTypeDescriptor = col.pTypeDescriptor + moduleBase;

			std::shared_ptr<_Class> ValidClass = std::make_shared<_Class>();
			ValidClass->CompleteObjectLocator = c.CompleteObjectLocator;
			ValidClass->VTable = c.VTable;
			char name[bufferSize];
			memset(name, 0, bufferSize);
			process->Read(pTypeDescriptor + offsetof(RTTITypeDescriptor, name), name, bufferSize);
			name[bufferSize - 1] = 0;
			ValidClass->MangledName = name;
			ValidClass->Name = DemangleMSVC(name);
			FilterSymbol(ValidClass->Name);

			ValidClass->VTableOffset = col.offset;
			ValidClass->ConstructorDisplacementOffset = col.cdOffset;
			ValidClass->numBaseClasses = chd.numBaseClasses;

			ValidClass->bMultipleInheritance = (chd.attributes >> 0) & 1;
			ValidClass->bVirtualInheritance = (chd.attributes >> 1) & 1;
			ValidClass->bAmbigious = (chd.attributes >> 2) & 1;

			if (ValidClass->MangledName[3] == 'U')
			{
				ValidClass->bStruct = true;
			}

			EnumerateVirtualFunctions(ValidClass);
			Classes.push_back(ValidClass);
			ClassMap.insert(std::pair<uintptr_t, std::shared_ptr<_Class>>(ValidClass->VTable, ValidClass));
		}
		PotentialClassesFinal.clear();
		PotentialClassesFinal.shrink_to_fit();

		// process super classes
		for (std::shared_ptr<_Class> c : Classes)
		{
			if (c->numBaseClasses > 1)
			{
				// read class array (skip the first one)
				std::unique_ptr<DWORD[]> baseClassArray = std::make_unique<DWORD[]>(0x4000);
				std::vector<uintptr_t> baseClasses;
				baseClasses.reserve(c->numBaseClasses);
				RTTICompleteObjectLocator col;
				process->Read(c->CompleteObjectLocator, &col, sizeof(RTTICompleteObjectLocator));

				RTTIClassHierarchyDescriptor chd;
				uintptr_t pClassDescriptor = col.pClassDescriptor + moduleBase;
				process->Read(pClassDescriptor, &chd, sizeof(RTTIClassHierarchyDescriptor));
				uintptr_t pBaseClassArray = chd.pBaseClassArray + moduleBase;
				process->Read(pBaseClassArray, baseClassArray.get(), sizeof(uintptr_t) * c->numBaseClasses - 1);

				for (unsigned int i = 0; i < c->numBaseClasses - 1; i++)
				{
					baseClasses.push_back(baseClassArray[i] + moduleBase);
				}

				DWORD lastdisplacement = 0;
				DWORD depth = 0;

				for (unsigned int i = 0; i < c->numBaseClasses - 1; i++)
				{
					RTTIBaseClassDescriptor bcd;
					std::shared_ptr<_ParentClassNode> node = std::make_shared<_ParentClassNode>();
					process->Read(baseClasses[i], &bcd, sizeof(RTTIBaseClassDescriptor));

					// process child name
					char name[bufferSize];
					process->Read((uintptr_t)bcd.pTypeDescriptor + moduleBase + offsetof(RTTITypeDescriptor, name), name, bufferSize);
					name[bufferSize - 1] = 0;
					node->MangledName = name;
					node->Name = DemangleMSVC(name);
					node->attributes = bcd.attributes;
					FilterSymbol(node->Name);

					node->ChildClass = c;
					node->Class = FindFirst(node->Name);
					node->numContainedBases = bcd.numContainedBases;
					node->where = bcd.where;

					if (bcd.where.mdisp == lastdisplacement)
					{
						depth++;
					}
					else
					{
						lastdisplacement = bcd.where.mdisp;
						depth = 0;
					}
					node->treeDepth = depth;
					if (c->VTableOffset == node->where.mdisp && c->bInterface)
					{
						c->Name = node->Name;
						c->MangledName = node->MangledName;
					}
					c->Parents.push_back(node);
				}
			}
		}
	}

	void EnumerateVirtualFunctions(std::shared_ptr<_Class> c)
	{
		constexpr int maxVFuncs = 0x4000;
		auto buffer = std::make_unique<uintptr_t[]>(maxVFuncs);
		memset(buffer.get(), 0, sizeof(uintptr_t) * maxVFuncs);
		c->functions.clear();
		process->Read(c->VTable, buffer.get(), maxVFuncs);
		for (size_t i = 0; i < maxVFuncs / sizeof(uintptr_t); i++)
		{
			if (buffer[i] == 0)
			{
				break;
			}
			if (!IsInExecutableSection(buffer[i]))
			{
				break;
			}
			c->functions.push_back(buffer[i]);
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
		char buff[bufferSize];
		std::memset(buff, 0, bufferSize);
		if (!UnDecorateSymbolName(modifiedSymbol.c_str(), buff, bufferSize, 0))
		{
			//report error
			return std::string(symbol);
		}

		return std::string(buff);
	}

	void SortClasses32()
	{
		std::sort(PotentialClassesFinal.begin(), PotentialClassesFinal.end(), [=](PotentialClass a, PotentialClass b)
			{
				char aName[bufferSize];
				char bName[bufferSize];
				RTTICompleteObjectLocator col1, col2;
				process->Read(a.CompleteObjectLocator, &col1, sizeof(RTTICompleteObjectLocator));
				process->Read(b.CompleteObjectLocator, &col2, sizeof(RTTICompleteObjectLocator));
				process->Read((uintptr_t)col1.pTypeDescriptor + offsetof(RTTITypeDescriptor, name), aName, bufferSize);
				process->Read((uintptr_t)col2.pTypeDescriptor + offsetof(RTTITypeDescriptor, name), bName, bufferSize);
				std::string aNameStr = DemangleMSVC(aName);
				std::string bNameStr = DemangleMSVC(bName);
				return aNameStr < bNameStr;
			});
	}

	void SortClasses64()
	{
		std::sort(PotentialClassesFinal.begin(), PotentialClassesFinal.end(), [=](PotentialClass a, PotentialClass b)
			{
				char aName[bufferSize];
				char bName[bufferSize];
				RTTICompleteObjectLocator col1, col2;
				process->Read(a.CompleteObjectLocator, &col1, sizeof(RTTICompleteObjectLocator));
				process->Read(b.CompleteObjectLocator, &col2, sizeof(RTTICompleteObjectLocator));
				uintptr_t pTypeDescriptor1 = (uintptr_t)col1.pTypeDescriptor + moduleBase;
				uintptr_t pTypeDescriptor2 = (uintptr_t)col2.pTypeDescriptor + moduleBase;
				process->Read(pTypeDescriptor1 + offsetof(RTTITypeDescriptor, name), aName, bufferSize);
				process->Read(pTypeDescriptor2 + offsetof(RTTITypeDescriptor, name), bName, bufferSize);
				std::string aNameStr = DemangleMSVC(aName);
				std::string bNameStr = DemangleMSVC(bName);
				return aNameStr < bNameStr;
			});
	}

	void FilterSymbol(std::string& symbol)
	{
	static std::vector<std::string> filters =
	{
		"::`vftable'",
		"const ",
		"::`anonymous namespace'"
	};

	for (auto& filter : filters)
		{
			size_t pos;
			while ((pos = symbol.find(filter)) != std::string::npos)
			{
				symbol.erase(pos, filter.length());
			}
		}
	}


	std::string moduleName;
	Module* module;
	uintptr_t moduleBase;
	TargetProcess* process;
	std::vector<ModuleSection> ExecutableSections;
	std::vector<ModuleSection> ReadOnlySections;
	std::vector<PotentialClass> PotentialClasses;
	std::vector<PotentialClass> PotentialClassesFinal;
	std::vector<std::shared_ptr<_Class>> Classes;
	std::map<uintptr_t, std::shared_ptr<_Class>> ClassMap;
};