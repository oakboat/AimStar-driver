#include "driver.h"
#include "loader.h"

#define printf(...)

bool driver::init()
{
	if (test())
	{
		printf("�����Ѽ���\n");
		return true;
	}
	printf("��ʼ��������\n");
	Load();
	if (!test())
	{
		printf("��������ʧ��\n");
		return false;
	}
	return true;
}

bool driver::attach(const wchar_t* process_name)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W process{ 0 };
	process.dwSize = sizeof(process);
	while (Process32NextW(snap, &process))
	{
		if (wcscmp(process.szExeFile, process_name) == 0)
		{
			pid = process.th32ProcessID;
			CloseHandle(snap);
			return true;
		}
	}
	CloseHandle(snap);
	return false;
}
NTSTATUS driver::call(DWORD type, void* data, DWORD size)
{
	HKEY hKey = NULL;
	RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Clipboard", 0, KEY_ALL_ACCESS, &hKey);

	if (hKey == NULL || hKey == INVALID_HANDLE_VALUE) {
		printf("Registry error\n");
		return 1;
	}
	return RegSetValueExA(hKey, "DisableAntiSpyware", 0, type, reinterpret_cast<const BYTE*>(data), size);
}
bool driver::test()
{
	NTSTATUS status = call('0000', nullptr, 0);
	if (status != ERROR_�ɹ�)
	{
		printf("ͨ��ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::verify()
{
	NTSTATUS status = call('0001', nullptr, 0);
	if (status != ERROR_�ɹ�)
	{
		printf("��֤ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::inject(PINJECT_DATA data, DWORD size)
{
	NTSTATUS status = call('0002', data, size);
	if (status != ERROR_�ɹ�)
	{
		printf("����ע��ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::grant_handle(HANDLE handle)
{
	typedef struct _HANDLE_GRANT_ACCESS_BUFFER {
		HANDLE Handle;
	} HANDLE_GRANT_ACCESS_BUFFER, * PHANDLE_GRANT_ACCESS_BUFFER;
	HANDLE_GRANT_ACCESS_BUFFER buffer{ 0 };
	buffer.Handle = handle;
	NTSTATUS status = call('0003', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("��Ȩʧ��: %x\n", status);
		return false;
	}
	return true;
}
uint64_t driver::get_base_address()
{
	uint64_t address = 0;
	typedef struct _GET_PROCESS_BASE_BUFFER {
		ULONG64 hProcessId;
		PVOID64 OutBuffer;
	} GET_PROCESS_BASE_BUFFER, * PGET_PROCESS_BASE_BUFFER;
	GET_PROCESS_BASE_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	buffer.OutBuffer = &address;
	NTSTATUS status = call('0004', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("��ȡ����ַʧ��: %x\n", status);
		return 0;
	}
	return address;
}
uint64_t driver::get_module_address(const char* module_name)
{
	typedef struct _GET_MODULE_BASE_BUFFER {
		ULONG64 hProcessId;
		PVOID64 ModuleName;
		PVOID64 OutBuffer;
	} GET_MODULE_BASE_BUFFER, * PGET_MODULE_BASE_BUFFER;
	GET_MODULE_BASE_BUFFER buffer{ 0 };
	uint64_t address = 0;
	buffer.hProcessId = pid;
	buffer.ModuleName = const_cast<char*>(module_name);
	buffer.OutBuffer = &address;
	NTSTATUS status = call('0005', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("��ȡģ���ַʧ��: %x\n", status);
		return 0;
	}
	return address;
}
bool driver::read(uint64_t src_address, uint64_t dest_address, SIZE_T size)
{
	typedef struct _READ_WRITE_MEMORY_BUFFER {
		ULONG64 hProcessId;
		PVOID64 TargetAddress;
		PVOID64 SourceAddress;
		ULONG64 NumberOfBytes;
		ULONG32 ReadWriteType;
	} READ_WRITE_MEMORY_BUFFER, * PREAD_WRITE_MEMORY_BUFFER;
	READ_WRITE_MEMORY_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	buffer.TargetAddress = reinterpret_cast<PVOID64>(src_address);
	buffer.SourceAddress = reinterpret_cast<PVOID64>(dest_address);
	buffer.NumberOfBytes = size;
	buffer.ReadWriteType = 0;
	NTSTATUS status = call('0006', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("��ȡʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::write(uint64_t src_address, uint64_t dest_address, SIZE_T size)
{
	typedef struct _READ_WRITE_MEMORY_BUFFER {
		ULONG64 hProcessId;
		PVOID64 TargetAddress;
		PVOID64 SourceAddress;
		ULONG64 NumberOfBytes;
		ULONG32 ReadWriteType;
	} READ_WRITE_MEMORY_BUFFER, * PREAD_WRITE_MEMORY_BUFFER;
	READ_WRITE_MEMORY_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	buffer.TargetAddress = reinterpret_cast<PVOID64>(dest_address);
	buffer.SourceAddress = reinterpret_cast<PVOID64>(src_address);
	buffer.NumberOfBytes = size;
	buffer.ReadWriteType = 1;
	NTSTATUS status = call('0006', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("д��ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::write1(uint64_t src_address, uint64_t dest_address, SIZE_T size)
{
	typedef struct _READ_WRITE_MEMORY_BUFFER {
		ULONG64 hProcessId;
		PVOID64 TargetAddress;
		PVOID64 SourceAddress;
		ULONG64 NumberOfBytes;
		ULONG32 ReadWriteType;
	} READ_WRITE_MEMORY_BUFFER, * PREAD_WRITE_MEMORY_BUFFER;
	READ_WRITE_MEMORY_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	buffer.TargetAddress = reinterpret_cast<PVOID64>(dest_address);
	buffer.SourceAddress = reinterpret_cast<PVOID64>(src_address);
	buffer.NumberOfBytes = size;
	buffer.ReadWriteType = 2;
	NTSTATUS status = call('0006', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("д��ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::force_delete(const char* file_path)
{
	typedef struct _DRIVER_FORCE_DELETE_FILE_BUFFER {
		PVOID64 FilePath;
	} DRIVER_FORCE_DELETE_FILE_BUFFER, * PDRIVER_FORCE_DELETE_FILE_BUFFER;
	DRIVER_FORCE_DELETE_FILE_BUFFER buffer{ 0 };
	buffer.FilePath = const_cast<char*>(file_path);
	NTSTATUS status = call('0007', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("ǿɾ�ļ�ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::protect_process(BOOL enable)
{
	typedef struct _PROTECT_PROCESS_BUFFER {
		ULONG64 hProcessId;
		ULONG32 Enable;
	} PROTECT_PROCESS_BUFFER, * PPROTECT_PROCESS_BUFFER;
	PROTECT_PROCESS_BUFFER buffer{ 0 };
	buffer.Enable = enable;
	NTSTATUS status = call('0008', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("��������ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::hide_process()
{
	typedef struct _FORCE_HIDE_PROCESS_BUFFER {
		ULONG64 hProcessId;
	} FORCE_HIDE_PROCESS_BUFFER, * PFORCE_HIDE_PROCESS_BUFFER;
	FORCE_HIDE_PROCESS_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	NTSTATUS status = call('0009', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("���ؽ���ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::kill_process(const char* process_name)
{
	typedef struct _FORCE_KILL_PROCESS_BUFFER {
		PVOID64 ProcessName;
	} FORCE_KILL_PROCESS_BUFFER, * PFORCE_KILL_PROCESS_BUFFER;
	FORCE_KILL_PROCESS_BUFFER buffer{ 0 };
	buffer.ProcessName = const_cast<char*>(process_name);
	NTSTATUS status = call('0010', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("ǿɱ����ʧ��: %x\n", status);
		return false;
	}
	return true;
}
uint64_t driver::alloc_memory(ULONG64 size, ULONG32 protect, ULONG32 high_address)
{
	typedef struct _ALLOCATE_VIRTUAL_MEMORY_BUFFER {
		ULONG64 hProcessId;
		ULONG64 MemSize;
		ULONG32 MemProtect;
		ULONG32 HighAddress;
		PVOID64 OutBuffer;
	} ALLOCATE_VIRTUAL_MEMORY_BUFFER, * PALLOCATE_VIRTUAL_MEMORY_BUFFER;
	ALLOCATE_VIRTUAL_MEMORY_BUFFER buffer{ 0 };
	uint64_t address = 0;
	buffer.hProcessId = pid;
	buffer.MemSize = size;
	buffer.MemProtect = protect;
	buffer.HighAddress = high_address;
	buffer.OutBuffer = &address;
	NTSTATUS status = call('0011', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("�����ڴ�ʧ��: %x\n", status);
		return 0;
	}
	return address;
}
bool driver::free_memory(uint64_t address)
{
	typedef struct _FREE_VIRTUAL_MEMORY_BUFFER {
		ULONG64 hProcessId;
		PVOID64 MemoryAddress;
	} FREE_VIRTUAL_MEMORY_BUFFER, * PFREE_VIRTUAL_MEMORY_BUFFER;
	FREE_VIRTUAL_MEMORY_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	buffer.MemoryAddress = reinterpret_cast<PVOID64>(address);
	NTSTATUS status = call('0012', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("�ͷ��ڴ�ʧ��: %x\n", status);
		return 0;
	}
	return address;
}
bool driver::protect_memory(uint64_t address, ULONG64 size, ULONG32 protect)
{
	typedef struct _PROTECT_VIRTUAL_MEMORY_BUFFER {
		ULONG64 hProcessId;
		ULONG64 MemAddress;
		ULONG64 RegionSize;
		ULONG32 NewProtect;
	} PROTECT_VIRTUAL_MEMORY_BUFFER, * PPROTECT_VIRTUAL_MEMORY_BUFFER;
	PROTECT_VIRTUAL_MEMORY_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	buffer.MemAddress = address;
	buffer.RegionSize = size;
	buffer.NewProtect = protect;
	NTSTATUS status = call('0013', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("�ڴ�����ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::hide_memory(uint64_t address, ULONG64 size)
{
	typedef struct _HIDE_VIRTUAL_MEMORY_BUFFER {
		ULONG64 hProcessId;
		ULONG64 MemAddress;
		ULONG64 NumberOfBytes;
	} HIDE_VIRTUAL_MEMORY_BUFFER, * PHIDE_VIRTUAL_MEMORY_BUFFER;
	HIDE_VIRTUAL_MEMORY_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	buffer.MemAddress = address;
	buffer.NumberOfBytes = size;
	NTSTATUS status = call('0014', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("�����ڴ�ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::query_memory(uint64_t address, PMEMORY_BASIC_INFORMATION info)
{
	typedef struct _QUERY_VIRTUAL_MEMORY_BUFFER {
		ULONG64 hProcessId;
		PVOID64 MemAddress;
		PVOID64 OutBuffer;
	} QUERY_VIRTUAL_MEMORY_BUFFER, * PQUERY_VIRTUAL_MEMORY_BUFFER;
	QUERY_VIRTUAL_MEMORY_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	buffer.MemAddress = reinterpret_cast<PVOID64>(address);
	buffer.OutBuffer = info;
	NTSTATUS status = call('0015', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("��ѯ�ڴ�ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::create_thread(uint64_t address)
{
	typedef struct _CREATE_REMOTE_THREAD_BUFFER {
		ULONG64 hProcessId;
		PVOID64 Address;
	} CREATE_REMOTE_THREAD_BUFFER, * PCREATE_REMOTE_THREAD_BUFFER;
	CREATE_REMOTE_THREAD_BUFFER buffer{ 0 };
	buffer.hProcessId = pid;
	buffer.Address = reinterpret_cast<PVOID64>(address);
	NTSTATUS status = call('0016', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("�����߳�ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::mouse(PMOUSE_INPUT_DATA data)
{
	NTSTATUS status = call('0017', data, sizeof(MOUSE_INPUT_DATA));
	if (status != ERROR_�ɹ�)
	{
		printf("ģ�����ʧ��: %x\n", status);
		return false;
	}
	return true;
}
bool driver::keyboard(PKEYBOARD_INPUT_DATA data)
{
	NTSTATUS status = call('0018', data, sizeof(KEYBOARD_INPUT_DATA));
	if (status != ERROR_�ɹ�)
	{
		printf("ģ�����ʧ��: %x\n", status);
		return false;
	}
	return true;
}

bool driver::spoof_hwid(ULONG32 type)
{
	typedef struct _SPOOF_BUFFER {
		ULONG32 Type;
	} SPOOF_BUFFER, * PSPOOF_BUFFER;
	SPOOF_BUFFER buffer{ 0 };
	buffer.Type = type;
	NTSTATUS status = call('0019', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("�Ļ�����ʧ��: %x\n", status);
		return false;
	}
	return true;
}

uint64_t driver::find_pattern(const char * sigin_code, ULONG32 sigin_code_size, ULONG32 protect, uint64_t address)
{
	typedef struct _FIND_SIGIN_ADDRESS_BUFFER {
		ULONG64 hProcessId;
		PVOID64 SiginCode;
		ULONG32 SiginCodeSize;
		ULONG32 Protect;
		PVOID64 Address;
		PVOID64 OutBuffer;
	} FIND_SIGIN_ADDRESS_BUFFER, * PFIND_SIGIN_ADDRESS_BUFFER;
	FIND_SIGIN_ADDRESS_BUFFER buffer{ 0 };
	uint64_t ret_address = 0;
	buffer.hProcessId = pid;
	buffer.SiginCode = const_cast<char*>(sigin_code);
	buffer.Protect = protect;
	buffer.Address = reinterpret_cast<PVOID64>(address);
	buffer.OutBuffer = &ret_address;
	NTSTATUS status = call('0020', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("��������ʧ��: %x\n", status);
		return 0;
	}
	return ret_address;
}

bool driver::hide_window(HWND window, UINT flag)
{
	typedef struct _HIDW_WINDOW_BUFFER {
		HWND hWnd;
		UINT Flags;
	} HIDW_WINDOW_BUFFER, * PHIDW_WINDOW_BUFFER;
	HIDW_WINDOW_BUFFER buffer{ 0 };
	buffer.hWnd = window;
	buffer.Flags = flag;
	NTSTATUS status = call('0021', &buffer, sizeof(buffer));
	if (status != ERROR_�ɹ�)
	{
		printf("���ڷ���ʧ��: %x\n", status);
		return false;
	}
	return true;
}

