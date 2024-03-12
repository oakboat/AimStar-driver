#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>
#include <Tlhelp32.h>
#include <atlconv.h>
#include "../../driver/ConsoleApplication2/driver.h"
#define _is_invalid(v) if(v==NULL) return false
#define _is_invalid(v,n) if(v==NULL) return n
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} UNICODE_STRING, *UNICODE_STRING_Ptr;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	UNICODE_STRING_Ptr ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, * OBJECT_ATTRIBUTES_Ptr;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef NTSYSAPI NTSTATUS(NTAPI* FUNC_NtOpenProcess)(PHANDLE ProcessHandle,ACCESS_MASK DesiredAccess,OBJECT_ATTRIBUTES_Ptr ObjectAttributes,PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* FUNC_NtQuerySystemInformation)(ULONG SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
typedef NTSTATUS(NTAPI* FUNC_RtlAdjustPrivilege)(ULONG Privilege,BOOLEAN Enable,BOOLEAN CurrentThread,PBOOLEAN Enabled);
typedef NTSTATUS(NTAPI* FUNC_NtDuplicateObject)(HANDLE SourceProcessHandle,HANDLE SourceHandle,HANDLE TargetProcessHandle,PHANDLE TargetHandle,ACCESS_MASK DesiredAccess,ULONG Attributes,ULONG Options);

/// <summary>
/// ����״̬��
/// </summary>
enum StatusCode
{
	SUCCEED,
	FAILE_PROCESSID,
	FAILE_HPROCESS,
	FAILE_MODULE,
	FAILE_DRIVER,
};

/// <summary>
/// ���̹���
/// </summary>
class ProcessManager 
{
private:
	bool   Attached = false;
	driver m_driver;

public:
	DWORD  ProcessID = 0;
	DWORD64  ModuleAddress = 0;

public:
	~ProcessManager()
	{
		//if (hProcess)
			//CloseHandle(hProcess);
	}
	SYSTEM_HANDLE_INFORMATION* t_SYSTEM_HANDLE_INFORMATION;
	HANDLE Source_Process = NULL;
	HANDLE target_handle = NULL;
	/// <summary>
	/// ����
	/// </summary>
	/// <param name="ProcessName">������</param>
	/// <returns>����״̬��</returns>
	StatusCode Attach(std::string ProcessName)
	{
		if (!m_driver.init())
		{
			return FAILE_DRIVER;
		}
		m_driver.verify();
		ProcessID = this->GetProcessID(ProcessName);
		_is_invalid(ProcessID, FAILE_PROCESSID);
		m_driver.pid = ProcessID;
		ModuleAddress = reinterpret_cast<DWORD64>(this->GetProcessModuleHandle(ProcessName));
		_is_invalid(ModuleAddress, FAILE_MODULE);
		Attached = true;
		return SUCCEED;
	}

	/// <summary>
	/// ȡ������
	/// </summary>
	void Detach()
	{
		Attached = false;
	}

	/// <summary>
	/// �жϽ����Ƿ񼤻�״̬
	/// </summary>
	/// <returns>�Ƿ񼤻�״̬</returns>
	bool IsActive()
	{
		if (!Attached)
			return false;
		return m_driver.read<char>(ModuleAddress) == 'M';
	}

	/// <summary>
	/// ��ȡ�����ڴ�
	/// </summary>
	/// <typeparam name="ReadType">��ȡ����</typeparam>
	/// <param name="Address">��ȡ��ַ</param>
	/// <param name="Value">��������</param>
	/// <param name="Size">��ȡ��С</param>
	/// <returns>�Ƿ��ȡ�ɹ�</returns>
	template <typename ReadType>
	bool ReadMemory(DWORD64 Address, ReadType& Value, int Size)
	{
		_is_invalid(ProcessID, false);

		if (m_driver.read(Address, (uint64_t) & Value, Size))
			return true;
		return false;
	}

	template <typename ReadType>
	bool ReadMemory(DWORD64 Address, ReadType& Value)
	{
		_is_invalid(ProcessID, false);

		if (m_driver.read(Address, (uint64_t) & Value, sizeof(ReadType)))
			return true;
		return false;
	}

	/// <summary>
	/// д������ڴ�
	/// </summary>
	/// <typeparam name="ReadType">д������</typeparam>
	/// <param name="Address">д���ַ</param>
	/// <param name="Value">д������</param>
	/// <param name="Size">д���С</param>
	/// <returns>�Ƿ�д��ɹ�</returns>
	template <typename ReadType>
	bool WriteMemory(DWORD64 Address, ReadType& Value, int Size)
	{
		_is_invalid(ProcessID, false);

		if (m_driver.write(Address, (uint64_t) & Value, Size))
			return true;
		return false;
	}

	template <typename ReadType>
	bool WriteMemory(DWORD64 Address, ReadType& Value)
	{
		_is_invalid(ProcessID, false);

		if (m_driver.write(Address, (uint64_t) & Value, sizeof(ReadType)))
			return true;
		return false;
	}

	/// <summary>
	/// ����������
	/// </summary>
	/// <param name="Signature">������</param>
	/// <param name="StartAddress">��ʼ��ַ</param>
	/// <param name="EndAddress">������ַ</param>
	/// <returns>ƥ���������</returns>
	std::vector<DWORD64> SearchMemory(const std::string& Signature, DWORD64 StartAddress, DWORD64 EndAddress, int SearchNum = 1);

	DWORD64 TraceAddress(DWORD64 BaseAddress, std::vector<DWORD> Offsets)
	{
		_is_invalid(ProcessID,0);
		DWORD64 Address = 0;

		if (Offsets.size() == 0)
			return BaseAddress;

		if (!ReadMemory<DWORD64>(BaseAddress, Address))
			return 0;
	
		for (int i = 0; i < Offsets.size() - 1; i++)
		{
			if (!ReadMemory<DWORD64>(Address + Offsets[i], Address))
				return 0;
		}
		return Address == 0 ? 0 : Address + Offsets[Offsets.size() - 1];
	}

public:

	DWORD GetProcessID(std::string ProcessName)
	{
		PROCESSENTRY32 ProcessInfoPE;
		ProcessInfoPE.dwSize = sizeof(PROCESSENTRY32);
		HANDLE hSnapshot = CreateToolhelp32Snapshot(15, 0);
		Process32First(hSnapshot, &ProcessInfoPE);
		USES_CONVERSION;
		do {
			if (strcmp(W2A(ProcessInfoPE.szExeFile), ProcessName.c_str()) == 0)
			{
				CloseHandle(hSnapshot);
				return ProcessInfoPE.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &ProcessInfoPE));
		CloseHandle(hSnapshot);
		return 0;
	}

	HMODULE GetProcessModuleHandle(std::string ModuleName)
	{
		return (HMODULE)m_driver.get_module_address(ModuleName.c_str());
	}
};

inline ProcessManager ProcessMgr;