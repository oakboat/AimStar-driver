#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

class driver
{
public:
	typedef struct _INJECT_DATA {
		INT32 InjectHash;
		INT32 InjectBits;
		INT32 InjectMode;
		INT32 InjectHide;
		PBYTE InjectData;
		INT64 InjectSize;
	} INJECT_DATA, * PINJECT_DATA;
	typedef struct _MOUSE_INPUT_DATA {
		USHORT UnitId;
		USHORT Flags;
		union {
			ULONG Buttons;
			struct {
				USHORT  ButtonFlags;
				USHORT  ButtonData;
			};
		};
		ULONG RawButtons;
		LONG LastX;
		LONG LastY;
		ULONG ExtraInformation;
	} MOUSE_INPUT_DATA, * PMOUSE_INPUT_DATA;
	typedef struct _KEYBOARD_INPUT_DATA {
		USHORT UnitId;
		USHORT MakeCode;
		USHORT Flags;
		USHORT Reserved;
		ULONG ExtraInformation;
	} KEYBOARD_INPUT_DATA, * PKEYBOARD_INPUT_DATA;

	DWORD pid;
	
	bool init();
	bool attach(const wchar_t* process_name);
	NTSTATUS call(DWORD type, void* data, DWORD size);
	bool test();
	bool verify();
	bool inject(PINJECT_DATA data, DWORD size);
	bool grant_handle(HANDLE handle);
	uint64_t get_base_address();
	uint64_t get_module_address(const char* module_name);
	bool read(uint64_t src_address, uint64_t dest_address, SIZE_T size);
	bool write(uint64_t src_address, uint64_t dest_address, SIZE_T size);
	bool write1(uint64_t src_address, uint64_t dest_address, SIZE_T size);
	bool force_delete(const char* file_path);
	bool protect_process(BOOL enable);
	bool hide_process();
	bool kill_process(const char* process_name);
	uint64_t alloc_memory(ULONG64 size, ULONG32 protect, ULONG32 high_address);
	bool free_memory(uint64_t address);
	bool protect_memory(uint64_t address, ULONG64 size, ULONG32 protect);
	bool hide_memory(uint64_t address, ULONG64 size);
	bool query_memory(uint64_t address, PMEMORY_BASIC_INFORMATION info);
	bool create_thread(uint64_t address);
	bool mouse(PMOUSE_INPUT_DATA data);
	bool keyboard(PKEYBOARD_INPUT_DATA data);
	bool spoof_hwid(ULONG32 type);
	uint64_t find_pattern(const char* sigin_code, ULONG32 sigin_code_size, ULONG32 protect, uint64_t address);
	bool hide_window(HWND window, UINT flag);
	template<typename T>
	T read(uint64_t address)
	{
		T data{ 0 };
		read(address, reinterpret_cast<uint64_t>(&data), sizeof(T));
		return data;
	}

};