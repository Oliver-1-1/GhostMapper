#pragma once
#include <Windows.h>


class AutoHandle
{
public:
	AutoHandle(HANDLE Handle) : m_handle(Handle) {};
	~AutoHandle()
	{
		if (m_handle != INVALID_HANDLE_VALUE && m_handle != NULL)
			CloseHandle(m_handle);
	}
private:
	HANDLE m_handle;
};