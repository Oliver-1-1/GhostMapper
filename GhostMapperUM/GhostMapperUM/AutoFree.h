#pragma once
#include <Windows.h>



class AutoFree
{
public:
	AutoFree(void* Buffer) : m_ptr(Buffer){};
	~AutoFree() { VirtualFree(m_ptr, 0, MEM_RELEASE); };

private: 
	void* m_ptr;
};