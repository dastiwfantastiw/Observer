#pragma once
#include "config.h"

class IInject
{
public:
    virtual bool Inject(HANDLE hProcess, HANDLE hThread, void* data, uint32_t dataSize, CConfig config) = 0;
};

#ifdef _DEBUG
class CRemoteThreadInjection: public IInject
{
public:
    bool Inject(HANDLE hProcess, HANDLE hThread, void* data, uint32_t dataSize, CConfig config) override;
};
#endif

class CReflectiveThreadInjection: public IInject
{
public:
    bool Inject(HANDLE hProcess, HANDLE hThread, void* data, uint32_t dataSize, CConfig config) override;
};