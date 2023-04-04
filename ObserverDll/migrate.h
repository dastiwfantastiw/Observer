#pragma once
#include "../Observer/inject.h"
#include <Windows.h>

namespace migrate {
bool MigrateDebug(HANDLE processHandle, HANDLE threadHandle);
bool Migrate(HANDLE processHandle, HANDLE threadHandle, inject::ObserverDllData* injectData);
} // namespace migrate
