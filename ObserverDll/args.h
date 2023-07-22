#pragma once
#include "analyzer.h"
#include "database.h"

class CArgs
{
private:
    CLogger& m_Logger;
    CAnalyzer& m_Analyzer;

    std::vector<std::string> m_Args;

public:
    CArgs(CLogger& logger, CAnalyzer& analyzer)
        : m_Logger(logger)
        , m_Analyzer(analyzer){};

    void AnalyzerArguments(uint32_t* args, CDbFunction* func);

    bool LogFunction(SYSTEMTIME* time, CDbModule* dbModule, CDbFunction* dbFunc, uint32_t* ntstatus);
};