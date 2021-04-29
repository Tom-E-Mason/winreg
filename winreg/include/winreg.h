
#pragma once

#include <Windows.h>

#include <string>

namespace winreg
{
    class key
    {
    public:
        key(HKEY key, std::string) : m_key(key)
        {
        
        }

        ~key() 
        {
        
        }

    private:
        HKEY m_key;
    };
}