
#pragma once

#include <Windows.h>

#include <string>

namespace winreg
{
    enum class access
    {
        all_access = KEY_ALL_ACCESS,
        create_link = KEY_CREATE_LINK,
        create_sub_key = KEY_CREATE_SUB_KEY,
        enumerate_sub_keys = KEY_ENUMERATE_SUB_KEYS,
        execute = KEY_EXECUTE,
        notify = KEY_NOTIFY,
        query_value = KEY_QUERY_VALUE,
        set_value = KEY_SET_VALUE,
        wow64_32key = KEY_WOW64_32KEY,
        wow64_64key = KEY_WOW64_64KEY,
        write = KEY_WRITE,
    };

    class key
    {
    public:
        key(HKEY key, std::string subkey) : m_key(key)
        {
        
        }

        ~key() 
        {
        
        }

    private:
        HKEY m_key;
    };
}