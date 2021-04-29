
#pragma once

#include <Windows.h>

#include <system_error>
#include <string>

namespace winreg
{
    enum class access : REGSAM
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
        key(HKEY hkey) : m_key(hkey) {}

        key(const key&) = delete;

        ~key() 
        {
            close();
        }

        key open(const std::wstring& subkey, access required_access)
        {
            if (subkey.empty())
                throw std::invalid_argument("subkey may not be empty string");

            HKEY result{};
            DWORD options{};

            auto ls = RegOpenKeyEx(m_key, subkey.c_str(), options, static_cast<REGSAM>(required_access), &result);
            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegOpenKeyEx() failed");
            }

            return key(result);
        }

        void close()
        {
            if (m_key)
            {
                auto ls{ RegCloseKey(m_key) };
                if (ls != ERROR_SUCCESS)
                {
                    auto ec{ std::error_code(ls, std::system_category()) };
                    throw std::system_error(ec, "RegCloseKey() failed");
                }
            }
        }

        bool is_valid() const noexcept { return m_key; }
        operator bool() const noexcept { return m_key; }

    private:
        HKEY m_key;
    };
}