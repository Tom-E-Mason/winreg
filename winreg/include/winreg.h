
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
        read = KEY_READ,
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

                m_key = nullptr;
            }
        }

        struct info
        {
            std::wstring class_name;
            DWORD n_subkeys;
            DWORD max_subkey_name_len;
            DWORD max_class_len;
            DWORD n_values;
            DWORD max_value_name_len;
            DWORD max_value_size;
            DWORD security_desc_size;
            PFILETIME last_write_time;
        };

        info query_info(DWORD class_name_buffer_size = 16)
        {
            auto key_info{ info{} };
            key_info.class_name.resize(class_name_buffer_size, '\0');

            auto ls{ RegQueryInfoKey(
                m_key,
                key_info.class_name.data(),
                &class_name_buffer_size,
                nullptr,
                &key_info.n_subkeys,
                &key_info.max_subkey_name_len,
                &key_info.max_class_len,
                &key_info.n_values,
                &key_info.max_value_name_len,
                &key_info.max_value_size,
                &key_info.security_desc_size,
                key_info.last_write_time
            ) };

            if (ls != ERROR_SUCCESS)
            {
                if (ls == ERROR_MORE_DATA)
                {
                    key_info = query_info(class_name_buffer_size * 2);
                }
                else
                {
                    auto ec{ std::error_code(ls, std::system_category()) };
                    throw std::system_error(ec, "RegQueryInfoKey() failed");
                }
            }
            
            return key_info;
        }



        const HKEY& get() const noexcept { return m_key; }

        bool is_open() const noexcept { return m_key; }
        operator bool() const noexcept { return m_key; }

    private:
        HKEY m_key;
    };

    key classes_root(HKEY_CLASSES_ROOT);
    key current_user(HKEY_CURRENT_USER);
    key local_machine(HKEY_LOCAL_MACHINE);
    key users(HKEY_USERS);
    key current_config(HKEY_CURRENT_CONFIG);
}