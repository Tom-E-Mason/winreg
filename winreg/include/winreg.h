
#pragma once

#include <Windows.h>

#include <system_error>
#include <string>

namespace winreg
{
    using string = std::wstring;
    using char_t = wchar_t;
    constexpr char_t null_c{ L'0' };

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
        key(key&& rhs) : m_key(rhs.m_key) { rhs.m_key = nullptr; }

        ~key() 
        {
            close();
        }

        auto open(const std::wstring& subkey, access required_access = access::read) -> key
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

            return { result };
        }

        auto close() -> void
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

        auto query_info(DWORD class_name_buffer_size = 16) -> info
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
            else
                key_info.class_name.resize(key_info.class_name.find(L'\0'));

            return key_info;
        }

        auto get_string(const std::wstring& name)->std::wstring
        {
            return get_string(name.c_str());
        }

        auto get_string(const wchar_t* name) -> std::wstring
        {
            auto size{ DWORD{} };
            auto type{ DWORD{} };
            constexpr auto type_restrictions{ DWORD{ RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND } };

            auto ls{ RegGetValue(m_key, nullptr, name, type_restrictions, &type, nullptr, &size) };
            if (ls != ERROR_SUCCESS)
            {
                auto ec{ std::error_code(ls, std::system_category()) };
                throw std::system_error(ec, "RegQueryValueEx() failed");
            }

            auto value{ std::wstring{} };

            if (size)
            {
                value.resize(size / sizeof(std::wstring::value_type), L'\0');

                ls = RegGetValue(m_key, nullptr, name, type_restrictions, &type, value.data(), &size);
                if (ls != ERROR_SUCCESS)
                {
                    auto ec{ std::error_code{ ls, std::system_category() } };
                    throw std::system_error{ ec, "RegGetValue() failed" };
                }

                value.resize(value.find(L'\0'));
            }
            

            return value;
        }

        template<typename Func>
        auto enumerate(Func&& func) -> void
        {
            auto n_subkeys{ DWORD{} };
            auto max_subkey_name_len{ DWORD{} };

            auto ls{ RegQueryInfoKey(
                m_key,
                nullptr,
                nullptr,
                nullptr,
                &n_subkeys,
                &max_subkey_name_len,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr
            ) };

            if (ls != ERROR_SUCCESS)
            {
                auto ec{ std::error_code{ ls, std::system_category() } };
                throw std::system_error{ ec, "RegQueryInfoKey() failed in for_each()" };
            }

            ++max_subkey_name_len; // plus 1 for '\0'

            auto name_buf{ std::wstring(max_subkey_name_len, '\0') };

            for (auto i{ DWORD{0} }; i < n_subkeys; ++i)
            {
                auto subkey_name_len{ max_subkey_name_len }; // in-out param

                auto ls{ RegEnumKeyEx(
                    m_key,
                    i,
                    name_buf.data(),
                    &subkey_name_len,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr
                ) };

                if (!func(name_buf.c_str()))
                    break;
            }
        }

        auto get() const noexcept -> const HKEY& { return m_key; }

        auto is_open() const noexcept -> bool { return m_key; }
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