
#pragma once

#include <Windows.h>
#include <ktmw32.h>

#include <system_error>
#include <string>
#include <vector>

namespace winreg
{
#if UNICODE
    using string = std::wstring;
    using char_t = wchar_t;
    constexpr char_t null_char{ L'\0' };
#define STR(str) string(L ## str ## )
#else
    using string = std::string;
    using char_t = char;
    constexpr char_t null_char{ '\0' };
#define STR(str) string( ## str ## )
#endif

    static constexpr DWORD RESERVED = 0;

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
        explicit key(HKEY hkey, const string& name)
            : m_key(hkey), m_name(name)
        {
        }

        key(const key&) = delete;
        key(key&& rhs) noexcept : m_key(rhs.m_key) { rhs.m_key = nullptr; }

        ~key()
        {
            close();
        }

        auto create_subkey(const string& subkey) const -> key
        {
            HKEY new_key{};

            auto ls = RegCreateKey(m_key, subkey.c_str(), &new_key);
            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegCreateKey() failed");
            }

            return key(new_key, subkey);
        }

        void delete_subkey(const string& subkey) const
        {
            auto ls = RegDeleteKey(m_key, subkey.c_str());
            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegDeleteKey() failed");
            }
        }

        auto open(const string& subkey, access required_access = access::read) const -> key
        {
            HKEY result{};
            DWORD options{};

            auto ls = RegOpenKeyEx(m_key, subkey.c_str(), options, static_cast<REGSAM>(required_access), &result);
            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegOpenKeyEx() failed");
            }

            return key(result, subkey);
        }

        void close()
        {
            if (m_key)
            {
                auto ls = RegCloseKey(m_key);
                if (ls != ERROR_SUCCESS)
                {
                    auto ec = std::error_code(ls, std::system_category());
                    throw std::system_error(ec, "RegCloseKey() failed");
                }

                m_key = nullptr;
            }
        }

        struct query_info_t
        {
            string class_name;
            DWORD n_subkeys;
            DWORD max_subkey_name_len;
            DWORD max_class_len;
            DWORD n_values;
            DWORD max_value_name_len;
            DWORD max_value_size;
            DWORD security_desc_size;
            PFILETIME last_write_time;
        };

        auto query_info(DWORD class_name_buffer_size = 16) -> query_info_t
        {
            query_info_t key_info{};
            key_info.class_name.resize(class_name_buffer_size, null_char);

            auto ls = RegQueryInfoKey(
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
            );

            if (ls != ERROR_SUCCESS)
            {
                if (ls == ERROR_MORE_DATA)
                {
                    key_info = query_info(class_name_buffer_size * 2);
                }
                else
                {
                    auto ec = std::error_code(ls, std::system_category());
                    throw std::system_error(ec, "RegQueryInfoKey() failed");
                }
            }
            else
                key_info.class_name.resize(key_info.class_name.find(null_char));

            return key_info;
        }

        void set_string(const string& name, const string& value)
        {
            set_string(name.c_str(), value.c_str());
        }

        void set_string(const char_t* name, const string& value)
        {
            const auto ls = RegSetValueEx(m_key,
                                          name,
                                          RESERVED,
                                          REG_SZ,
                                          reinterpret_cast<const BYTE*>(value.c_str()),
                                          (DWORD)(value.length() + 1) * sizeof(char_t));

            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegSetValueEx() failed");
            }
        }

        auto get_string(const string& name) -> string
        {
            return get_string(name.c_str());
        }

        auto get_string(const char_t* name) -> string
        {
            DWORD size_bytes{};
            DWORD type{};
            constexpr DWORD type_restrictions{ RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND };

            auto ls{ RegGetValue(m_key, nullptr, name, type_restrictions, &type, nullptr, &size_bytes) };
            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegQueryValueEx() failed");
            }

            string value;

            if (size_bytes)
            {
                value.resize(size_bytes / sizeof(char_t), null_char);

                ls = RegGetValue(m_key, nullptr, name, type_restrictions, &type, value.data(), &size_bytes);
                if (ls != ERROR_SUCCESS)
                {
                    auto ec = std::error_code(ls, std::system_category());
                    throw std::system_error(ec, "RegGetValue() failed");
                }

                value.resize(value.find(null_char));
            }
            
            return value;
        }

        void set_multistring(const string& name, const std::vector<string>& multistring)
        {
            string multistring_concat;
            for (const auto& str : multistring)
            {
                multistring_concat += str;
                multistring_concat += null_char;
            }

            multistring_concat += null_char;

            set_multistring(name, multistring_concat);
        }

        void set_multistring(const string& name, const string& multistring)
        {
            const auto ls = RegSetValueEx(m_key,
                                          name.c_str(),
                                          RESERVED,
                                          REG_MULTI_SZ,
                                          reinterpret_cast<const BYTE*>(multistring.c_str()),
                                          (DWORD)(multistring.length() * sizeof(char_t)));
        }

        auto get_multistring(const string& name) -> std::vector<string>
        {
            DWORD size_bytes{};
            DWORD type{};

            auto ls{ RegGetValue(m_key, nullptr, name.c_str(), RRF_RT_REG_MULTI_SZ, &type, nullptr, &size_bytes) };
            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegQueryValueEx() failed");
            }

            std::vector<string> multistring;

            if (size_bytes)
            {
                string buffer(size_bytes / sizeof(char_t), null_char);

                ls = RegGetValue(m_key, nullptr, name.c_str(), RRF_RT_REG_MULTI_SZ, &type, buffer.data(), &size_bytes);
                if (ls != ERROR_SUCCESS)
                {
                    auto ec = std::error_code(ls, std::system_category());
                    throw std::system_error(ec, "RegGetValue() failed");
                }

                for (std::size_t offset = 0, count = 0;
                     buffer[offset] != null_char && offset + count < buffer.length();
                     ++count)
                {
                    if (buffer[offset + count] == null_char)
                    {
                        multistring.push_back(buffer.substr(offset, count));

                        offset += (count + 1);
                        count = 0;
                    }
                }
            }

            return multistring;
        }

        void set_dword(const string& name, DWORD value) const
        {
            set_dword(name.c_str(), value);
        }

        void set_dword(const char_t* name, DWORD value) const
        {
            const auto ls = RegSetValueEx(m_key,
                                          name,
                                          RESERVED,
                                          REG_DWORD,
                                          reinterpret_cast<const BYTE*>(&value),
                                          sizeof(DWORD));

            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegSetValueEx() failed");
            }
        }

        auto get_dword(const string& name) const -> DWORD
        {
            return get_dword(name.c_str());
        }

        auto get_dword(const char_t* name) const -> DWORD
        {
            DWORD value{};
            DWORD size = sizeof(DWORD);
            const auto ls = RegGetValue(m_key,
                                        nullptr,
                                        name,
                                        RRF_RT_REG_DWORD,
                                        nullptr,
                                        &value,
                                        &size);

            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegGetValue() failed");
            }

            return value;
        }

        void set_qword(const string& name, uint64_t value) const
        {
            set_qword(name.c_str(), value);
        }

        void set_qword(const char_t* name, uint64_t value) const
        {
            const auto ls = RegSetValueEx(m_key,
                                          name,
                                          RESERVED,
                                          REG_QWORD,
                                          reinterpret_cast<const BYTE*>(&value),
                                          sizeof(uint64_t));

            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegSetValueEx() failed");
            }
        }

        auto get_qword(const string& name) const -> uint64_t
        {
            return get_qword(name.c_str());
        }

        auto get_qword(const char_t* name) const -> uint64_t
        {
            uint64_t value{};
            DWORD size = sizeof(uint64_t);
            const auto ls = RegGetValue(m_key,
                                        nullptr,
                                        name,
                                        RRF_RT_REG_QWORD,
                                        nullptr,
                                        &value,
                                        &size);

            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegGetValue() failed");
            }

            return value;
        }

        void delete_value(const string& name) const
        {
            delete_value(name.c_str());
        }

        void delete_value(const char_t* name) const
        {
            auto ls = RegDeleteValue(m_key, name);
            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegDeleteValue() failed");
            }
        }

        // TODO: make work for different types of callables, taking
        // keys, key names, names and values, just values etc.
        template<typename Func>
        void for_each(Func&& func)
        {
            DWORD n_subkeys{};
            DWORD max_subkey_name_len{};

            auto ls = RegQueryInfoKey(
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
            );

            if (ls != ERROR_SUCCESS)
            {
                auto ec = std::error_code(ls, std::system_category());
                throw std::system_error(ec, "RegQueryInfoKey() failed in for_each()");
            }

            ++max_subkey_name_len; // plus 1 for '\0'

            auto name_buf = string(max_subkey_name_len, null_char);

            for (DWORD i = 0; i < n_subkeys; ++i)
            {
                auto subkey_name_len = max_subkey_name_len; // in-out param

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

                if (!std::forward<Func>(func)(name_buf.c_str()))
                    break;
            }
        }

        auto get() const noexcept -> HKEY { return m_key; }

        auto is_open() const noexcept -> bool { return m_key; }
        operator bool() const noexcept { return m_key; }

        const string& name() const { return m_name; }

    private:
        HKEY m_key;
        string m_name;
    };

    extern const key classes_root(HKEY_CLASSES_ROOT, STR("HKEY_CLASSES_ROOT"));
    extern const key current_user(HKEY_CURRENT_USER, STR("HKEY_CURRENT_USER"));
    extern const key local_machine(HKEY_LOCAL_MACHINE, STR("HKEY_LOCAL_MACHINE"));
    extern const key users(HKEY_USERS, STR("HKEY_USERS"));
    extern const key current_config(HKEY_CURRENT_CONFIG, STR("HKEY_CURRENT_CONFIG"));

    class transaction
    {
    public:
        transaction(DWORD timeout = INFINITE)
            : m_uncaught_exceptions(std::uncaught_exceptions())
        {
            m_handle = CreateTransaction(nullptr,                    // security attributes
                                         nullptr,                    // reserved
                                         TRANSACTION_DO_NOT_PROMOTE, // transaction can't be distributed
                                         NULL,                       // reserved
                                         NULL,                       // reserved
                                         timeout,                    // milliseconds
                                         nullptr);                   // description
        }

        ~transaction()
        {
            if (m_uncaught_exceptions == std::uncaught_exceptions())
            {
                auto CommitTransaction(m_handle);
            }
            
            CloseHandle(m_handle);
        }

    private:
        HANDLE m_handle;
        int m_uncaught_exceptions;
    };
}

#undef STR
