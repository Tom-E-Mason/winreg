
#include "pch.h"

#include "include/winreg.h"

using namespace std::string_literals;

TEST(winreg_test, openclose)
{
    auto path{ L"software\\asio"s };
    auto subkey{ winreg::local_machine.open(path, winreg::access::read) };

    EXPECT_TRUE(subkey);
    EXPECT_TRUE(subkey.is_open());

    auto info{ subkey.query_info() };
    EXPECT_TRUE(info.class_name == std::wstring{ L"" });
    EXPECT_TRUE(info.n_subkeys == 12);
    EXPECT_TRUE(info.max_subkey_name_len == 28);
    EXPECT_TRUE(info.max_class_len == 0);
    EXPECT_TRUE(info.n_values == 0);
    EXPECT_TRUE(info.max_value_name_len == 0);
    EXPECT_TRUE(info.max_value_size == 0);
    EXPECT_TRUE(info.security_desc_size == 224);
    EXPECT_TRUE(info.last_write_time == 0);

    auto count{ info.n_subkeys };
    subkey.enumerate([&count](std::wstring subkey) { --count; return true; });

    EXPECT_TRUE(count == 0);

    subkey.close();

    EXPECT_FALSE(subkey);
    EXPECT_FALSE(subkey.is_open());
}

TEST(winreg_test, get_string)
{
    auto path{ L"software\\microsoft"s };
    auto subkey{ winreg::local_machine.open(path, winreg::access::read) };

    auto dotnet{ subkey.open(L".netframework", winreg::access::read) };

    bool threw{ false };
    try
    {
        auto not_a_string{ dotnet.get_string(L"dbgjitdebuglaunchsetting"s) };
    }
    catch (std::system_error& e)
    {
        if (e.code() == std::error_code{ ERROR_UNSUPPORTED_TYPE, std::system_category() })
            threw = true;
    }

    EXPECT_TRUE(threw);

    auto a_string{ dotnet.get_string(L"installroot"s) };

    EXPECT_TRUE(a_string == std::wstring(L"C:\\Windows\\Microsoft.NET\\Framework\\"));

}