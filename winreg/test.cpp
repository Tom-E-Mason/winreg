
#include "pch.h"

#include "include/winreg.h"

using namespace std::string_literals;

#if UNICODE
#define STR(str) L ## str ## s
#else
#define STR(str) str ## s
#endif

TEST(winreg_test, openclose)
{
    auto path{ STR("software\\asio") };
    auto subkey{ winreg::local_machine.open(path, winreg::access::read) };

    EXPECT_TRUE(subkey);
    EXPECT_TRUE(subkey.is_open());

    auto info{ subkey.query_info() };
    EXPECT_TRUE(info.class_name == winreg::string{ STR("") });
    EXPECT_TRUE(info.n_subkeys == 12);
    EXPECT_TRUE(info.max_subkey_name_len == 28);
    EXPECT_TRUE(info.max_class_len == 0);
    EXPECT_TRUE(info.n_values == 0);
    EXPECT_TRUE(info.max_value_name_len == 0);
    EXPECT_TRUE(info.max_value_size == 0);
    EXPECT_TRUE(info.security_desc_size == 224);
    EXPECT_TRUE(info.last_write_time == 0);

    auto count{ info.n_subkeys };
    subkey.enumerate([&count](winreg::string subkey) { --count; return true; });

    EXPECT_TRUE(count == 0);

    subkey.close();

    EXPECT_FALSE(subkey);
    EXPECT_FALSE(subkey.is_open());
}

TEST(winreg_test, get_string)
{
    auto path{ STR("software\\microsoft") };
    auto subkey{ winreg::local_machine.open(path, winreg::access::read) };

    auto dotnet{ subkey.open(STR(".netframework"), winreg::access::read) };

    bool threw{ false };
    try
    {
        auto not_a_string{ dotnet.get_string(STR("dbgjitdebuglaunchsetting")) };
    }
    catch (std::system_error& e)
    {
        if (e.code() == std::error_code{ ERROR_UNSUPPORTED_TYPE, std::system_category() })
            threw = true;
    }

    EXPECT_TRUE(threw);

    auto a_string{ dotnet.get_string(STR("installroot")) };

    EXPECT_TRUE(a_string == winreg::string(STR("C:\\Windows\\Microsoft.NET\\Framework\\")));

}