
#include "pch.h"

#include "include/winreg.h"

using namespace std::string_literals;

TEST(winreg_test, openclose)
{
    auto subkey{ L"software\\asio"s };
    auto hkey{ winreg::local_machine.open(subkey, winreg::access::read) };

    EXPECT_TRUE(hkey);
    EXPECT_TRUE(hkey.is_open());

    auto info{ hkey.query_info() };
    EXPECT_TRUE(info.class_name == std::wstring{ L"" });
    EXPECT_TRUE(info.n_subkeys == 12);
    EXPECT_TRUE(info.max_subkey_name_len == 28);
    EXPECT_TRUE(info.max_class_len == 0);
    EXPECT_TRUE(info.n_values == 0);
    EXPECT_TRUE(info.max_value_name_len == 0);
    EXPECT_TRUE(info.max_value_size == 0);
    EXPECT_TRUE(info.security_desc_size == 224);
    EXPECT_TRUE(info.last_write_time == 0);

    hkey.close();

    EXPECT_FALSE(hkey);
    EXPECT_FALSE(hkey.is_open());
}
