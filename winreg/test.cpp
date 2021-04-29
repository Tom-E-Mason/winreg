
#include "pch.h"

#include "include/winreg.h"

using namespace std::string_literals;

TEST(winreg_test, openclose)
{
    auto subkey{ L"software\\asio"s };
    auto hkey{ winreg::local_machine.open(subkey, winreg::access::read) };

    EXPECT_TRUE(hkey);
    EXPECT_TRUE(hkey.is_open());

    hkey.close();

    EXPECT_FALSE(hkey);
    EXPECT_FALSE(hkey.is_open());
}