
#include "pch.h"

#include "include/winreg.h"

using namespace std::string_literals;

#if UNICODE
#define STR(str) L ## str ## s
#else
#define STR(str) str ## s
#endif

TEST(winreg_test, enums_and_constants)
{
    using namespace winreg;

    EXPECT_EQ((REGSAM)access::all_access, KEY_ALL_ACCESS);
    EXPECT_EQ((REGSAM)access::create_link, KEY_CREATE_LINK);
    EXPECT_EQ((REGSAM)access::create_sub_key, KEY_CREATE_SUB_KEY);
    EXPECT_EQ((REGSAM)access::enumerate_sub_keys, KEY_ENUMERATE_SUB_KEYS);
    EXPECT_EQ((REGSAM)access::execute, KEY_EXECUTE);
    EXPECT_EQ((REGSAM)access::notify, KEY_NOTIFY);
    EXPECT_EQ((REGSAM)access::query_value, KEY_QUERY_VALUE);
    EXPECT_EQ((REGSAM)access::read, KEY_READ);
    EXPECT_EQ((REGSAM)access::set_value, KEY_SET_VALUE);
    EXPECT_EQ((REGSAM)access::wow64_32key, KEY_WOW64_32KEY);
    EXPECT_EQ((REGSAM)access::wow64_64key, KEY_WOW64_64KEY);
    EXPECT_EQ((REGSAM)access::write, KEY_WRITE);

    EXPECT_EQ(classes_root.get(), HKEY_CLASSES_ROOT);
    EXPECT_EQ(current_user.get(), HKEY_CURRENT_USER);
    EXPECT_EQ(local_machine.get(), HKEY_LOCAL_MACHINE);
    EXPECT_EQ(users.get(), HKEY_USERS);
    EXPECT_EQ(current_config.get(), HKEY_CURRENT_CONFIG);
}

TEST(winreg_test, openclose)
{
    auto path = STR("software\\asio");
    auto subkey{ winreg::local_machine.open(path, winreg::access::read) };

    EXPECT_TRUE(subkey);
    EXPECT_TRUE(subkey.is_open());

    auto info = subkey.query_info();
    EXPECT_TRUE(info.class_name == winreg::string(STR("")));
    EXPECT_TRUE(info.n_subkeys == 12);
    EXPECT_TRUE(info.max_subkey_name_len == 28);
    EXPECT_TRUE(info.max_class_len == 0);
    EXPECT_TRUE(info.n_values == 0);
    EXPECT_TRUE(info.max_value_name_len == 0);
    EXPECT_TRUE(info.max_value_size == 0);
    EXPECT_TRUE(info.security_desc_size == 224);
    EXPECT_TRUE(info.last_write_time == 0);

    auto count = info.n_subkeys;
    subkey.for_each([&count](winreg::string subkey) { --count; return true; });

    EXPECT_TRUE(count == 0);

    subkey.close();

    EXPECT_FALSE(subkey);
    EXPECT_FALSE(subkey.is_open());
}

TEST(winreg_test, get_string)
{
    auto path = STR("software\\microsoft");
    auto subkey = winreg::local_machine.open(path, winreg::access::read);

    auto dotnet = subkey.open(STR(".netframework"), winreg::access::read);

    auto threw = false;
    try
    {
        auto not_a_string = dotnet.get_string(STR("dbgjitdebuglaunchsetting"));
    }
    catch (std::system_error& e)
    {
        if (e.code() == std::error_code(ERROR_UNSUPPORTED_TYPE, std::system_category()))
            threw = true;
    }

    EXPECT_TRUE(threw);

    auto a_string = dotnet.get_string(STR("installroot"));

    EXPECT_TRUE(a_string == winreg::string(STR("C:\\Windows\\Microsoft.NET\\Framework\\")));
}

TEST(winreg_test, create_delete)
{
    const auto new_key_name = winreg::string(STR("long_and_unique_name_for_new_key"));

    auto new_key = winreg::current_user.create_subkey(new_key_name);

    auto new_key_copy = winreg::current_user.open(new_key_name);
    
    EXPECT_EQ(new_key, new_key_copy);

    winreg::current_user.delete_subkey(new_key_name);

    bool threw = false;
    try
    {
        auto nonexistent_key = winreg::current_user.open(new_key_name);
    }
    catch (std::system_error& e)
    {
        threw = true;
        EXPECT_EQ(std::string("RegQueryInfoKey() failed: "), std::string(e.what()));
    }

    EXPECT_TRUE(threw);
}
