
#include "pch.h"

#include "include/winreg.h"

using namespace std::string_literals;

#if UNICODE
#define STR(str) L ## str ## s
#else
#define STR(str) str ## s
#endif

class winreg_test : public ::testing::Test
{
protected:
    winreg_test()
        : m_key(winreg::current_user.create_subkey(STR("winreg-test-key")))
    {
    }

    ~winreg_test()
    {
        m_key.for_each([this](const winreg::char_t* key_name)
            {
                m_key.delete_subkey(key_name);

                return true;
            });

        winreg::current_user.delete_subkey(STR("winreg-test-key"));
    }

    winreg::key m_key;
};

TEST_F(winreg_test, enums_and_constants)
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

TEST_F(winreg_test, create_write_read_delete)
{
    // create
    auto key_copy = winreg::current_user.open(m_key.name());

    EXPECT_EQ(m_key, key_copy);

    // write
    m_key.set_dword(winreg::string(STR("dword-value")), 42);
    m_key.set_qword(winreg::string(STR("qword-value")), uint64_t(-1));
    m_key.set_string(winreg::string(STR("string-value")), winreg::string(STR("my-string")));
    
    const auto multistring = std::vector<winreg::string>{ STR("a"), STR("multi"), STR("string") };
    m_key.set_multistring(winreg::string(STR("multistring-value")), multistring);

    // read
    EXPECT_EQ(m_key.get_dword(winreg::string(STR("dword-value"))), 42);
    EXPECT_EQ(m_key.get_qword(winreg::string(STR("qword-value"))), uint64_t(-1));
    EXPECT_EQ(m_key.get_string(winreg::string(STR("string-value"))), winreg::string(STR("my-string")));
    EXPECT_EQ(m_key.get_multistring(winreg::string(STR("multistring-value"))), multistring);

    // delete
    m_key.delete_value(winreg::string(STR("dword-value")));
    m_key.delete_value(winreg::string(STR("qword-value")));
    m_key.delete_value(winreg::string(STR("string-value")));
    m_key.delete_value(winreg::string(STR("multistring-value")));

    winreg::current_user.delete_subkey(m_key.name());

    bool threw = false;
    try
    {
        auto nonexistent_key = winreg::current_user.open(m_key.name());
    }
    catch (std::system_error& e)
    {
        threw = true;
        EXPECT_EQ(std::string("RegOpenKeyEx() failed: The system cannot find the file specified."), std::string(e.what()));
    }

    EXPECT_TRUE(threw);
}

//TEST(winreg_test, transaction)
//{
//    const auto new_key_name = winreg::string(STR("transaction_test"));
//
//    const auto new_key = winreg::local_machine.create_subkey(new_key_name);
//
//    new_key.set_dword(STR("dword-value"), 42);
//
//    auto transaction = winreg::transaction(new_key);
//
//    EXPECT_EQ(transaction.get_dword(STR("dword-value")), 42);
//
//    winreg::current_user.delete_subkey(new_key_name);
//
//}