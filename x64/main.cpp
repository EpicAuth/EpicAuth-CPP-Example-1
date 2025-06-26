#include <Windows.h>
#include "auth.hpp"
#include <string>
#include <thread>
#include "utils.hpp"
#include "skStr.h"
#include <iostream>
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
void sessionStatus();

using namespace EpicAuth;

// copy and paste from https://EpicAuth.cc/app/ and replace these string variables
// Please watch tutorial HERE https://www.youtube.com/watch?v=5x4YkTmFH-U
std::string name = skCrypt("name").decrypt(); // App name
std::string ownerid = skCrypt("ownerid").decrypt(); // Account ID
std::string version = skCrypt("1.0").decrypt(); // Application version. Used for automatic downloads see video here https://www.youtube.com/watch?v=kW195PLCBKs
std::string url = skCrypt("https://EpicAuth.cc/api/1.3/").decrypt(); // change if using KeyAuth custom domains feature
std::string path = skCrypt("").decrypt(); // (OPTIONAL) see tutorial here https://www.youtube.com/watch?v=I9rxt821gMk&t=1s


api EpicAuthApp(name, ownerid, version, url, path);

int main()
{
    std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");

    EpicAuthApp.init();
    if (!EpicAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << EpicAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    if (std::filesystem::exists("test.json")) //change test.txt to the path of your file :smile:
    {
        if (!CheckIfJsonKeyExists("test.json", "username"))
        {
            std::string key = ReadFromJson("test.json", "license");
            EpicAuthApp.license(key);
            if (!EpicAuthApp.response.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << EpicAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
        else
        {
            std::string username = ReadFromJson("test.json", "username");
            std::string password = ReadFromJson("test.json", "password");
            EpicAuthApp.login(username, password);
            if (!EpicAuthApp.response.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << EpicAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
    }
    else
    {
        std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

        int option;
        std::string username, password, key, TfaCode;

        std::cin >> option;
        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter 2fa code if applicable: ");
            std::cin >> TfaCode;
            EpicAuthApp.login(username, password, TfaCode);
            break;
        case 2:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            EpicAuthApp.regstr(username, password, key);
            break;
        case 3:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            EpicAuthApp.upgrade(username, key);
            break;
        case 4:
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            std::cout << skCrypt("\n Enter 2fa code if applicable: ");
            std::cin >> TfaCode;
            EpicAuthApp.license(key, TfaCode);
            break;
        default:
            std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
            Sleep(3000);
            exit(1);
        }

        if (EpicAuthApp.response.message.empty()) exit(11);
        if (!EpicAuthApp.response.success)
        {
            std::cout << skCrypt("\n Status: ") << EpicAuthApp.response.message;
            Sleep(1500);
            exit(1);
        }

        if (username.empty() || password.empty())
        {
            WriteToJson("test.json", "license", key, false, "", "");
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }
        else
        {
            WriteToJson("test.json", "username", username, true, "password", password);
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }
    }

    /*
    * Do NOT remove this checkAuthenticated() function.
    * It protects you from cracking, it would be NOT be a good idea to remove it
    */
    std::thread run(checkAuthenticated, ownerid);
    // do NOT remove checkAuthenticated(), it MUST stay for security reasons
    std::thread check(sessionStatus); // do NOT remove this function either.

    //enable 2FA 
    // EpicAuthApp.enable2fa(); you will need to ask for the code
    //enable 2fa without the need of asking for the code
    //EpicAuthApp.enable2fa().handleInput(EpicAuthApp);

    //disbale 2FA
    // EpicAuthApp.disable2fa();

    if (EpicAuthApp.user_data.username.empty()) exit(10);
    std::cout << skCrypt("\n User data:");
    std::cout << skCrypt("\n Username: ") << EpicAuthApp.user_data.username;
    std::cout << skCrypt("\n IP address: ") << EpicAuthApp.user_data.ip;
    std::cout << skCrypt("\n Hardware-Id: ") << EpicAuthApp.user_data.hwid;
    std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(EpicAuthApp.user_data.createdate)));
    std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(EpicAuthApp.user_data.lastlogin)));
    std::cout << skCrypt("\n Subscription(s): ");

    for (int i = 0; i < EpicAuthApp.user_data.subscriptions.size(); i++) {
        auto sub = EpicAuthApp.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
    }


    std::cout << skCrypt("\n\n Status: ") << EpicAuthApp.response.message;


    std::cout << skCrypt("\n\n Closing in five seconds...");
    Sleep(5000);

    return 0;
}

void sessionStatus() {
    EpicAuthApp.check(true); // do NOT specify true usually, it is slower and will get you blocked from API
    if (!EpicAuthApp.response.success) {
        exit(0);
    }

    if (EpicAuthApp.response.isPaid) {
        while (true) {
            Sleep(20000); // this MUST be included or else you get blocked from API
            EpicAuthApp.check();
            if (!EpicAuthApp.response.success) {
                exit(0);
            }
        }
    }
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10); // long

    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}
