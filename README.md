# EpicAuth-CPP-Example : Please star 🌟

EpicAuth C++ example SDK for https://EpicAuth.cc license key API auth.

This example uses a C++ static library found here https://github.com/EpicAuth/EpicAuth-cpp-library-1.3API

### Tutorial Video

This video explains both how to use this example, but also how to add EpicAuth to your <ins>**OWN PROJECT**</ins> https://www.youtube.com/watch?v=GEXpZo3sce0

## **Bugs**

If you are using our example with no significant changes, and you are having problems, please Report Bug here https://EpicAuth.cc/app/?page=forms

However, we do **NOT** provide support for adding EpicAuth to your project. If you can't figure this out you should use Google or YouTube to learn more about the programming language you want to sell a program in.

## **Security practices**

* Utilize obfuscation provided by companies such as VMProtect or Themida (utilize their SDKs too for greater protection)
* Preform frequent integrity checks to ensure the memory of the program has not been modified
* Don't write the bytes of a file you've downloaded to disk if you don't want that file to be retrieved by the user. Rather, execute the file in memory and erase it from memory the moment execution finishes

While our API ensures licenses validation, it's crucial to implement robust client-side protection like obfuscation and integrity checks to prevent software tampering, as vulnerabilities often stem from insufficient client security.

## Copyright License

EpicAuth is licensed under **Elastic License 2.0**

* You may not provide the software to third parties as a hosted or managed
service, where the service provides users with access to any substantial set of
the features or functionality of the software.

* You may not move, change, disable, or circumvent the license key functionality
in the software, and you may not remove or obscure any functionality in the
software that is protected by the license key.

* You may not alter, remove, or obscure any licensing, copyright, or other notices
of the licensor in the software. Any use of the licensor’s trademarks is subject
to applicable law.

Thank you for your compliance, we work hard on the development of EpicAuth and do not appreciate our copyright being infringed.

## **What is EpicAuth?**

EpicAuth is an Open source authentication system with cloud hosting plans as well. Client SDKs available for [C#](https://github.com/EpicAuth/EpicAuth-CSHARP-Example), [C++](https://github.com/EpicAuth/EpicAuth-CPP-Example), [Python](https://github.com/EpicAuth/EpicAuth-Python-Example), [Java](https://github.com/EpicAuth/EpicAuth-JAVA-api), [JavaScript](https://github.com/EpicAuth/EpicAuth-JS-Example), [VB.NET](https://github.com/EpicAuth/EpicAuth-VB-Example), [PHP](https://github.com/EpicAuth/EpicAuth-PHP-Example), [Rust](https://github.com/EpicAuth/EpicAuth-Rust-Example), [Go](https://github.com/EpicAuth/EpicAuth-Go-Example), [Lua](https://github.com/EpicAuth/EpicAuth-Lua-Examples), [Ruby](https://github.com/EpicAuth/EpicAuth-Ruby-Example), and [Perl](https://github.com/EpicAuth/EpicAuth-Perl-Example). EpicAuth has several unique features such as memory streaming, webhook function where you can send requests to API without leaking the API, discord webhook notifications, ban the user securely through the application at your discretion. Feel free to join https://t.me/EpicAuth if you have questions or suggestions.

> [!TIP]
> https://vaultcord.com FREE Discord bot to Backup server, members, channels, messages & more. Custom verify page, block alt accounts, VPNs & more.

## **Customer connection issues?**

This is common amongst all authentication systems. Program obfuscation causes false positives in virus scanners, and with the scale of EpicAuth this is perceived as a malicious domain. So, `EpicAuth.com` and `EpicAuth.cc` have been blocked by many internet providers. for dashbord, reseller panel, customer panel, use `EpicAuth.cc`

For API, `EpicAuth.cc` will not work because I purposefully blocked it on there so `EpicAuth.cc` doesn't get blocked also. So, you should create your own domain and follow this tutorial video https://www.youtube.com/watch?v=a2SROFJ0eYc. The tutorial video shows you how to create a domain name for 100% free if you don't want to purchase one.

## **`EpicAuthApp` instance definition**

Visit https://EpicAuth.cc/app/ and select your application, then click on the **C++** tab

It'll provide you with the code which you should replace with in the [`main.cpp`](https://github.com/EpicAuth/EpicAuth-CPP-Example/blob/8f3215d5259c42f25854476c49ee443d67af639a/main.cpp#L14-L17) file

```cpp
std::string name = "example"; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = "JjPMBVlIOd"; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = "db40d586f4b189e04e5c18c3c94b7e72221be3f6551995adc05236948d1762bc"; // app secret, the blurred text on licenses tab and other tabs
std::string version = "1.0"; // leave alone unless you've changed version on website
std::string url = "https://EpicAuth.cc/api/1.2/"; // change if you're self-hosting

api EpicAuthApp(name, ownerid, secret, version, url);
```

## **Initialize application**

You must call this function prior to using any other EpicAuth function. Otherwise the other EpicAuth function won't work.

```cpp
EpicAuthApp.init();
if (!EpicAuthApp.response.success)
{
	std::cout << skCrypt("\n Status: ") << EpicAuthApp.response.message;
	Sleep(1500);
	exit(0);
}
```

## **Display application information**

```cpp
EpicAuthApp.fetchstats();
std::cout << skCrypt("\n\n Number of users: ") << EpicAuthApp.app_data.numUsers;
std::cout << skCrypt("\n Number of online users: ") << EpicAuthApp.app_data.numOnlineUsers;
std::cout << skCrypt("\n Number of keys: ") << EpicAuthApp.app_data.numKeys;
std::cout << skCrypt("\n Application Version: ") << EpicAuthApp.app_data.version;
std::cout << skCrypt("\n Customer panel link: ") << EpicAuthApp.app_data.customerPanelLink;
```

## **Check session validation**

Use this to see if the user is logged in or not.

```cpp
std::cout << skCrypt("\n Checking session validation status (remove this if causing your loader to be slow)");
EpicAuthApp.check();
std::cout << skCrypt("\n Current Session Validation Status: ") << EpicAuthApp.response.message;
```

## **Check blacklist status**

Check if HWID or IP Address is blacklisted. You can add this if you want, just to make sure nobody can open your program for less than a second if they're blacklisted. Though, if you don't mind a blacklisted user having the program for a few seconds until they try to login and register, and you care about having the quickest program for your users, you shouldn't use this function then. If a blacklisted user tries to login/register, the EpicAuth server will check if they're blacklisted and deny entry if so. So the check blacklist function is just auxiliary function that's optional.

```cpp
if (EpicAuthApp.checkblack()) {
	abort();
}
```

## **Login with username/password**

```cpp
std::string username;
std::string password;
std::cout << skCrypt("\n\n Enter username: ");
std::cin >> username;
std::cout << skCrypt("\n Enter password: ");
std::cin >> password;
EpicAuthApp.login(username, password);
if (!EpicAuthApp.response.success)
{
	std::cout << skCrypt("\n Status: ") << EpicAuthApp.response.message;
	Sleep(1500);
	exit(0);
}
```

## **Register with username/password/key**

```cpp
std::string username;
std::string password;
std::string key;
std::cout << skCrypt("\n\n Enter username: ");
std::cin >> username;
std::cout << skCrypt("\n Enter password: ");
std::cin >> password;
std::cout << skCrypt("\n Enter license: ");
std::cin >> key;
EpicAuthApp.regstr(username, password, key);
if (!EpicAuthApp.response.success)
{
	std::cout << skCrypt("\n Status: ") << EpicAuthApp.response.message;
	Sleep(1500);
	exit(0);
}
```

## **Upgrade user username/key**

Used so the user can add extra time to their account by claiming new key.

> [!WARNING]  
> No password is needed to upgrade account. So, unlike login, register, and license functions - you should **not** log user in after successful upgrade.


```cpp
std::string username;
std::string key;
std::cout << skCrypt("\n\n Enter username: ");
std::cin >> username;
std::cout << skCrypt("\n Enter license: ");
std::cin >> key;
EpicAuthApp.upgrade(username, key);
```

## **Login with just license key**

Users can use this function if their license key has never been used before, and if it has been used before. So if you plan to just allow users to use keys, you can remove the login and register functions from your code.

```cpp
std::string key;
std::cout << skCrypt("\n Enter license: ");
std::cin >> key;
EpicAuthApp.license(key);
if (!EpicAuthApp.response.success)
{
	std::cout << skCrypt("\n Status: ") << EpicAuthApp.response.message;
	Sleep(1500);
	exit(0);
}
```

## **Login with web loader**

Have your users login through website. Tutorial video here https://www.youtube.com/watch?v=9-qgmsUUCK4 you can use your own domain for customer panel also, https://www.youtube.com/watch?v=iHQe4GLvgaE

```cpp
std::cout << "\n Waiting for user to login";
EpicAuthApp.web_login();
std::cout << "\n Waiting for button to be clicked";
EpicAuthApp.button("close");
```

## **User Data**

Show information for current logged-in user.

```cpp
std::cout << skCrypt("\n User data:");
std::cout << skCrypt("\n Username: ") << EpicAuthApp.response.username;
std::cout << skCrypt("\n IP address: ") << EpicAuthApp.user_data.ip;
std::cout << skCrypt("\n Hardware-Id: ") << EpicAuthApp.user_data.hwid;
std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(EpicAuthApp.user_data.createdate)));
std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(EpicAuthApp.user_data.lastlogin)));
std::cout << skCrypt("\n Subscription name(s): ");
std::string subs;
for (std::string value : EpicAuthApp.user_data.subscriptions)subs += value + " ";
std::cout << subs;
std::cout << skCrypt("\n Subscription expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(EpicAuthApp.user_data.expiry)));
```

## **Check subscription name of user**

If you want to wall off parts of your app to only certain users, you can have multiple subscriptions with different names. Then, when you create licenses that correspond to the level of that subscription, users who use those licenses will get a subscription with the name of the subscription that corresponds to the level of the license key they used.

```cpp
for (std::string subs : EpicAuthApp.user_data.subscriptions)
{
	if (subs == "default")
	{
		std::cout << skCrypt("\n User has subscription with name: default");
	}
}
```

## **Application variables**

A string that is kept on the server-side of EpicAuth. On the dashboard you can choose for each variable to be authenticated (only logged in users can access), or not authenticated (any user can access before login). These are global and static for all users, unlike User Variables which will be dicussed below this section.

```cpp
// get data from global variable with name 'status'
std::cout << "\n status - " + EpicAuthApp.var("status");
```

## **User Variables**

User variables are strings kept on the server-side of EpicAuth. They are specific to users. They can be set on Dashboard in the Users tab, via SellerAPI, or via your loader using the code below. `discord` is the user variable name you fetch the user variable by. `test#0001` is the variable data you get when fetching the user variable.

```cpp
std::cout << "\n user variable - " + EpicAuthApp.getvar("discord"); // get value of the user variable 'discord'
```

And here's how you fetch the user variable:

```cpp
EpicAuthApp.setvar("discord", "test#0001"); // set the value of user variable 'discord' to 'test#0001'
```

## **Application Logs**

Can be used to log data. Good for anti-debug alerts and maybe error debugging. If you set Discord webhook in the app settings of the Dashboard, it will send log messages to your Discord webhook rather than store them on site. It's recommended that you set Discord webhook, as logs on site are deleted 1 month after being sent.

You can use the log function before login & after login.

```cpp
EpicAuthApp.log("user logged in"); // send event to logs. if you set discord webhook in app settings, it will send there instead of dashboard
```

## **Ban the user**

Ban the user and blacklist their HWID and IP Address. Good function to call upon if you use anti-debug and have detected an intrusion attempt.

Function only works after login.

```cpp
EpicAuthApp.ban();
```

## **Ban the user (with reason)**

Ban the user and blacklist their HWID and IP Address. Good function to call upon if you use anti-debug and have detected an intrusion attempt.

Function only works after login.

The reason paramater will be the ban reason displayed to the user if they try to login, and visible on the EpicAuth dashboard.

```cpp
EpicAuthApp.ban("You have been banned because of reason..");
```

## **Server-sided webhooks**

Tutorial video https://www.youtube.com/watch?v=ENRaNPPYJbc

> [!NOTE]
> Read documentation for EpicAuth webhooks here https://EpicAuth.readme.io/reference/webhooks-1

Send HTTP requests to URLs securely without leaking the URL in your application. You should definitely use if you want to send requests to SellerAPI from your application, otherwise if you don't use you'll be leaking your seller key to everyone. And then someone can mess up your application.

```cpp
std::string resp = EpicAuthApp.webhook("Sh1j25S5iX", "&mak=best&debug=1");
if (!EpicAuthApp.response.success) // check whether webhook request sent correctly
{
	std::cout << skCrypt("\n\n Status: ") << EpicAuthApp.response.message;
	Sleep(1500);
	exit(0);
}
std::cout << "\n Response recieved from webhook request: " + resp;
```

## **Download file**

> [!NOTE]
> Read documentation for EpicAuth files here https://docs.EpicAuth.cc/website/dashboard/files

Keep files secure by providing EpicAuth your file download link on the EpicAuth dashboard. Make sure this is a direct download link (as soon as you go to the link, it starts downloading without you clicking anything). The EpicAuth download function provides the bytes, and then you get to decide what to do with those. This example shows how to write it to a file named `text.txt` in the same folder as the program, though you could execute with RunPE or whatever you want.

`362906` is the file ID you get from the dashboard after adding file.

```cpp
// remember, certain paths like windows folder will require you to turn on auto run as admin https://stackoverflow.com/a/19617989
std::vector<std::uint8_t> bytes = EpicAuthApp.download("362906");
if (!EpicAuthApp.response.success) // check whether file downloaded correctly
{
	std::cout << skCrypt("\n\n Status: ") << EpicAuthApp.response.message;
	Sleep(1500);
	exit(0);
}
std::ofstream file("file.dll", std::ios_base::out | std::ios_base::binary);
file.write((char*)bytes.data(), bytes.size());
file.close();
```

## **Chat channels**

Allow users to communicate amongst themselves in your program.

```cpp
EpicAuthApp.chatget("test");
for (int i = 0; i < EpicAuthApp.response.channeldata.size(); i++)
{
	std::cout << "\n Author:" + EpicAuthApp.user_data.channeldata[i].author + " | Message:" + EpicAuthApp.user_data.channeldata[i].message + " | Send Time:" + tm_to_readable_time(timet_to_tm(string_to_timet(EpicAuthApp.user_data.channeldata[i].timestamp)));
}
```

```cpp
std::cout << skCrypt("\n Type Chat message: ");
std::string message;
std::getline(std::cin, message);
if (!EpicAuthApp.chatsend("test", message))
{
	std::cout << EpicAuthApp.response.message << std::endl;
}
```

Here's an ImGui example https://github.com/EpicAuth-Archive/EpicAuth-Chat-ImGui-CPP

## **Changing username**

Allow users to change their username when logged-in.

```cpp
std::cout << skCrypt("\n Change Username To: ");
std::string newusername;
std::cin >> newusername;
EpicAuthApp.changeusername(newusername);
if (EpicAuthApp.response.success) 
{
        std::cout << EpicAuthApp.response.message << std::endl;
}
```
