---
layout: post
description: Undisclosed Home Routers Full Takeover
comments: true
date: 2023-06-01
last-update: 2023-06-01
---

Recently, I came to own some Customer Premises Equipment (CPEs). You might wonder why. Well, occasionally, when I'm feeling bored, I enjoy testing the vulnerabilities of embedded devices, while staying within ethical and righteous boundaries.

In this article, and perhaps in future articles, I will discuss a complete and unauthenticated remote takeover that can be performed on these devices via the embedded management web interface. It should be noted that the management interface of these devices is accessible from the Internet by default.

## Table of Contents

- [Undisclosed Home Routers Full Takeover](#undisclosed-home-routers-full-takeover)
  - [The story](#the-story)
  - [Let’s get started](#lets-get-started)
  - [Router 1](#router-1)
    - [Using the source](#using-the-source)
      - [What is all this XML?](#what-is-all-this-xml)
      - [Back to the blacklist upload](#back-to-the-blacklist-upload)
      - [A dead end?](#a-dead-end)
    - [Injecting commands with no authentication, at last](#injecting-commands-with-no-authentication-at-last)
    - [Recap](#recap)
  - [Router 2](#router-2)
    - [Exploit](#exploit)
  - [Router 3](#router-3)
    - [Exploit](#exploit-1)
  - [How the vendor should fix these issues](#how-the-vendor-should-fix-these-issues)

# Undisclosed Home Routers Full Takeover

The purpose of this article is to raise awareness about vulnerabilities present in cheap modems and routers, especially those provided by telcos.

Stay safe. If possible, I recommend using a custom device, such as one running a robust distribution like [pfSense](https://www.pfsense.org), for your internet access.

## The story

Recently, I came to own some Customer Premises Equipment (CPEs). You might wonder why. Well, occasionally, when I'm feeling bored, I enjoy testing the vulnerabilities of embedded devices, while staying within ethical and righteous boundaries.

In this article, and perhaps in future articles, I will discuss a complete and unauthenticated remote takeover that can be performed on these devices via the embedded management web interface. It should be noted that the management interface of these devices is accessible from the Internet by default.

As for the number of these devices in existence, I don't have an exact figure. However, a quick search on [Shodan](https://www.shodan.io) revealed several thousand devices, primarily located in Russia, India, and China. From my understanding, there are various modems and routers that utilize the same underlying (vulnerable) framework. These devices have been rebranded by several telecommunications companies, each with their own custom configurations and additional features.

I want to make it clear that I will not provide any information that could be used to identify these devices. Instead, I will focus solely on the vulnerabilities I have discovered, which are currently to be considered zero-days. Additionally, I am attempting to contact the framework vendor to address these issues and obtain assigned CVEs.

## Let’s get started

Enumeration is always the first step. So, after brute forcing a few unauthenticated endpoints (without joy) I logged into the router with the default credentials and started to play with the available router features.

I have clear memories of when I was starting my career and found it fascinating how there were numerous "looking glass" services on the internet that were susceptible to system command injections. All it took was adding to the "pinged" or "tracerouted" hostname a semicolon, strategically placed after or instead of the address being tested, and then adding your own commands.

I was under the impression that these vulnerabilities were a thing of the past, but apparently they can still be found. To keep it brief, the router's "diagnostic" interface can be exploited simply by adding a shell command in the form of command substitution: `$(xxx)`. Let me explain with an example. If we were to utilize this technique while pinging a host from the diagnostic interface, the router would construct something like `ping $(id)` and execute it, resulting in an error message displaying information about the malformed or unreachable host, along with the user identification details: `uid=0(root) gid=0(root) groups=0(root)`.

Note: the vulnerability (i.e., CWE-78: Improper Neutralization of Special Elements used in an OS Command aka ‘OS Command Injection’) is present, *with important differences*, in all the routers I tinkered with. Although the exploits require authentication, they allowed me to get an initial foothold on these systems and thus allowed me to find more severe vulnerabilities.

After getting the initial access to the system, I started looking around. Unsurprisingly, I learned that these are embedded Linux devices. The management interface is PHP based, so I grabbed the source code and started reading it.

It should also be noted that a similar level of access could probably be acquired by downloading and unpacking these devices' firmware (e.g., binwalking).

In the rest of the article, I will go a bit deeper on the unauthenticated vulnerabilities I have found.

Nevertheless, in the spirit of responsible disclosure, while waiting for a response from the vendor, I will omit any details that could be used to identify the devices I have tested. Moreover, I will call these devices with dummy names.

## Router 1

### Using the source

After getting a better understanding of the platform and software architecture, I searched for any dangerous PHP command and this function caught my attention:

```php
 function upload()
 {
  $upload_dir = '/tmp';
  $ret = 2;
  if ($_REQUEST['black_upload'] == true) {
   $attachment = $_FILES['black_file_upload'];
   $filename = $attachment['name'];
   $fileext = substr(strrchr($filename, '.'), 1);

   if ($filename != null && ($fileext == "txt" || $fileext == "TXT")) {
    $path = $upload_dir . "/" . $filename;
    move_uploaded_file($attachment['tmp_name'], $path);

    $fp = @fopen($path, "r");

    $black_xml = '<http_filter action="add"><group>';
    $black_xml .= '<name>black_list</name>';
    $black_xml .= '<item>';
    while (!feof($fp)) {
                  [...]
    }

    $black_xml .= '</item></group></http_filter>';

    $ret = Node_mod3($black_xml);
    if ($ret == 0) $ret = 1;
    fclose($fp);
    @system('mount /dev/cfa1 /mnt');
    @system('mv ' . $path . ' /mnt/local_black_list.txt'); // <-- Line 29
                [...]
   }
            [...]
  }
        [...]
 }
```

The `upload()` function above is called by the CRUD logic for the router URL filtering feature. Specifically, it can be called to upload a blacklist to the router.

Line `29` above seemed immediately interesting, as `$path` is tainted (i.e., partially controlled by user). My goal now was to use this function providing a malicious filename to get RCE via `system()`.

#### What is all this XML?

After some research, I realized that in order to perform system operations (and seemingly router configuration), the PHP frontend communicates with a system daemon named `guish`. This uses a proprietary XML protocol over a Unix Domain Socket (UDS).

When the user logs in, an authenticated session is created using a PHP session. In particular, among other things, `$_SESSION['session_id']` is defined and a session with the same id is created within the `guish` system daemon context.

My research shows that the `guish` daemon validates the received XML by checking whether the session, passed from PHP via XML, exists, and it’s not expired.

#### Back to the blacklist upload

The PHP function used to communicate with `guish` is in this case `Node_mod3()`. Although the return value of that function is basically ignored, the library functions called from that function would eventually `die()` if there was no authenticated PHP session. This prevents reaching line `29` in the above listing.

```php
function Node_mod3($node_xml)
{
 global $obj_guish;
 $str = 0;
 if ($node_xml != "") {
  $obj_guish->set_rsgui($_SESSION['session_id'], NULL, $node_xml, UCT_CMD);
  $str_xml = $obj_guish->get_xml();
  $str = check_err3($str_xml, 'mod');
 }

 return $str;
}
```

The `die()` invocation happens because without an authenticated session, `$obj_guish` is not initialized by `set_rsgui()`. Thus, the subsequent `get_xml()` method call finds `obj_guish->rs_guish == NULL` and bails out.

```php
function get_xml()
{
 $str_xml = NULL;
 if($this->sock_fd <=0 ||$this->rs_guish == NULL)
 {
  die('[...]');
 }
    [...]
}
```

So, even if I could control the program flow to the `upload()` function above, I couldn't inject any system command, without being authenticated.

#### A dead end?

Continuing my source code exploration, I noticed another upload PHP endpoint.

```php
[...]
<?php
[...]
$upload_dir = '/tmp';
[...]
$attachment = $_FILES['Filedata'];
$filename = $attachment['name']; //iconv("UTF-8","GB2312",$attachment['name']);//$attachment['name'];
[...]
$path = $upload_dir . "/" . $filename;
[...]
if (!move_uploaded_file($attachment['tmp_name'], $path)) {
 echo "#### upload file failed";
 exit(1);
}
[...]
```

This PHP file where this endpoint lives is quite disorganized. It's filled with commented-out code and "debug" statements scattered all over, which immediately caught my attention.

Based on the code style, it seems likely that this is a custom endpoint that was added later to the router (maybe by a telco?). Interestingly, this endpoint is completely unauthenticated and allows for file uploads to the router's temporary file system (tmpfs).

This is a significant vulnerability on its own. It enables the uploading of any file with any filename to the `/tmp` directory, excluding its subdirectories. For the RCE we are chasing, it's common knowledge that PHP stores sessions in the `/tmp` directory by default... aha!

### Injecting commands with no authentication, at last

From what stated before about the blacklist uploading feature, we needed a PHP session to get our “unauthenticated” RCE… so we have succeeded: we just need to create and upload a session file, pass the right PHP session identifier in the HTTP cookie, and we can get past line `25` of the function `upload()` above.

Note: since we can only create a PHP session, which is not used by or passed to the `guish` daemon, we won’t be actually able to use the web interface to operate the system and the router configuration. Nevertheless, to get to command injection via PHP, we don’t need that.

Our entry point is this piece of code:

```php
@system('mv ' . $path . ' /mnt/local_black_list.txt');
```

The URL filtering blacklist `upload()` function checks the extension of the upload file:

```php
if ($filename != null && ($fileext == "txt" || $fileext == "TXT")) { 
    [...]
```

So we need to be a bit creative...

***Here is an example of filename that we can use to do RCE:***

```php
a;sleep 2 #.txt
```

Note that this is a blind RCE, but since these commands will be executed as root, from here it’s an easy task to get a full shell.

### Recap

To recap, the steps to get this unauthenticated RCE are:

1. create a fake session containing just a serialized variable `session_id`;
2. using the aforementioned arbitrary file upload endpoint, upload that session file with a name like `sess_cafebabe`;
3. call the URL filtering endpoint, using a cookie with `PHPSESSID` equals to `sess_cafebabe` and with the right parameters. Specifically, use the blacklist filename to inject system commands.

From there, a malicious actor could use the router to pivot into your local network, looking at your traffic and create any sort of serious problems…

## Router 2

After the experience with Router 1, this one was relatively easy.

Again, I used the administrative interface “diagnostics” to get the initial foothold and download source code and artefacts from the router.

I found an interesting endpoint, used probably by telcos to upload the system configuration.

```php
<?
require('php_class/function.php');
require '/www/custom/language_resource/sys_language.php';

$upload_dir = '/www';
$attachment = $_FILES['Filedata'];
$filename = $attachment['name'];
$fileext = substr(strrchr($filename, '.'), 1);
$path = $upload_dir . "/" . $filename;
move_uploaded_file($attachment['tmp_name'], $path);
[...]
```

This was easy. You can basically upload any file, with any filename and extension, straight into `/www`. The `/www` directory (the whole root filesystem, actually) is writeable. In fact, as it turns out, during boot the `init` script unpacks a tarball with the root filesystem and leaves it `rw`.

### Exploit

The exploit is very simple: just upload a `.php` file and its code will be executed with root privileges.

## Router 3

The third router was even easier than the second.

In fact, very much like Router 1 and Router 2, this one has an unauthenticated generic upload endpoint… The difference is that this endpoint uploads stuff straight into the `/www` directory.

### Exploit

Although the endpoint is different from the one used for Router 2, the exploit for this router is the same as for Router 2.

## How the vendor should fix these issues

All the three full takeovers are possible because of the presence of an unauthenticated upload endpoint.

The PHP code should make sure to authenticate these endpoints or be extremely careful while handling user input.

The diagnostic features on management interface should validate user provided input, so that also authenticated exploits are not possible.
