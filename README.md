## ip Bash Completion

This is an enhanced version of the existing ip command's autocomplete function.  
This function is based on the help message output by the ip command.

```sh
bash$ hostnamectl
Operating System: Ubuntu 22.10                    
          Kernel: Linux 5.19.0-23-generic
    Architecture: x86-64

bash$ ip -Version
ip utility, iproute2-5.15.0, libbpf 0.8.0

bash$ ip [tab]
address     ioam        monitor     neighbour   ntbl        tcpmetrics  xfrm
addrlabel   l2tp        mptcp       netconf     route       token       
fou         link        mroute      netns       rule        tunnel      
help        macsec      mrule       nexthop     sr          tuntap      
ila         maddress    neighbor    ntable      tap         vrf
```


## Usage

Basically, capitalized words are values that the user has to enter.

```sh
bash$ ip route add PREFIX via ADDRESS

bash$ ip route add 10.0.3.0/24 via 10.0.3.1
```

It may be necessary to escape spaces if the completion word consists of multiple words.

```sh
foo\ ba[tab]      # escape space with "\"
```

## Installation

Copy contents of `httpie-bash-completion.sh` file to `~/.bash_completion`.  
open new terminal and try auto completion !


> please leave an issue above if you have problems using this script.


