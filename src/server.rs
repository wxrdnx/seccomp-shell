use crate::config::Config;

pub fn help() {
    print!("
    Core Commands
    ============= 

        Command                Description
        -------                -----------
        options                List all options
        set <option> <value>   Set option
        run                    Start server
        close                  Close server
        back                   Back to menu
");
}

pub fn option_help(config: &mut Config) {
    print!("
    Options
    =======

        Option        Value           Description
        ------        -----           -----------
        host          {:<16}Server host
        port          {:<16}Server port
        format        {:<16}Shellcode format
        read_syscall  SYS_{:<12}Read syscall


    Available Syscalls
    ==================

        Verb          Syscalls
        ----          --------
        read_syscall  SYS_read, SYS_recvfrom

    Shellcode Formats
    ==================

        Format        Example
        -------       -------
        quoted        \"\\xde\\xad\\xbe\\xef\"
        hex           deadbeef
", config.server_host, config.server_port, config.sc_fmt, config.read_syscall);
}

pub fn prompt(config: &mut Config) {
    option_help(config);
}
