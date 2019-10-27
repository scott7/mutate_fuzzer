# Mutate fuzzer for networking devices


* The following fuzzer will send fuzzed xml rpc commands, based on valid commands, post authentication to a junos device.
* Requires PyEZ module from Juniper to be installed: https://github.com/Juniper/py-junos-eznc
* This will stop with a connection error if a non-Junos device is input.

## Command types

* This can send two different command types:
* `send_xml_cmd()` --> `<rpc><command>show system uptime</command></rpc>`
* `send_rpc_cmd()` --> (requires valid command)
     ```
     <rpc><get-system-uptime-information>
     </get-system-uptime-information></rpc>
     ```

## Variations

* This fuzzer will fuzz valid commands with different character types and different order generated for each case.
* It will randomly choose to append, prepend, or mix the fuzzed data.
* It will always generate a proper xml rpc format for Junos so that it won't be rejected right away - except in the case of ASCII control characters (these will be send without proper formatting).


## Sample output

* Sample output:
* 'name' indicates what type of fuzzed data is being used (generated in `generate_fuzz_data()`).
* JSON logs will be written during execution so cntrl-c abort can be used. 
* JSON log sameple at sample_data_20191027-193544.json
```
python3 mutate_fuzz.py -i x.x.x.x -u user
using telnet - not secure
Password:
Password received
Test command succeeded
STARTING FUZZING - writing to json file for logs

======Case 1======
    name    --> rand_fuzz_numbers_special
    command --> show syst))$;/;%&4.-9=*"""1;8#;!(%9?%4)$59 )36 80#522%6/78/?$?0(=%528-#4747$!*&&03:2?/2%+)?+81?$;(%':$#5='60'*,4%<56"%28(.$2"<"!+7:5"<";4;86&( .>%6;#0 8% 6<!;2>#.3(.%8*(!,::41&$>,06,!&2em uptime
    result  --> RpcError(severity: error, bad_element: ), message: syntax error, expecting <command>)

failed: RpcError(severity: error, bad_element: systdsphvwzwmoxibzaexcfeyeplxkbefuhdqgrxpgkbzovgfemldtdxsiawojnysszcqfohdrrcbkdirunryafzxiowbrjavczrvdgvjxcrwmuthaahtexwxzhmixhwmxuluiesjvsinsdvyvemibazjsrem, message: syntax error, expecting <command>)
======Case 2======
    name    --> rand_fuzz_abc
    command --> show systdsphvwzwmoxibzaexcfeyeplxkbefuhdqgrxpgkbzovgfemldtdxsiawojnysszcqfohdrrcbkdirunryafzxiowbrjavczrvdgvjxcrwmuthaahtexwxzhmixhwmxuluiesjvsinsdvyvemibazjsrem uptime
    result  --> RpcError(severity: error, bad_element: systdsphvwzwmoxibzaexcfeyeplxkbefuhdqgrxpgkbzovgfemldtdxsiawojnysszcqfohdrrcbkdirunryafzxiowbrjavczrvdgvjxcrwmuthaahtexwxzhmixhwmxuluiesjvsinsdvyvemibazjsrem, message: syntax error, expecting <command>)

======Case 3======
---- Possible Crash detected----
Reason --> Unexpected error message
    name    --> valid_commands_mixed
    command --> ping 172.26.0.19show system uptimeversion+2&=6
    result  --> RpcError(severity: error, bad_element: system, message: syntax error)

======Case 4======
    name    --> valid_commands_with_chars_ascii
    command --> sh version+2&=6 $.?*>!>816)$<3259,;-!/4show system uptime
    result  --> RpcError(severity: error, bad_element: version+2, message: syntax error, expecting <command>)

======Case 5======
    name    --> valid_commands_with_cc_ascii
    command --> b'sh version\x13\x14\x1e\x13\x15\x19\x1e\x1e\x1c\x10\r\x11\x0e\r\x08\x07\x1d\x0c\n\x1b\x14\x19\x04\x1d\x18\x15\x08\x01\x07\r\x0e\x0f\n\x1d\x12\x19\x03\x07\nshow system uptime'
    result  --> Start tag expected, '<' not found, line 1, column 1 (<string>, line 1)
...
```
