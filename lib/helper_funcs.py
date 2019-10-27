import random
import json
import sys
from collections import OrderedDict

##
# Helper functions
##
def rand_fuzz(max_length=200, char_start=32, char_range=32, ret_hex=False):
    """
    Random fuzzer used in generate_fuzz()
    """
    string_length = random.randrange(0, max_length + 1)
    ret = ""
    for i in range(0, string_length):
        if(ret_hex):
            ret += hex(random.randrange(char_start, char_start + char_range))
        else:
            ret += chr(random.randrange(char_start, char_start + char_range))
    return ret

def generate_fuzz_data():
    """
    generate various static and randomized fuzz data called in mutate_fuzzer
    return dict of values
    """
    fuzz_data = {}
    fuzz_data['rand_fuzz_numbers_special'] = rand_fuzz()
    fuzz_data['rand_fuzz_abc'] = rand_fuzz(char_start=ord('a'), char_range = 26)
    fuzz_data['rand_fuzz_control_chars_ascii'] = rand_fuzz(char_start=0, char_range=31)
    fuzz_data['rand_fuzz_control_chars_hex'] = rand_fuzz(char_start=0, char_range=31, ret_hex=True)
    fuzz_data['rand_fuzz_extended_ascii'] = rand_fuzz(char_start=127, char_range = 127)
    valid_commands_list = ['show', 'set', 'load', 'sh', 'sh version', 'show version',
                          'show route', 'show policy', 'ping 172.26.0.19', 'ping']
    fuzz_data['valid_commands_mixed'] = random.choice(valid_commands_list)
    fuzz_data['valid_commands_with_chars_ascii'] = random.choice(valid_commands_list) + rand_fuzz()
    fuzz_data['valid_commands_with_cc_ascii'] = random.choice(valid_commands_list) + rand_fuzz(char_start=0, char_range=31)
    fuzz_data['large_string_data'] = 'A' * 5000
    fuzz_data['spaces'] = ' ' * 1000
    fuzz_data['exit'] = 'exit;' + rand_fuzz()
    return fuzz_data

def generate_fuzz_string(string):
    """
    Uses generate_fuzz_data for randomized data to add to valid commands.
    """
    fuzz_data = generate_fuzz_data()
    ret = {}
    options = ['pre','post','mixed']
    choice = random.choice(options)
    if choice == 'post':
        for name,value in fuzz_data.items():
            ret[name] = string + value
    elif choice == 'pre':
        for name,value in fuzz_data.items():
            ret[name] = value + string
    elif choice == 'mixed':
        lens = len(string)
        half = round(lens / 2)
        subs1 = string[0:half]
        subs2 = string[half:lens]
        for name,value in fuzz_data.items():
            ret[name] = subs1 + value + subs2
    return ret

def populate_dict_from_json(filename):
    try:
        fh = open(filename, "r")
    except Exception as e:
        return False

    new_dict = OrderedDict()
    try:
        new_dict = json.load(fh,object_pairs_hook=OrderedDict)
        fh.close()
    except Exception as e:
        return False

    return new_dict
