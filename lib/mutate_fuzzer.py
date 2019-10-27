"""
Uses PyEZ module:
https://github.com/Juniper/py-junos-eznc
"""

import datetime
import json
import codecs
import sys
import re

from collections import OrderedDict
from time import time,sleep
from lxml import etree
from lxml.builder import E
from pprint import pprint
from jnpr.junos import Device
from lib.helper_funcs import rand_fuzz, generate_fuzz_data, generate_fuzz_string, populate_dict_from_json

class Fuzz:
    """
    Class to initiate mutate fuzzer
    """
    def __init__(self, host, user, password, mode, port):
        self.host = host
        self.user = user
        self.password = password
        self.mode = mode
        self.port = port
        device = Device(host=self.host, user=self.user, password=self.password,
                        mode=self.mode, port=self.port, gather_facts=False)
        try:
            device.open()
        except Exception as e:
            print("Failed to connect: " + str(e))
            sys.exit("Failed to connect")
        self.device = device


    def catch(self, response):
          """
          Return true if we have unexpected command result or anything
          that would indicate a crash
          Return <boolean result>,<string reason>
          """
          up = self.device.probe()
          # try twice
          if not up:
              up = self.device.probe()
              if not up:
                  print("Device not responding.")
                  return True, "not responding"

          # these are expected command results
          if isinstance(response,str):
              regex = re.compile('syntax error, expecting')
              match = regex.search(response)
              if match:
                  return False, "NA"
              elif re.search('Start tag expected',response):
                  return False, "NA"
              elif re.search("utf-8' codec can't decode byte",response):
                  return False, "NA"
              elif re.search("syntax error",response):
                  return False, "NA"
          else:
              if response is not None and isinstance(response.tag,str):
                  return False, "NA"
          return True, "Unexpected error message"


    def send_xml_command(self, cmd, debug=False, raw=False):
        """
        Send command in the following format: <rpc><command>show system uptime</command></rpc>
        Does not require 'command lookup'
        When 'raw' is set to True - do not build command as XML (for cases of ascii control chars)
        """
        resp = None
        if not raw:
            convert_cmd = E('command', cmd)
        else:
            convert_cmd = cmd
        if debug:
            print(f'send_xml_cmd() convert_cmd --> {convert_cmd}')
        try:
            resp = self.device.execute(convert_cmd, normalize=False)
            if debug:
                etree.dump(resp)
            return resp
        except Exception as e:
            print("failed: " + str(e))
            if resp:
               etree.dump(resp)
            return str(e)
        return None

    def send_cmd_wrapper(self, cmd, debug=False, command_xml=True, raw=False):
        """
        Wrapper function to send data to Junos API
        """
        if command_xml:
            result = self.send_xml_command(cmd=cmd, debug=debug, raw=raw)
        else:
            if raw:
                result = self.send_xml_command(cmd=cmd, debug=debug, raw=raw)
            else:
                result = self.send_rpc_command(cmd=cmd, debug=debug)
        catch_,reason = self.catch(result)
        if catch_: # command caused crash
            return True,result,reason
        else: # no crash
            return False, result,reason

    def send_rpc_command(self, cmd, debug=False):
        """
        Lookup rpc xml command first 'display_xml_rpc()' and send corresponding xml.
        Requires valid command.
        Example:
        <rpc><get-system-uptime-information>
        </get-system-uptime-information></rpc>
        """
        xml_rpc = self.device.display_xml_rpc(cmd, format="text")
        if debug:
            print(f'xml_rpc command ==> {xml_rpc}')
        resp = None
        try:
            rpc = etree.XML(xml_rpc)
            resp = self.device.execute(rpc, normalize=False)
            if debug:
                etree.dump(resp)
            return resp
        except Exception as e:
            print("failed: " + str(e))
            if resp:
                etree.dump(resp)
            return str(e)
        return None

    def mutate_fuzzer(self, commands_list, num_cases=5, sleep_time=2):
        """
        Gather fuzzed data and send to target
        print results to console and save to json during execution
        return list of results
        """
        counter = 1
        results = []
        ts = datetime.datetime.fromtimestamp(time()).strftime('%Y%m%d-%H%M%S')
        filename = f'data_{ts}.json'
        for i in range(num_cases):
            for c in commands_list:
                fuzz = generate_fuzz_string(c)
                for name,fuzz_cmd in fuzz.items():
                    raw = False # when True - indicate we want do not want to build xml. Used with ascii control chars
                    test_results = {}
                    test_results_total = populate_dict_from_json(filename)
                    if not test_results_total:
                        test_results_total = {}
                    sleep(sleep_time)
                    if name == 'rand_fuzz_control_chars_ascii' or name == 'valid_commands_with_cc_ascii':
                        raw = True # ascii control characters
                    crash,result,reason = self.send_cmd_wrapper(cmd=fuzz_cmd, raw=raw)
                    if raw:
                        fuzz_cmd = codecs.encode(fuzz_cmd) # so we can display chars
                    test_results['crash'] = crash
                    test_results['result'] = result
                    test_results['name'] = name
                    test_results['reason'] = reason
                    # convert to string if needed for json
                    try:
                        fuzz_cmd = fuzz_cmd.decode("utf-8")
                    except (UnicodeDecodeError, AttributeError):
                        pass

                    test_results['cmd'] = fuzz_cmd
                    test_results_total[counter] = test_results
                    # write back to file
                    with open(filename, 'w') as outfile:
                        json.dump(test_results_total, outfile)
                    results.append(test_results)
                    print(f'======Case {counter}======')
                    if crash:
                        # detected a crash
                        print('----Possible crash detected----')
                        print(f'Reason --> {reason}')
                    print(f'    name    --> {name}')
                    print(f'    command --> {fuzz_cmd}')
                    print(f'    result  --> {result}\n')
                    counter += 1

        self.device.close()
        return results
