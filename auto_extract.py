from idautils import *
from idaapi import *
import idc

# idat64.exe -A -S"auto_extract.py" malware.exe


idc.auto_wait()

argv = idc.ARGV[1]
f_func=open(f"{argv}.func", 'a')
f_api= open(f"{argv}.api", 'a')
f_string= open(f"{argv}.string", 'a')

############Script#####################

from ida_segment import *

text_seg = get_segm_by_name(".text")

text_st_addr = text_seg.start_ea
text_end_addr= get_segm_end(text_st_addr)



st_addr= text_st_addr
end_addr = text_end_addr

curr_addr =st_addr
local_func= {}
APIs_list= {}
strings = {}

import json
json_data= json.loads(open("API_file.txt", "rb").read())
api_name= json_data['exports']



while curr_addr < end_addr:
    inss= idc.generate_disasm_line(curr_addr, 1)
    curr_func_name= idc.get_func_name(curr_addr)

    # filter
    if "sub_" not in curr_func_name and '_main_' not in curr_func_name:
        curr_addr= idc.next_head(curr_addr)
        continue

    # more filter
    if "?" in curr_func_name or "scrt" in curr_func_name or "null" in curr_func_name:
        curr_addr= idc.next_head(curr_addr)
        continue        

    if curr_func_name not in local_func:
        local_func[curr_func_name]= []
    
    if curr_func_name not in APIs_list:
        APIs_list[curr_func_name]= []
    
    if curr_func_name not in strings:
        strings[curr_func_name]= []

    if "call" in inss:
        if "sub_" in inss and "null" not in inss:
            local_func[curr_func_name].append(inss[inss.index("sub_"):])

        else:
            if "cs" in inss:
                api= inss.replace("call    cs:","")
            
            else:
                api= inss.replace("call    ","")

            if api in api_name:
                if api not in APIs_list[curr_func_name]:
                    APIs_list[curr_func_name].append(api)
    
    if "lea" in inss:
        str_addr = idc.get_operand_value(curr_addr,1)
        str_size = get_item_size(str_addr)
        str_byte = get_bytes(str_addr, str_size)
        if len(str_byte) >=4 and b'\xff\xff\xff' not in str_byte and b'\x00\x00' not in str_byte:
            strings[curr_func_name].append(str_byte)            

    curr_addr= idc.next_head(curr_addr)

#print(local_func)
#print(APIs_list)
#print(strings)
    


#####################################################################

f_func.write(str(local_func))
f_api.write(str(APIs_list))
f_string.write(str(strings))

f_func.close()
f_api.close()
f_string.close()

idc.exit()
