import angr
import capstone
from predit_experiment import check_edge
import pickle
import os
import json
import sys





binary_path = "/home/isec/Documents/angr_experiment_1/nu/libpcre2-8.so.0.10.4"
# binary_path = "/home/isec/Documents/experiment_6/binary_list/0a2b974d283bc5c732bb7bb5af4ec84c6b2a1bebb7ac6f83458bd4ddc0e9d9df"
#binary_path = "/home/isec/Documents/angr_experiment_1/libapr-1.so.0.7.4"
#sharelib_path = "/home/isec/Documents/angr_experiment_1/apache-libapr-funcs.txt"
project_path = "/home/isec/Documents/angr_experiment_1/project.pkl"
sharelib_path = "/home/isec/Documents/angr_experiment_1/apache-libpcre2-funcs.txt"
# read data from file
sharelib_func_list = open(sharelib_path, "r").read().splitlines()
sharelib_addr_list = []
directcall_addr_list = []
indirectcall_addr_list = []
project = None
callsitecnt = 0
calleecnt = 0
project = angr.Project(binary_path,load_options={'auto_load_libs': False}, use_sim_procedures=False)
# obj = project.loader.main_object
# print(obj.segments)
# print(obj.sections)




#Open the file in binary write mode and save the project object
if not os.path.exists(project_path):
    with open(project_path, 'wb') as project_file:
        pickle.dump(project, project_file)
print("starting")
# procedures = angr.SIM_PROCEDURES
# for key, value in procedures.items():
#     print(f"key:{key}, value:{value} +\n")
#Create a CFGFast object
cfg = project.analyses.CFGFast(cross_references=True)
# Get all functions
functions = cfg.kb.functions
function_addr_id = []
addrtoid_path = "/home/isec/Documents/angr_experiment_1/dir/addrtoid.json"
    # get id from addrtoid.json
    # Step 1: Open the file
with open(addrtoid_path) as addrtoid:
    # Step 2: Read the JSON data
        addrdict = json.load(addrtoid)
print(f"len(addrdict): {len(addrdict)}")
for addr, func in functions.items():
    if str(addr) in addrdict:
        function_addr_id.append(int(addrdict[str(addr)]))
idtoaddrdict = {}
idtoaddr_path = "/home/isec/Documents/angr_experiment_1/dir/idtoaddr.json"
notinsharelib = "/home/isec/Documents/angr_experiment_1/dir/notinsharelib.txt"
notinshareliblist = []
function_list = []
with open(idtoaddr_path) as idtoaddr:
    idtoaddrdict = json.load(idtoaddr)
addrn = len(sharelib_addr_list)
for addr, func in functions. items():
    if func.name in sharelib_func_list:
        sharelib_addr_list.append(addr)
        function_list.append(func.name)
for func in sharelib_func_list:
    if func not in function_list:
        notinshareliblist.append(func)
with open(notinsharelib, 'w') as file:
    # Iterate over the items in the list
    for item in notinshareliblist:
        # Write each item to a new line in the file
        file.write(str(item) + '\n')

if len(sharelib_addr_list) == addrn:
    print(f"len(sharelib_addr_list):{len(sharelib_addr_list)}")
    sys.exit()

for addr in sharelib_addr_list:
    func = cfg.kb.functions.get(addr)
    if func:
        basic_blocks= func.blocks
        for bb in basic_blocks:
                # Get instructions of the basic block
                instructions = bb.capstone.insns
                # print(instructions)
                for insn in instructions:
                    #print(insn.mnemonic)
                    if insn.mnemonic == "call":
                    #'reg': Indicates a register operand.
                    # 'imm': Indicates an immediate value operand.
                    #'mem': Indicates a memory operand.
                    #'fp': Indicates a floating-point operand.
                    #'cimm': Indicates a constant immediate operand.
                    #print(insn)
                    #print(f"insn: {insn}, type: {insn.operands[0].type} \n")
                        typeofins = insn.operands[0].type
                        if len(insn.operands) > 0 and  typeofins== 2:
                            #print(f"{str(insn)}, {typeofins}")
                            callee_address = int(str(insn).split()[-1].rstrip('h'),16)
                            directcall_addr_list.append(callee_address)
                            if callee_address not in sharelib_addr_list:
                                sharelib_addr_list.append(callee_address)
                        elif len(insn.operands) > 0 and typeofins == 3 or typeofins== 1:
                            callsitecnt += 1
                            callsite_addr = str(bb.addr)
                            callsite_id = 0
                            #print(f"callsite_addr: {callsite_addr}")
                            if callsite_addr in addrdict:
                                print(f"callsite_addr:{callsite_addr}")
                                callsite_id = int(addrdict[callsite_addr])
                                #print(f"callsite_id: {callsite_id}")
                            callee = []
                            callees = []
                            if callsite_id != 0:
                                print(f"callsite_id: {callsite_id}")
                                print(f"len(function_addr_id):{len(function_addr_id)}")
                                callees = check_edge(callsite_id,function_addr_id)
                            if len(callees) > 0:
                                for callee in callees:
                                    inaddr = idtoaddrdict[str(callee)]
                                    if int(inaddr) not in sharelib_addr_list:
                                        sharelib_addr_list.append(int(inaddr))
                                indirectcall_addr_list.extend(callees)
                            calleecnt += len(callees)
    #cfg

print(f"indirectaddr_list(calleecnt)： {len(list(set(indirectcall_addr_list)))}")
print(f"callsitecnt:{callsitecnt}")
print(f"calleecnt:{calleecnt}")

file_path = "/home/isec/Desktop/model/sharelib.txt"
# Open the file for writing
with open(file_path, 'w') as file:
    # Iterate over the items in the list
    for item in sharelib_addr_list:
        # Write each item to a new line in the file
        file.write(str(item) + '\n')

file_path = "/home/isec/Desktop/model/directcall_addr.txt"
# Open the file for writing
with open(file_path, 'w') as file:
    # Iterate over the items in the list
    for item in directcall_addr_list:
        # Write each item to a new line in the file
        file.write(str(item) + '\n')

file_path = "/home/isec/Desktop/model/Indirectcall_addr.txt"
# Open the file for writing
with open(file_path, 'w') as file:
    # Iterate over the items in the list
    for item in indirectcall_addr_list:
        # Write each item to a new line in the file
        file.write(str(item) + '\n')
target = sharelib_addr_list + directcall_addr_list + indirectcall_addr_list

# target = list(set(target))
# file_path = "/home/isec/Desktop/model/target.txt"
# # Open the file for writing
# with open(file_path, 'w') as file:
#     # Iterate over the items in the list
#     for item in target:
#         # Write each item to a new line in the file
#         file.write(str(item) + '\n')








