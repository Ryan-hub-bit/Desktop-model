import angr
import capstone
from predit_experiment import check_edge
import pickle
import os
import json
import sys




# binary_path = "/home/isec/Documents/experiment_6/binary_list/0a2b974d283bc5c732bb7bb5af4ec84c6b2a1bebb7ac6f83458bd4ddc0e9d9df"
#binary_path = "/home/isec/Documents/angr_experiment_1/libapr-1.so.0.7.4"
#sharelib_path = "/home/isec/Documents/angr_experiment_1/apache-libapr-funcs.txt"
# project_path = "/home/isec/Documents/angr_experiment_1/project.pkl"
# sharelib_path = "/home/isec/Documents/angr_experiment_1/apache-libpcre2-funcs.txt"
# read data from file
# sharelib_addr_list = []
# directcall_addr_list = []
# indirectcall_addr_list = []
# project = None
# callsitecnt = 0
# calleecnt = 0
#project = angr.Project(binary_path,load_options={'auto_load_libs': False}, use_sim_procedures=False)
# obj = project.loader.main_object
# print(obj.segments)
# print(obj.sections)


def generate_and_modify_cfg(binary_path):
    function_addr_id = []
    addrtoid_folder = "/home/isec/Documents/differentopdata/Reorganized_Dataset/O0/addrtoid"
    idtoaddr_folder = "/home/isec/Documents/differentopdata/Reorganized_Dataset/O0/idtoaddr"
    # get id from addrtoid.json
    # Step 1: Open the file
    addrtoid_path = os.path.join(addrtoid_folder, binary_path +"_addrtoid.json")
    with open(addrtoid_path) as addrtoid:
    # Step 2: Read the JSON data
        addrdict = json.load(addrtoid)
    print(f"len(addrdict): {len(addrdict)}")
    for addr, func in functions.items():
        if str(addr) in addrdict:
            function_addr_id.append(int(addrdict[str(addr)]))
    idtoaddrdict = {}
    idtoaddr_path = os.path.join(idtoaddr_folder, binary_path +"_idtoaddr.json")
    function_list = []
    with open(idtoaddr_path) as idtoaddr:
        idtoaddrdict = json.load(idtoaddr)
    # Load the binary into the project
    project = angr.Project(binary_path)
    # Generate a fast CFG with cross-references enabled
    cfg = project.analyses.CFGFast(cross_references=True)
    # Example: To visualize the number of nodes and edges
    print(f"Before Number of nodes in CFG: {len(cfg.graph.nodes)}")
    print(f"Before Number of edges in CFG: {len(cfg.graph.edges)}")
    functions = cfg.kb.functions
    for addr, func in functions.items():
        callsite_node = cfg.get_any_node(addr)
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
                            callee_address = int(str(insn).split()[-1],16)
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
                                    callee_addr = idtoaddrdict[str(callee)]
                                    callee_node = cfg.get_any_node(callee_addr)
                                    if callsite_node and callee_node:
                                        print(f"Node 1 at address {hex(callsite_addr)}: {callsite_node}")
                                        print(f"Node 2 at address {hex(callee_addr)}: {callee_addr}")
                                    else:
                                        if not callsite_node:
                                            print(f"No callsite_node found at address {hex(callsite_addr)}")
                                        if not callee_node:
                                            print(f"No callee_node found at address {hex(callee_addr)}")
                                    if not cfg.graph.has_edge(callsite_node, callee_node):
                                        cfg.graph.add_edge(callsite_node, callee_node)
                                        print(f"build node between {hex(callsite_addr)} and {hex(callee_addr)}")
    return cfg


o0path = "/home/isec/Documents/differentopdata/Reorganized_Dataset/O0/valid_binary_list"
o1path = "/home/isec/Documents/differentopdata/Reorganized_Dataset/O1/valid_binary_list"
o0cfggraph = "/home/isec/Documents/differentopdata/Reorganized_Dataset/O0/cfggraph"
o1cfggraph = "/home/isec/Documents/differentopdata/Reorganized_Dataset/O1/cfggraph"
path = "/home/isec/Documents/differentopdata/Reorganized_Dataset/Opdict/o0too1dict.json"
o0too1 = {}
with open(path, "r") as f:
    o0to01 = json.load(f)

n = 0
for key, value in o0too1.items():
    if n > 0:
        continue
    o0 = value.split()[0]
    o1 = value.split()[1]
    o0file = os.path.join(o0path, o0)
    o1file = os.path.join(o1path, o1)
    print(o0file)
    print(o1file)
    n += 1
    o0cfg = generate_and_modify_cfg(o0file)
    o1cfg = generate_and_modify_cfg(o1file)
    print(f"after Number of nodes in CFG: {len(o0cfg.graph.nodes)}")
    print(f"after Number of edges in CFG: {len(o0cfg.graph.edges)}")
    print(f"after Number of nodes in CFG: {len(o1cfg.graph.nodes)}")
    print(f"after Number of edges in CFG: {len(o1cfg.graph.edges)}")
    # Save the CFG to a file using pickle
    o0cfgpath = os.path.join(o0cfggraph, o0 +"_cfg.pkl")
    with open(o0cfgpath, 'wb') as f:
        pickle.dump(o0cfg.graph, f)
    o1cfgpath = os.path.join(o1cfggraph, o1 +"_cfg.pkl")
    with open(o1cfgpath, 'wb') as f:
        pickle.dump(o1cfg.graph, f)







#cfg = generate_and_modify_cfg(binary_path1)

# Example: To visualize the number of nodes and edges
#print(f"After Number of nodes in CFG: {len(cfg.graph.nodes)}")
#print(f"After Number of edges in CFG: {len(cfg.graph.edges)}")


