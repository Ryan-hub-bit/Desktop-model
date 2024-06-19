import json
import os




addrtodir = "/home/isec/Documents/differentopdata/Reorganized_Dataset/O0/addrtoid"
idtoaddr = "/home/isec/Documents/differentopdata/Reorganized_Dataset/O0/idtoaddr"


for root, dir, jsonfile in os.walk(addrtodir):
    binfile = jsonfile.split("_")[0]
    # Read JSON data from file
    with open(jsonfile, 'r') as file:
        json_data = file.read()

    # Parse JSON data
    data = json.loads(json_data)

    # Reverse key-value pairs
    reversed_data = {v: k for k, v in data.items()}
    reverse_file = os.path.join(idtoaddr, binfile +"_idtoaddr.json")
    with open(reverse_file,"w") as file:
        json.dump(reversed_data, file, indent=4)
