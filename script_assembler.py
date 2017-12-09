# much of this is taken from lumen's unpack_ai, but none of it is directly copied from it
# currently only works for battle AI scripts. will need to rework some of it to work with dungeon scripts.

import argparse
import struct

# same opcode names as lumen even if I don't understand them exactly... I'm using his unpacker after all
instruction_opcodes = {
    "PUSHI"     : 0x00,
    "PUSHF"     : 0x01,
    "PUSHIX"    : 0x02,
    "PUSHIF"    : 0x03,
    "PUSHREG"   : 0x04,
    "POPIX"     : 0x05,
    "POPFX"     : 0x06,
    "PROC"      : 0x07,
    "COMM"      : 0x08,
    "END"       : 0x09,
    "JUMP"      : 0x0A,
    "CALL"      : 0x0B,
    "RUN"       : 0x0C,
    "GOTO"      : 0x0D,
    "ADD"       : 0x0E,
    "SUB"       : 0x0F,
    "MUL"       : 0x10,
    "DIV"       : 0x11,
    "MINUS"     : 0x12,
    "NOT"       : 0x13, 
    "OR"        : 0x14,
    "AND"       : 0x15,
    "EQ"        : 0x16,
    "NEQ"       : 0x17,
    "LT"        : 0x18,
    "GT"        : 0x19,
    "LTE"       : 0x1A,
    "GTE"       : 0x1B,
    "IF"        : 0x1C,
    "PUSHIS"    : 0x1D,
    "PUSHLIX"   : 0x1E, 
    "PUSHLFX"   : 0x1F,
    "POPLIX"    : 0x20,
    "POPLFX"    : 0x21,
    "PUSHSTR"   : 0x22
}

# some COMM functions return values. if they aren't followed by PUSHREG, they will fail. we need to handle this. this list is not exhaustive.
has_return = [0x0, 0x4, 0x5, 0x6, 0x13, 0x16, 0x1E, 0x20, 0x21, 0x3C, 0x3F, 0x40, 0x5E, 0x5F, 0x80, 0x83, 0x85, 0x88, 0xB4, 0xB6, 0xB9, 0xBB, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC6, 0xC7, 0xC8, 0xCA, 0xCB, 0xCD, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD8, 0xD9, 0xE1, 0xE4, 0xEA]

# which codes require operands and which don't.

has_operand = ["PUSHI", "PUSHF", "PUSHIX", "PUSHIF", "PROC", "COMM", "JUMP", "CALL", "GOTO", "IF", "PUSHIS", "PUSHLIX", "PUSHLFX", "POPLIX", "POPLFX", "PUSHSTR", "label:"] # label: is a pseudo-opcode
no_operand = ["PUSHREG", "POPIX", "POPFX", "END", "RUN", "ADD", "SUB", "MUL", "DIV", "MINUS", "NOT", "OR", "AND", "EQ", "NEQ", "LT", "GT", "LTE", "GTE"]

def getArgs():
    parser = argparse.ArgumentParser(description="Read a script's bytecode and create a .bf file")
    parser.add_argument("input", help="modified unpack_ai.py script file")
    parser.add_argument("output", help="bf file to create")
    return parser.parse_args()
    
def assembleBfFile(input):
        
    # reads the file and splits it into lines    
    def splitFile(): 
        with open(input, "r", encoding="utf-8") as scrtxt:
            data = scrtxt.read()
            temp_list = data.splitlines() # split the file into a list of lines for easier parsing
            line_list = []
            pure_list = [] # without the label headers
            for line in temp_list:
                # skip empty lines
                if line == "": 
                    pass
                    
                # slice comments for easier parsing and add to the array
                elif "#" in line: 
                    line = line[0:line.index("#")].strip()
                    if line == "": # get rid of the line if it's empty
                        pass
                    else:
                        line_list.append(line)
                    
                # add to array otherwise
                else:
                    line_list.append(line.strip())
                    
            # now create a list without the label headers in it
            for line in line_list:
                if line.startswith("label:"):
                    pass
                else:
                    if "(" in line:
                        line = line[0:line.index("(")].strip() #kind of a janky place to put it, but the "loc" needs to be removed from these too
                    pure_list.append(line)
            for line in pure_list:
                print(line)
        return line_list, pure_list

    # count how many labels we need to make
    def countLabels(line_list):
        label_count = 0
        for line in line_list:
            if line.startswith("label:"):
                label_count += 1
        print(label_count) # remove this print
        return label_count
        
    # checks that all opcodes are valid and create a list of jumps. TODO: fix line indicators being a bit wrong
    def structureCheck(line_list, pure_list):
        error_check = 0 # if any of the checks fail, we set it to 1
        opcode_found = 0 # if we go through the valid lists without finding our opcode, throw an error
        label_list = [] # a list of the labels we find, which we are going to use for both error checking and in another function
        jump_labels = [] # a list of labels that are jumped to in code.
        label_names = [] # a list of all labels, without the offsets. we'll need this later for error checking.
        true_position = 0 # position on the list without the labels
        for pos, line in enumerate(line_list):
            instruction = line.split(" ", 1) # .split returns a list delimited by the character in the quotation marks, so this returns the instruction
            # handles various things for the operands
            if instruction[0] in has_operand:     
                # missing operand
                if len(instruction) < 2:
                    print("ERROR: Instruction " + instruction[0] + " requires an operand. (Line " + str(pos - 1) + ")")
                    error_check = 1
                    
                # too many operands
                elif len(instruction) > 2:
                    print("ERROR: Instruction " + instruction[0] + " has too many operands (got " + str(len(instruction) - 1) + ", expected 1. (Line " + str(pos - 1) + ")")
                    error_check = 1
                
                # if the instruction is correctly formed, proceed to further checks and processing
                else:
                
                    # ensure a COMM return is correctly pushed
                    # I don't know if you can theoretically do other things before pushing the return, but even if you can, that seems like poor style so I'll keep this an error
                    if instruction[0] == "COMM":
                        if int(instruction[1], 16) in has_return:
                            if line_list[pos + 1] != "PUSHREG":
                                print("ERROR: Instruction " + instruction[0] + " " + instruction[1] + " has unpushed return (add PUSHREG to next line). (Line " + str(pos - 1) + ")")
                                error_check = 1
                
                    # this is not an error checker. instead, it checks for all the label names and populates the label list with it and the jump locations.
                    elif instruction[0] == "label:":
                        if " " in instruction[1]:
                            label_name = instruction[1][0:instruction[1].index(" ")] # ugly line of code. it slices off the (loc xx) created by the unpack_ai.py file.
                        else:
                            label_name = instruction[1]
                        label_tuple = (label_name, true_position)
                        label_names.append(label_name) # for the error handler later
                        label_list.append(label_tuple)
                        true_position -= 1 # this true_position thing feels like a hack...
                    
                    # also not an error handler. checks GOTO and IF statements for their jump outs. we'll be using this later.    
                    elif instruction[0] == "GOTO" or instruction[0] == "IF":
                        if " " in instruction[1]: # no spaces
                            jump_labels.append(instruction[1][0:instruction[1].index(" ")] )
                        else:
                            jump_labels.append(instruction[1])
                    opcode_found = 1

            # same as the other one, but this time, for instructions that take no operand.
            if instruction[0] in no_operand:
                opcode_found = 1
                if len(line.split()) > 1:
                    print("ERROR: Instruction " + instruction[0] + " has operand but does not take an operand. (Line " + str(pos) + ")")
                    error_check = 1
            if not opcode_found:
                print("ERROR: Instruction \"" + instruction[0] + "\" is not a valid opcode. (Line " + str(pos - 1) + ")")
                quit()
            opcode_found = 0
            true_position += 1
        
        # making sure our label list is sane
        for pos, entry in enumerate(label_list):
        
            # label length
            if len(entry[0]) > 0x18:
                print ("ERROR: Name of label \"" + str(entry[0]) + "\" is too long (length: " + str(len(entry[0])) + ", maximum: 24)")
                error_check = 1
                
            # PROC jump location. this is done for enemy AI scripts and won't work for dungeon scripts (edit that later?)
            if pos == 0:
                if entry[1] != 0:
                    print ("ERROR: First label's jump location is not 0.")
                    error_check = 1
                    
            # bounds checking        
            if entry[1] > len(pure_list) - 1:
                print ("ERROR: Label \"" + entry[0] + "\" attempts to jump out of range (Jumps to " + str(entry[1]) + ", maximum: " + str(len(pure_list) - 1) + ")")
                error_check = 1
            elif entry[1] < 0:
                print ("ERROR: Label \"" + entry[0] + "\" attempts to jump to a negative offset (Jumps to " + str(entry[1]) + "). This should never happen.") # and if it does, it's my fault
                error_check = 1
                
            # is the destination used? this is non-fatal
            if entry[0] not in jump_labels and entry[1] != 0:
                print ("WARNING: Label \"" + entry[0] + "\" defined but no instructions jump to it.")
                
        # check if all destinations exist. TODO: find a way to put a line number on this        
        for entry in jump_labels:
            if entry not in label_names:
                print(jump_labels)
                print(label_names)
                print ("ERROR: An instruction attempted to jump to non-existent label \"" + entry + "\".")
                error_check = 1
        
        # fail if any errors    
        if error_check:
            quit()
        return label_list
        
    # this creates our label byte object    
    def createLabels(label_list):
        label_bytes = bytearray()
        for entry in label_list:
            text = bytearray()
            text.extend(map(ord, entry[0].ljust(0x18, "\x00"))) # adds the label to the object, and pads the length.
            dest = struct.pack("<q", entry[1]) #q is for a long long. I doubt it's actually a long long, but this provides the padding we need
            obj = text + dest # combine everything down here
            label_bytes = label_bytes + obj
        return label_bytes
    
    # this creates our instruction byte object.
    def createInstructions(pure_list, label_list):
        instruction_bytes = b''
        for line in pure_list:
            instruction = line.split(" ", 1)
            # print (instruction)
            if len(instruction) == 1:
                opcode = struct.pack("<l", instruction_opcodes.get(instruction[0])) # <l suitably handles this
            elif len(instruction) == 2:
                opcode = struct.pack("<h", instruction_opcodes.get(instruction[0]))
                if instruction[0] != "GOTO" and instruction[0] != "IF": # GOTO and IF need special handling
                    value = struct.pack("<h", int(instruction[1], 16))
                    opcode = opcode + value
                else:
                    for pos, labels in enumerate(label_list):
                        if instruction[1] == labels[0]:
                            value = struct.pack("<h", pos - 1) # header does not count, so we need to do pos - 1
                            opcode = opcode + value
                            break # break to save cycles
            else:
                print ("ERROR: Somehow the instruction length was wrong. This should never happen.")
                quit()
            instruction_bytes = instruction_bytes + opcode
        padding = bytearray()
        padding.extend(map(ord, "".ljust(0xF0, "\x00"))) # there's always 0xF0 of padding, so I'll add it here. 
        instruction_bytes = instruction_bytes + padding
        return instruction_bytes

            
    # the headers that control various bits of info about the file        
    def createHeaders(label_bytes, instruction_bytes):
        start = b'\x00\x00\x00\x00'
        file_length = struct.pack("<l", len(label_bytes) + len(instruction_bytes) - 0x80) # the header space is always 0x70, but the 0xF0 of padding doesn't count, hence the - 0x80
        file_format = b'FLW0\x00\x00\x00\x00' # constant in all scripts
        header_and_entry_label = b'\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00\x70\x00\x00\x00' # replace for dungeon scripts. works for enemies for now
        label_id_and_length = b'\x01\x00\x00\x00\x20\x00\x00\x00' # always this value
        label_entries = struct.pack("<l", (len(label_bytes) - 0x20)>>5) # doing an ASR to avoid the float type
        label_offset = b'\x90\x00\x00\x00' # can change with the dungeon scripts fix. otherwise it's always this
        instruction_id_and_length = b'\x02\x00\x00\x00\x04\x00\x00\x00'
        instruction_entries = struct.pack("<l", (len(instruction_bytes) - 0xF0)>>2) # again, another ASR. 0xF0 for the padding
        instruction_offset = struct.pack("<l", len(label_bytes) + 0x70) # 0x70 because of 0xF0 - 0x90.
        unknown_section = b'\x03\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' + file_length + b'\x04\x00\x00\x00\x01\x00\x00\x00\xF0\x00\x00\x00' + file_length # constant in both enemy and dungeon scripts
        headers = start + file_length + file_format + header_and_entry_label + label_id_and_length + label_entries + label_offset + instruction_id_and_length + instruction_entries + instruction_offset + unknown_section # ugly
        print (headers)
        return headers

        
        
        
    # fire the functions
    
    line_list, pure_list = splitFile()    
    countLabels(line_list)
    label_list = structureCheck(line_list, pure_list)
    label_bytes = createLabels(label_list)
    instruction_bytes = createInstructions(pure_list, label_list)
    headers = createHeaders(label_bytes, instruction_bytes)
    output_file = headers + label_bytes + instruction_bytes
    with open(args.output, "wb") as outp:
        outp.write(output_file)    
    
    return
    
    
args = getArgs()
file_output = assembleBfFile(args.input)
