#!/usr/bin/python3
# coding=utf-8
from encode import *
from binascii import unhexlify, hexlify
import json

DESCRIPTION = 0x61C524
POKEBASE_STATS = 0x3203CC 
NUMBER_OF_POKES = 412
POKEBASE_STATS_LENGTH = 0x1C
POKENAMES = 0x3185C8
POKENAMES_LENGTH = 0xB
LEARNED_MOVES = 0x32937C
LEARNED_MOVES_LENGTH = 0x2
ATTACK_NAMES = 0x31977C
NUMBER_OF_ATTACKS = 0x163
ATTACK_NAME_LENGTH = 0xD
ATTACK_DATA=0x31C898
ATTACK_DATA_LENGTH = 12
FILE = "Pokemon Emerald.gba"


move_list = []
poke_list = []
learnset = []
attack_data_list = []
stat_list = []


def get_bytes(fname, lrange, rrange):
    lrange = lrange  
    with open(fname, "r+b") as rom:
        rom.seek(lrange)
        get_bytes = rom.read( rrange - lrange)

    return get_bytes

def print_bytes(fname, lrange, rrange):
    with open(fname, "r+b") as rom:
        rom.seek(lrange)
        get_bytes = rom.read( rrange - lrange)

    print(bytes_to_ascii(get_bytes))


def get_move_names():
    p_bytes = get_bytes(FILE, ATTACK_NAMES, ATTACK_NAMES + (ATTACK_NAME_LENGTH * NUMBER_OF_ATTACKS))

    return (bytes_to_ascii(p_bytes))

def get_pokes():
    p_bytes = get_bytes(FILE, POKENAMES, POKENAMES + (NUMBER_OF_POKES * POKENAMES_LENGTH))
    raw_list = bytes_to_ascii(p_bytes)
    ret_list = []

    for i in range(NUMBER_OF_POKES*(POKENAMES_LENGTH-1)):
        if(i % 10 == 0):
            ret_list.append(raw_list[i:i+10])

    return ret_list

def get_attack_data():
    a_bytes = get_bytes(FILE, ATTACK_DATA, ATTACK_DATA + (ATTACK_DATA_LENGTH * NUMBER_OF_ATTACKS))
    
    ind = {
        "Effect":0,
        "BP":1,
        "Type":2,
        "Accuracy":3,
        "PP":4,
        "EA":5,
        "AW":6,
        "Priority":7,
        "Flags":8,
        "Padding":9
    }

    byt = {
        "Effect":0,
        "BP":0,
        "Type":0,
        "Accuracy":0,
        "PP":0,
        "EA":0,
        "AW":0,
        "Priority":0,
        "Flags":0,
        "Padding":0
    }
    adl_tmp = []

    for i in range(0, (ATTACK_DATA_LENGTH * NUMBER_OF_ATTACKS), ATTACK_DATA_LENGTH):
        
        byt["BP"] = a_bytes[i + ind["BP"]]
        byt["Effect"] = a_bytes[i + ind["Effect"]]
        byt["Type"] = a_bytes[i + ind["Type"]]
        byt["PP"] = a_bytes[i + ind["PP"]]
        byt["EA"] = a_bytes[i + ind["EA"]]
        byt["AW"] = a_bytes[i + ind["AW"]]
        byt["Priority"] = a_bytes[i + ind["Priority"]]
        byt["Flags"] = a_bytes[i + ind["Flags"]]

        adl_tmp.append(byt.copy())
    return adl_tmp


def get_learnset():
    mvmset_pointer_bytes_obj = get_bytes(FILE, LEARNED_MOVES, LEARNED_MOVES + (NUMBER_OF_POKES * 4))
    mvmset_pointer_list = []
    ls_tmp = []

    for i in range(0, NUMBER_OF_POKES*4, 4):
        mvmset_pointer_list.append(make_32bit_pointer(mvmset_pointer_bytes_obj, i))

    for i in range(NUMBER_OF_POKES):
        first_point = int.from_bytes(mvmset_pointer_list[i], "little")
        mvset_bytes = get_bytes(FILE,first_point, first_point + (1024))
        
        tuple_int = 0x0
        move_counter = 0
        extra_bit_count = 0
        loff = 0
        roff = 2

        ls_tmp_list = []

        while move_counter < 512 and tuple_int != 0xFFFF:

            move_tuple = mvset_bytes[loff:roff]
            tuple_int = int.from_bytes(move_tuple, "little")


            out = [int(x) for x in '{:08b}'.format(tuple_int)]
            
            pad_arr = [ 0 for x in range(0,16 - len(out))]
            out = pad_arr + out
            lvl = (bitlist_to_int(out[0:7]))
            move_ind = (bitlist_to_int(out[7:]))

            #DEBUG
            #print("MOVE: ", move_list[move_ind])
            #print("LVL:  ", lvl)

            loff += 2
            roff = loff + 2
            move_counter += 1

            ls_tmp_list.append([move_ind, lvl])

            move_tuple = mvset_bytes[loff:roff]
            tuple_int = int.from_bytes(move_tuple, "little")


        ls_tmp.append(ls_tmp_list)

    return ls_tmp



def make_32bit_pointer(bt_arr, ind):
    return bt_arr[ind:ind+3:]

def populate_move_list():
    ll = get_move_names()
    return chunks(ll, 12)
    

def chunks(l, n):
    n = max(1, n)
    return [l[i:i+n] for i in range(0, len(l), n)]

def bitlist_to_int(bl):
    out = 0
    for bit in bl:
        out = (out << 1) | bit
    return out

def hexstr_to_hex(temp_string):
    return int(temp_string, 16)

def swap32(x):
    return (((x << 24) & 0xFF000000) |
            ((x <<  8) & 0x00FF0000) |
            ((x >>  8) & 0x0000FF00) |
            ((x >> 24) & 0x000000FF))



def swap16(x):
    return (((x >>  8) & 0x0000FF00) |
            ((x >> 24) & 0x000000FF))

def bytes_to_ascii(file_b):
    out_str = ""
    new_elem = ""
    for elem in file_b:
        if type(decoding_dict[elem]) == str:
               new_elem += decoding_dict[elem]
    return new_elem

def get_stats():
    s_bytes = get_bytes(FILE, POKEBASE_STATS, POKEBASE_STATS + (POKEBASE_STATS_LENGTH * NUMBER_OF_POKES))
    byt = {
        "HP":0,
        "ATK":0,
        "DEF":0,
        "SPD":0,
        "SPATK":0,
        "SPDEF":0,
        "TYPE1":0,
        "TYPE2":0
    }

    ll = []

    for i in range(0, NUMBER_OF_POKES*POKEBASE_STATS_LENGTH, 28):
        if i % 28 == 0:
            byt["HP"] = s_bytes[i]
            byt["ATK"] = s_bytes[i + 1]
            byt["DEF"] = s_bytes[i + 2]
            byt["SPD"] = s_bytes[i + 3]
            byt["SPATK"] = s_bytes[i + 4]
            byt["SPDEF"] = s_bytes[i + 5]
            byt["TYPE1"] = s_bytes[i + 6]
            byt["TYPE2"] = s_bytes[i + 7]
            ll.append(byt.copy())
    return ll

def make_json_moves_file(move_list_arg):
    serial_dict = {}

    for i in range(NUMBER_OF_ATTACKS):
        serial_dict[i] = move_list_arg[i]

    with open("moves.json", "w") as write_file:
        json.dump(serial_dict, write_file)

def make_json_poke_list(poke_list_arg):
    serial_dict = {}

    for i in range(NUMBER_OF_POKES):
        serial_dict[i] = poke_list_arg[i]

    with open("pokemon.json", "w") as write_file:
        json.dump(serial_dict, write_file)


def make_json_stats_list(stat_list_arg):
    serial_dict = {}

    for i in range(NUMBER_OF_POKES):
        serial_dict[i] = stat_list_arg[i]

    with open("stats.json", "w") as write_file:
        json.dump(serial_dict, write_file)

def make_json_learnet_list(learnset_list_arg):
    serial_dict = {}

    for i in range(NUMBER_OF_POKES):
        serial_dict[i] = []
        for elem in learnset_list_arg[i]:
            t_arr = [elem[0], elem[1]]
            serial_dict[i].append(t_arr)

    with open("learnset.json", "w") as write_file:
        json.dump(serial_dict, write_file)

def make_json_attack_data_list(attack_data_list_arg):
    serial_dict = {}
    byt = {
        "Effect":0,
        "BP":0,
        "Type":0,
        "Accuracy":0,
        "PP":0,
        "EA":0,
        "AW":0,
        "Priority":0,
        "Flags":0,
        "Padding":0
    }

    for i in range(NUMBER_OF_ATTACKS):
        serial_dict[i] = byt.copy()
        elem = attack_data_list_arg[i]

        serial_dict[i]["Effect"] = elem["Effect"]
        serial_dict[i]["BP"] = elem["BP"]
        serial_dict[i]["Type"] = elem["Type"]
        serial_dict[i]["Accuracy"] = elem["Accuracy"]


    with open("attack_data.json", "w") as write_file:
        json.dump(serial_dict, write_file)
def main():
    global move_list
    global poke_list
    global attack_data_list

    move_list = [*populate_move_list()]
    poke_list = get_pokes()
    gls_temp = get_learnset()
    attack_data_list = get_attack_data()
    stat_list = get_stats()

    make_json_moves_file(move_list)
    make_json_poke_list(poke_list)
    make_json_stats_list(stat_list)
    make_json_learnet_list(gls_temp)
    make_json_attack_data_list(attack_data_list)

if __name__ == "__main__":
    main()
