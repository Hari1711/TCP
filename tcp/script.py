import os
import json
input_file=input("enter input file name::")
output_file=input("enter output json file name::")
cmd='tshark -x -T json -r '+input_file+' >'+output_file
os.system(cmd)
f=open(output_file)
data=json.load(f)
class Frame:
    def __init__(self,hexdump,frame_no):
        self.hexdump=hexdump
        self.frame_no=frame_no
        self.proto=int(self.hexdump[46:48],16)
    def val_ip_protocol(self):
            if int(self.hexdump[46:48],16)==6:
                return 1
            else: 
                return 0   
    def val_dest_port(self):
        if int(self.hexdump[72:76],16)!=0:
            return 1
        else:
            return 0

    def val_tcp_head_len(self):
        if int(self.hexdump[92:94],16)/4>=20:
            return 1
        else:
            return 0
    def get_ack_type(self):
        ack=self.hexdump[94:96]
        return ack
    def get_source_port(self):
        port=int(self.hexdump[68:72],16)
        return str(port)
    def get_dest_port(self):
            port=int(self.hexdump[72:76],16)
            return str(port)
    def get_seq_number(self):
            seq_num=int(self.hexdump[76:84],16)
            return seq_num
    def get_ack_number(self):
            ack_num=int(self.hexdump[84:92],16)
            return ack_num
    def get_bytes(self):
            self.byte_len=data[self.frame_no-1]["_source"]["layers"]["tcp"]["tcp.len"]
            return int(self.byte_len)
    def get_source_ip(self):
        ip=[]
        ip.append(str(int(self.hexdump[52:54],16)))
        ip.append(str(int(self.hexdump[54:56],16)))
        ip.append(str(int(self.hexdump[56:58],16)))
        ip.append(str(int(self.hexdump[58:60],16)))
        ip_str=".".join(ip)
        return ip_str+":"+self.get_source_port()

    def get_dest_ip(self):
            ip=[]
            ip.append(str(int(self.hexdump[60:62],16)))
            ip.append(str(int(self.hexdump[62:64],16)))
            ip.append(str(int(self.hexdump[64:66],16)))
            ip.append(str(int(self.hexdump[66:68],16)))
            ip_str=".".join(ip)
            return ip_str+":"+self.get_dest_port()
def stream_id_check(str_id,dict):
    str_set=set(str_id.split("-"))
    keys=dict.keys()
    mtch_list=[]
    for key in keys:
        mtch_list.append(set(key.split("-")))
    if str_set in mtch_list:
        return True
    else:
        return False
def tcp_conversation(frame_list):
    conv_dict={}
    no_of_conversations=0
    no_of_proper_conversation_starts=0
    num_incr_flag=True
    cid=0
    for packet in frame_list:
        stream_id=packet.get_source_ip()+"-"+packet.get_dest_ip()+"-"+str(packet.proto)+"-"+str(cid)
        if not stream_id_check(stream_id,conv_dict):
            conv_dict[stream_id]=[]
            conv_dict[stream_id].append(packet)
        else:
            if packet.get_ack_type()=='02':
                cid=+1
                stream_id=packet.get_source_ip()+"-"+packet.get_dest_ip()+"-"+str(packet.proto)+"-"+str(cid)
                conv_dict[stream_id]=[]
                conv_dict[stream_id].append(packet)
            else:
                new_stream_id=packet.get_dest_ip()+"-"+packet.get_source_ip()+"-"+str(packet.proto)+"-"+str(cid)    
                if new_stream_id in conv_dict:
                    stream_id=new_stream_id
                conv_dict[stream_id].append(packet)
    no_of_conversations=len(conv_dict)
    for convo in conv_dict:
        if conv_dict[convo][0].get_ack_type() == '02':
            if conv_dict[convo][1].get_ack_type()=='12':
                if conv_dict[convo][2].get_ack_type()=='10':
                    no_of_proper_conversation_starts+=1
    for convo in conv_dict:
        for ind in range(len(conv_dict[convo])):
            print(conv_dict[convo][ind].frame_no,conv_dict[convo][ind].get_seq_number(),conv_dict[convo][ind].get_ack_number(),conv_dict[convo][ind].get_bytes())
            if ind==0:
                continue
            if conv_dict[convo][ind-1].get_ack_type()=='02':
                if conv_dict[convo][ind-1].get_seq_number() != conv_dict[convo][ind].get_ack_number()+1:
                        num_incr_flag=False
                        return [no_of_conversations,no_of_proper_conversation_starts,num_incr_flag]
            elif conv_dict[convo][ind-1].get_source_ip() == conv_dict[convo][ind].get_source_ip() :
                if (conv_dict[convo][ind-1].get_seq_number() != conv_dict[convo][ind].get_seq_number()) or  (conv_dict[convo][ind-1].get_ack_number() != conv_dict[convo][ind].get_ack_number()):
                    num_incr_flag=False
                    return [no_of_conversations,no_of_proper_conversation_starts,num_incr_flag]
            else:
                if conv_dict[convo][ind-1].get_bytes()!=0:
                    if (conv_dict[convo][ind-1].get_seq_number()+conv_dict[convo][ind-1].get_bytes()) != conv_dict[convo][ind].get_ack_number():
                        num_incr_flag=False
                        return [no_of_conversations,no_of_proper_conversation_starts,num_incr_flag]
                else:
                    if (conv_dict[convo][ind-1].get_seq_number()+1 != conv_dict[convo][ind].get_ack_number()) or (conv_dict[convo][ind-1].get_ack_number()!=conv_dict[convo][ind].get_seq_number()):
                        num_incr_flag=False
                        return [no_of_conversations,no_of_proper_conversation_starts,num_incr_flag]
        print("convo_end")
    return [no_of_conversations,no_of_proper_conversation_starts,num_incr_flag]


def main():
        frame_objs=[]
        res_dict={}
        for i in range(len(data)):
            frame_objs.append(Frame(data[i]["_source"]["layers"]["frame_raw"][0],i+1))
        valid_tcp_packets=[]
        for frame in frame_objs:
            try:
                if frame.val_ip_protocol() and frame.val_dest_port() and frame.val_tcp_head_len():
                    valid_tcp_packets.append(frame)
                res_dict[frame.frame_no]=[frame.val_ip_protocol(),frame.val_dest_port(),frame.val_tcp_head_len()]
            except:
                print("error occured at ",frame.frame_no)
        conv_list=tcp_conversation(valid_tcp_packets)
        res_dict['no of conversations']=conv_list[0]
        res_dict['no of proper conversation starts']=conv_list[1]
        res_dict['is syn,ack number correct']=conv_list[2]
        print(res_dict)    


main()
