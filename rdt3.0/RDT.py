import Network
import argparse
from time import sleep
import hashlib

# add ack field in object Packet
# find out where the length is breaking

class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S, ack):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.ack_status = ack # starts off with no ack status (is a boolean value)

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            #raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
            return self(None,None,False)
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S, True) # ack is right (not corrupt)

    # computes the various values that we need for each packet (sequence_num, checksum, length...)
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_hex = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_hex + self.msg_S


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_hex = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]

        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_hex = checksum.hexdigest()
        #and check if the same
        return checksum_hex != computed_checksum_hex


class RDT:

    seq_num = 0
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()


    def rdt_3_0_send(self, msg_S):
        # first part of the state manchine: send message with sequence number 0
        p = Packet(self.seq_num, msg_S, None)

        while True:

            self.network.udt_send(p.get_byte_S()) # send the packet to receiver
            resp = ""

            while resp == "":
                self.network.udt_send(p.get_byte_S())
                sleep(1)
                resp = self.network.udt_receive()


            message_length = int(resp[:Packet.length_S_length])
            self.byte_buffer = resp[message_length:]

            acknowledgement_packet = Packet.from_byte_S(resp[:message_length])
            if acknowledgement_packet.ack_status: # if not corrupt

                if acknowledgement_packet.seq_num == self.seq_num and acknowledgement_packet.msg_S == "0": #right ACK
                    print("Received ACK!")
                    print("Sequence number: ", acknowledgement_packet.seq_num, "\n")
                    self.seq_num = RDT.seq_num_alternation(self.seq_num)
                    break

                elif acknowledgement_packet.seq_num == self.seq_num and acknowledgement_packet.msg_S == "1": # right NACK
                    print("Received NACK!")
                    print("Sequence number: ", acknowledgement_packet.seq_num, "\n")
                    self.byte_buffer = ""

                else: # received either an ACK or NACK with the wrong sequence number, or something else...
                    print("LOSS")
                    print("TIMEOUT")
                    actual_packet = acknowledgement_packet #takes care of ack nack corruption
                    print("Sequence Number:", acknowledgement_packet.seq_num, "\n")
                    if actual_packet.ack_status:
                        acknowledgement_packet = Packet(actual_packet.seq_num, "0", None)#send ack
                        self.network.udt_send(acknowledgement_packet.get_byte_S())
                    elif not actual_packet.ack_status:
                        acknowledgement_packet = Packet(actual_packet.seq_num, "1", None)#send nack
                        self.network.udt_send(acknowledgement_packet.get_byte_S())

                    self.byte_buffer = ""

            else: # received a corrupt packet. Sender must resend another.
                print("Packet is corrupt... Considered it a NACK")
                print("Sequence number: ", acknowledgement_packet.seq_num)
                self.byte_buffer = ""

    def seq_num_alternation(seq_num): # alternates the sequence numbers from 0 to 1

        if seq_num == 0:
            seq_num = 1

        elif seq_num == 1:
            seq_num = 0

        else:
            print("Sequence Number ERROR!")

        return seq_num


    def rdt_3_0_receive(self):

        return_message = None # the value we will return at the end of this function. (should be a message)
        message =""
        while message =="":
            message = self.network.udt_receive() # receive the packet with the message
        self.byte_buffer += message # add the message from the packet to the buffer



        while True: # infinite loop until we break out

            if(len(self.byte_buffer) < Packet.length_S_length): # can't do slicing in next line so break
                break

            length = int(self.byte_buffer[:Packet.length_S_length])

            if len(self.byte_buffer) < length: # if the length is not right, break
                break

            print("Received a packet!")
            p = Packet.from_byte_S(self.byte_buffer[0:length])

            if not p.ack_status: # if packet is corrupt

                print("Packet is corrupt. Will send a NACK\n")
                print("Sequence number: ", p.seq_num)
                acknowledgement_packet = Packet(p.seq_num, "1", None)
                self.network.udt_send(acknowledgement_packet.get_byte_S())
                message =""
                while message =="":
                    message = self.network.udt_receive() # receive the packet with the message
                self.byte_buffer = ""
                self.byte_buffer += message

                if(len(self.byte_buffer) < Packet.length_S_length): # can't do slicing in next line so break
                    break

                length = int(self.byte_buffer[:Packet.length_S_length])

                if len(self.byte_buffer) < length: # if the length is not right, break
                    break
                p = Packet.from_byte_S(self.byte_buffer[0:length])


            else:
                print("Packet is not corrupt. Packet is correct.\n")

                # error when changing states
                if p.msg_S == "0" or p.msg_S == "1": # checking if we need to change states
                    print("Staying in the same state.")
                    self.byte_buffer = self.byte_buffer[length:]
                    continue

                else : # checking if sequence number is identical
                    print("Got the packet we were expecting. Will send ACK.")
                    acknowledgement_packet = Packet(p.seq_num, "0", None)
                    self.network.udt_send(acknowledgement_packet.get_byte_S())
                    #self.seq_num = RDT.seq_num_alternation(self.seq_num)
                    break

        try:
            p
        except NameError:
            p = None

        if p is None:
            return None
        return_message = p.msg_S if (return_message is None) else return_message + p.msg_S
        return return_message



if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_3_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_3_0_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_3_0_receive())
        rdt.rdt_3_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
