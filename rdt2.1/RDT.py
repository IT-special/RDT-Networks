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

    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def rdt_1_0_receive(self):
        return_message = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return return_message #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return return_message #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            return_message = p.msg_S if (return_message is None) else return_message + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration



# What is there to do for rdt 2.1 send?
# - it needs to be able to send packets to the receiver.
#     - first make the packet with sequence number 0
#     - then send that packet to the receiver
# - then the sender must wait for an ACK/NACK 0
#     - if it's a NACK, the sender needs to resend the packet
#     - if it's an ACK, it keeps going
# - Then we wait until we need to send the next packet again
#     - make the packet with sequence number 1
#     - send that packet to the receiver
# - then the sender must wait for an ACK/NACK 1
#     - if it's a NACK, the sender needs to resend the packet
#     - if it's an ACK, it keeps going
# - goes back to its original state with sequence number 0


    def rdt_2_1_send(self, msg_S):

        p = Packet(self.seq_num, msg_S, None)
        initial_seq = self.seq_num
        print("Sequence number: ", self.seq_num)

        while initial_seq == self.seq_num:
            self.network.udt_send(p.get_byte_S())
            resp = ''

            while resp == '':
                resp = self.network.udt_receive()

            msg_length = int(response[:Packet.length_S_length])
            self.byte_buffer = response[msg_length:]


            if not Packet.corrupt(response[:msg_length]):
                print("Packet is not corrupt.")
                response_p = Packet.from_byte_S(response[:msg_length])
                # if response_p.seq_num < self.seq_num:
                #     # It's trying to send me data again
                #     # debug_log("SENDER: Receiver behind sender")
                #     test = Packet(response_p.seq_num, "1")
                #     self.network.udt_send(test.get_byte_S())
                if response_p.msg_S is "1":
                    self.seq_num += 1
                    print("ACK Received.")
                    print("Sequence Number: ", self.seq_num%2)
                elif response_p.msg_S is "0":
                    self.byte_buffer = ''
                    print("NACK received")
                    print("Sequence Number: ", self.seq_num%2)
            else:
                self.byte_buffer = ''
                print("Packet is corrupt.")


    def rdt_2_1_receive(self):
        return_message = None
        message = self.network.udt_receive()
        self.byte_buffer += message
        initial_seq_num = self.seq_num


        while initial_seq_num == self.seq_num:

            if len(self.byte_buffer) < Packet.length_S_length:
                break

            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                break

            if Packet.corrupt(self.byte_buffer):
                # Send a NAK
                print("Received a corrupt packet. Sending a NACK.")
                resp = Packet(self.seq_num, "0")
                self.network.udt_send(resp.get_byte_S())

            else:
                p = Packet.from_byte_S(self.byte_buffer[0:length])

                if p.msg_S == '1' or p.msg_S == '0':
                    print("Staying in the same state.")
                    self.byte_buffer = self.byte_buffer[length:]
                    continue

                else:
                    print("Got the packet we were expecting. Will send ACK.")
                    resp = Packet(self.seq_num, "1")
                    self.network.udt_send(resp.get_byte_S())
                    self.seq_num += 1

                return_message = p.msg_S if (return_message is None) else return_message + p.msg_S

            self.byte_buffer = self.byte_buffer[length:]

        return return_message




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
                    print("LOSS: Considered a NACK")
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

                # else:
                #     print("\n|| ERROR in changing states ||\n")
                #     print("acknowledgement_packet.seq_num: ", p.seq_num)
                #     print("acknowledgement_packet.msg_S:", p.msg_S)

                # will return message if not corrupt
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
