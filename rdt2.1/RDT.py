import Network
import argparse
from time import sleep
import hashlib

class Packet:

    seq_num_S_length = 10 # length of the sequence number field
    length_S_length = 10 # length of the length field

    checksum_length = 32 # checksum length (HEX field)

    def __init__(self, seq_num, msg_S, ack):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.ack_status = ack # starts off with no ack status (is a boolean value)

    @classmethod
    def from_byte_S(self, byte_S):

        if Packet.corrupt(byte_S):
            return self(None, None, False) # returns essentially nothing if corrupt

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

    seq_num = 0 # starts with sequence number 0
    byte_buffer = '' # starts with empty buffer

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

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

            msg_length = int(resp[:Packet.length_S_length])
            self.byte_buffer = resp[msg_length:]


            if not Packet.corrupt(resp[:msg_length]):
                print("Packet is not corrupt.")
                resp_p = Packet.from_byte_S(resp[:msg_length])

                if resp_p.seq_num < self.seq_num:
                    acknowledgment_packet = Packet(resp_p.seq_num, "1", None)
                    self.network.udt_send(acknowledgment_packet.get_byte_S())

                if resp_p.msg_S is "1":
                    self.seq_num += 1
                    print("ACK Received.")
                    print("Sequence Number: ", self.seq_num%2)

                elif resp_p.msg_S is "0":
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
                resp = Packet(self.seq_num, "0", None)
                self.network.udt_send(resp.get_byte_S())

            else:
                p = Packet.from_byte_S(self.byte_buffer[0:length])

                if p.msg_S == '1' or p.msg_S == '0':
                    print("Staying in the same state.")
                    self.byte_buffer = self.byte_buffer[length:]
                    continue

                else:
                    print("Got the packet we were expecting. Will send ACK.")
                    resp = Packet(self.seq_num, "1", None)
                    self.network.udt_send(resp.get_byte_S())
                    self.seq_num += 1

                return_message = p.msg_S if (return_message is None) else return_message + p.msg_S

            self.byte_buffer = self.byte_buffer[length:]

        return return_message


    def seq_num_alternation(seq_num): # alternates the sequence numbers from 0 to 1

        if seq_num == 0:
            seq_num = 1

        elif seq_num == 1:
            seq_num = 0

        else:
            print("Sequence Number ERROR!")

        return seq_num

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()
