import argparse
import RDT
import time


def makePigLatin(word):
    m  = len(word)
    vowels = "a", "e", "i", "o", "u", "y"
    if m<3 or word=="the":
        return word
    else:
        for i in vowels:
            if word.find(i) < m and word.find(i) != -1:
                m = word.find(i)
        if m==0:
            return word+"way"
        else:
            return word[m:]+word[:m]+"ay"

def piglatinize(message):
    essagemay = ""
    message = message.strip(".")
    for word in message.split(' '):
        essagemay += " "+makePigLatin(word)
    return essagemay.strip()+"."


if __name__ == '__main__':

    parser =  argparse.ArgumentParser(description='Pig Latin conversion server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    timeout = 10 #close connection if no new data within 5 seconds
    time_of_last_data = time.time()

    rdt = RDT.RDT('server', None, args.port)
    while True:
        msg_S = rdt.rdt_3_0_receive()

        rep_msg_S = piglatinize(msg_S)
        print("\nMessage we want to convert: ", msg_S)
        print("----------------------------")
        print("Message converted: ", rep_msg_S)
        rdt.rdt_3_0_send(rep_msg_S)

    rdt.disconnect()
