import socket
import random
import numpy as np
import argparse


def getArgs():
    parser = argparse.ArgumentParser(description="IP and port for server")

    parser.add_argument("ip")
    parser.add_argument("port")
    return parser.parse_args()


def buildPacket(sync=0, ack=0, fin=0, seqNum=0, ackNum=0, payload=0, payloadSize=0, divisor="000000000"):
    flags = f"000{ack}00{sync}{fin}"
    stringPacket = flags + f"{seqNum:032b}" + f"{ackNum:032b}" + \
        f"{payloadSize:016b}" + f"{payload:01024b}"
    CRC = ""
    if int(divisor) > 0:
        CRC = getCRC(stringPacket, divisor)

    else:
        CRC = "00000000"
    stringPacket += CRC

    listPacket = np.array([val for val in stringPacket]).reshape(
        int(np.ceil(len(stringPacket)/8)), 8)
    intPacket = [int("".join(listByte), base=2) for listByte in listPacket]

    return intPacket


def getCRC(binCode, divisor):
    payload = list(binCode) + ([0]*(len(divisor)-1))
    payload = [int(n) for n in payload]
    divisor = [int(n) for n in list(divisor)]
    remainder = []
    pointer = 0

    while pointer <= len(payload) - len(divisor):
        # Extract slice to subtract
        val = payload[pointer: pointer + len(divisor)]

        # Subtract paired values
        operations = zip(val, divisor)
        remainder = [abs(op[0] - op[1]) for op in operations]

        # Modify payload values, set pointer to index
        for i in range(len(divisor)):
            payload[pointer + i] = remainder[i]

        # Move pointer to next non-zero value
        if 1 not in payload:
            return "0"*(len(divisor)-1)
        pointer = payload.index(1)

    return "".join([str(val) for val in payload[-(len(divisor) - 1):]])


def separateData(packet):
    stringPacket = [f"{packByte:08b}" for packByte in packet]
    flags = stringPacket[0]
    seqNum = int("".join(stringPacket[1:5]), base=2)
    ackNum = int("".join(stringPacket[5:9]), base=2)
    payloadSize = int("".join(stringPacket[9:11]), base=2)
    payload = "".join(stringPacket[11:-1])[-payloadSize:]
    return (flags, seqNum, ackNum, payload)


def decipherMessage(message):
    msgBytes = np.array([char for char in message]
                        ).reshape(int(len(message)/8), 8)
    letters = [chr(int("".join(msgByte), base=2)) for msgByte in msgBytes]
    return "".join(letters)


def decipherImage(message):
    msgBytes = [str(int(msg)) for msg in message]
    msgBytes = "".join(msgBytes)
    msgNum = int(msgBytes, base=2)
    hexNum = hex(msgNum)[2:]
    if len(hexNum) % 2 != 0:
        hexNum += "0"
    data = bytes.fromhex(hexNum)

    return data


def checkCRC(binCode, divisor):
    stringPacket = [f"{packByte:08b}" for packByte in binCode]
    payload = []
    for byteSection in stringPacket:
        payload += byteSection
    payload = [int(n) for n in payload]
    divisor = [int(n) for n in list(divisor)]
    remainder = []
    pointer = 0

    while pointer <= len(payload) - len(divisor):
        # Extract slice to subtract
        val = payload[pointer: pointer + len(divisor)]

        # Subtract paired values
        operations = zip(val, divisor)
        remainder = [abs(op[0] - op[1]) for op in operations]

        # Modify payload values, set pointer to index
        for i in range(len(divisor)):
            payload[pointer + i] = remainder[i]

        # Move pointer to next non-zero value
        if 1 not in payload:
            return 0
        pointer = payload.index(1)

    return "".join([str(val) for val in payload[-(len(divisor) - 1):]])


def runServer(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print("Looking for clients")
            s.bind((ip, int(port)))
            s.listen()
            while True:
                cnt = 0
                conn, adr = s.accept()
                with conn:
                    print(f"Connected to {adr}")

                    seqNum = 0
                    ackNum = 1
                    otherDivisor = "100000111"
                    totalPayload = ""

                    # Receive Sync Request
                    syncReq = conn.recv(2048)
                    sync = int(f"{syncReq[0]:08b}"[6])

                    if sync:
                        print("Client wants to synchronize")
                    else:
                        conn.close()
                        break

                    # Accept Sync Request
                    ack = buildPacket(
                        sync=1, ack=1, ackNum=ackNum, seqNum=seqNum)
                    seqNum += 1
                    conn.send(bytes(ack))

                    # Receive Sync Ack
                    syncAck = int(f"{conn.recv(2048)[0]:08b}"[3])
                    if (syncAck):
                        print("Ready to receive data")

                    else:
                        conn.close()
                        break

                    while True:
                        failRate = random.random()

                        # Receive Data
                        print("waiting for data")
                        packet = conn.recv(2048)
                        print("processing data")
                        clFlags, clSeqNum, clAckNum, payloadPiece = separateData(
                            packet)

                        if failRate < 0.2:
                            print("Random Packet Error")
                            stringPacket = [
                                f"{packByte:08b}" for packByte in packet]
                            bit1 = int(stringPacket[-2])
                            bit2 = int(stringPacket[-1])
                            stringPacket[-1] = stringPacket[-1][:-2] + \
                                str(bit1 ^ 1) + str(bit2 ^ 1)
                            packet = [int("".join(listByte), base=2)
                                      for listByte in stringPacket]

                        fin = int(clFlags[-1])
                        crcCheck = checkCRC(packet, otherDivisor)

                        print(crcCheck)

                        if fin:
                            print("Client is finished sending data")
                            conn.close()
                            break

                        if crcCheck == 0:
                            ackNum += len(packet)
                            totalPayload += payloadPiece

                        else:
                            print(crcCheck, len(payloadPiece),
                                  len(otherDivisor))
                            print(
                                "".join([f"{packByte:08b}" for packByte in packet]))
                            print("Erroneous data, try to request packet")

                        # Send Acknowledgement
                        print("ack", ackNum)
                        ack = buildPacket(ack=1, ackNum=ackNum, seqNum=seqNum)
                        conn.send(bytes(ack))

                        print(f"cnt: {cnt} >>> {int(payloadPiece)}")
                        cnt += 1

                print("Displaying data")
                if cnt >= 98 and cnt <= 110:
                    print(decipherMessage(totalPayload))

                elif len(totalPayload) < (2**15):
                    print(decipherMessage(totalPayload))

                else:
                    imgPayload = decipherImage(totalPayload)

                    with open('recImage.jpg', 'wb') as jpg:
                        jpg.write(imgPayload)

                    break

        except Exception as error:
            s.close()
            raise error


if __name__ == "__main__":
    args = getArgs()
    ip = "23.235.207.63"
    port = 9997
    runServer(ip, port)
