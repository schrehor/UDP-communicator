import os
import socket
import struct
import threading
from crccheck.crc import Crc32

# -----------General------------
ack = 0
nack = 0

def check_crc(data):
    """
    Vypocita crc preneseneho paketu.

    :param data: paket preneseny po sieti
    :return: crc
    """
    return Crc32.calc(data[:1] + data[5:])


def check_crc_num(data):
    """
    Vypocita crc preneseneho paketu, ktory obsahuje aj poradove cislo.

    :param data: paket preneseny po sieti
    :return: crc
    """
    flag, no_packet = struct.unpack("! c 4x H", data[:7])
    crc_struct = struct.pack("! c H", flag, no_packet)

    return Crc32.calc(crc_struct + data[7:])


def check_crc_file(data):
    """
    Vypocita crc preneseneho paketu, ktory obsahuje velkost suboru a velkost ramca.

    :param data: paket preneseny po sieti
    :return: crc
    """
    flag, size_file, size_frame = struct.unpack("! c 4x I H", data[:11])
    crc_struct = struct.pack("! c I H", flag, size_file, size_frame)

    return Crc32.calc(crc_struct + data[11:])


def count_crc(flag, data):
    """
    Vypocita crc pre pakety, ktore obsahuju nizsie uvedene flagy.

    :param flag: I, E, K, M
    :param data: data, ktore budu odoslane v pakete
    :return: crc
    """

    if data is None:
        return Crc32.calc(flag)
    else:
        return Crc32.calc(flag + data)


def count_crc_num(flag, no_packet, data):
    """
    Vypocita crc pre pakety, ktore obsahuju nizsie uvedene flagy.

    :param flag: C, X, P
    :param no_packet: cislo paketu
    :param data: data, ktore budu odoslane v pakete
    :return: crc
    """
    crc_struct = struct.pack("! c H", flag, no_packet)

    if data is None:
        return Crc32.calc(crc_struct)
    else:
        return Crc32.calc(crc_struct + data)


def count_crc_file(flag, size_file, size_frame, file_name):
    """
    Vypocita crc pre paket, ktory obsahuje flag F.

    :param flag: F
    :param size_file: velkost posielaneho suboru
    :param size_frame: velkost ramca zvolena pouzivatelom
    :param file_name: nazov suboru
    :return: crc
    """
    crc_struct = struct.pack("! c I H", flag, size_file, size_frame)

    return Crc32.calc(crc_struct + file_name.encode())


def get_iter_count(size_file, size_frame):
    """
    :return: pocet iteracii potrebnych na prenos celeho suboru
    """
    return int(size_file / size_frame) + 1


# -----------Klient------------


def ka_thread_setup(server_addr, sock):
    """
    Vytvori thread, ktory vola a spusta funkciu keep_alive.

    :return: event, ktorym riadim ci sa ma keep_alive vykonavat alebo nie
    """
    stop_thread = threading.Event()
    threading.Thread(target=keep_alive, args=(server_addr, sock, stop_thread)).start()

    return stop_thread


def keep_alive(server_addr, sock, thread):
    """
    Funkcia, ktora kazdych 60 sekund posle keep alive paket. Po odoslani caka na potvrdenie.

    :param thread: event, ktorym riadim thread
    """
    flag = b'K'
    kill = False
    crc = count_crc(flag, None)
    global ack, nack

    keep_alive_struct = struct.pack("! c I", flag, crc)

    while 1:
        if not thread.is_set():
            thread.wait(60)
            while 1:
                sock.sendto(keep_alive_struct, server_addr)
                try:
                    data = sock.recv(7)
                except ConnectionResetError:
                    kill = True
                    break

                flag, crc = struct.unpack("! c I", data[:5])
                if flag == b'C' and crc == check_crc_num(data):
                    ack += 1
                    break
                nack += 1

        if kill:
            break


def create_packet_struct(no_packet, data):
    flag = b'P'
    crc = count_crc_num(flag, no_packet, data)

    return struct.pack("! c I H", flag, crc, no_packet)


def create_answer_thread(byte_file, confirmed_pack, size_file, size_frame, sock):
    """
    :return: Thread na prijimanie odpovedi od servera.
    """
    server_answer = threading.Thread(target=receive_answer,
                                     args=(confirmed_pack, sock, byte_file, size_frame, size_file))
    server_answer.start()
    return server_answer


def receive_answer(confirmed_pack, sock, file, size_frame, size_file):
    """
    Prijima odpoved od servera. Ak nebol paket prijaty spravne, znovu ho posle.
    """
    iter_count = get_iter_count(size_file, size_frame)
    iteration = 0
    resent = []
    global ack
    global nack

    for num in range(1, iter_count + 1):
        confirmed_pack.add(num)

    while iteration < iter_count:
        data, server_addr = sock.recvfrom(7)
        flag, crc, no_packet = struct.unpack("! c I H", data)

        if crc == check_crc_num(data):
            if flag == b'C':
                confirmed_pack.discard(no_packet)
                check_lost_packets(confirmed_pack, file, no_packet, resent, server_addr, size_frame, sock)
                print("Paket cislo", no_packet, "bol uspesne potvrdeny")
                ack += 1
                iteration += 1
            elif flag == b'X':
                print("Paket cislo", no_packet, "nebol uspesne potvrdeny")
                resend_packets(file, no_packet, resent, server_addr, size_frame, sock)
                nack += 1


def check_lost_packets(confirmed_pack, file, no_packet, resent, server_addr, size_frame, sock):
    """
    Zisti ci sa nejake pakety nestratili tym, ze skontroluje, ci sa potvrdil prichod vsetkych paketov pred aktualnym.
    """
    for item in confirmed_pack:
        if no_packet > item and item not in resent:
            resend_packets(file, item, resent, server_addr, size_frame, sock)
        else:
            break


def resend_packets(file, no_packet, resent, server_addr, size_frame, sock):
    """
    Funkcia odosle pakety, ktore program urcil ako stratene, alebo nespravne prijate.
    """
    file_seg = file[size_frame * (no_packet - 1):size_frame * no_packet]
    packet_struct = create_packet_struct(no_packet, file_seg)
    sock.sendto(packet_struct + file_seg, server_addr)
    resent.append(no_packet)


def sim_mistake(current_file_seg, make_mistake):
    """
    Simuluje chybu tym, ze zmeni prvy bajt v prvom fragmente.

    :param current_file_seg: aktualny datovy fragment posielaneho suboru
    :param make_mistake: flag, ktory urcuje ci sa ma generovat chyba
    :return: pokazeny fragment a zmeneny flag.
    """
    if make_mistake == 'y':
        new_seg = list(current_file_seg)
        if 255 != new_seg[0]:
            new_seg[0] = 255
        else:
            new_seg[0] = 254
        current_file_seg = bytes(new_seg)
        make_mistake = 'n'
    return current_file_seg, make_mistake


def send_data_packets(byte_file, confirmed_pack, size_file, make_mistake, server_addr, size_frame, sock):
    """
    Odosle subor po jednotlivych paketoch. Pre odosielanie je nastaveny maximalny limit paketov, ktore mozu byt odoslane
    bez prijatia. Po mnohych testoch mi najlepsie fungoval limit 40.
    """
    buffer = 40
    iter_count = get_iter_count(size_file, size_frame)

    for iteration in range(iter_count):
        while iteration == (iter_count + 1) - len(confirmed_pack) + buffer:
            continue
        current_file_seg = byte_file[iteration * size_frame:(iteration + 1) * size_frame]
        packet_struct = create_packet_struct(iteration + 1, current_file_seg)
        current_file_seg, make_mistake = sim_mistake(current_file_seg, make_mistake)
        sock.sendto(packet_struct + current_file_seg, server_addr)


def send_file_struct(server_addr, sock, file_path, file_name, size_frame):
    """
    Posle serveru paket s informaciami potrebnymi na prijatie suboru.
    """
    file_flag = b'F'
    size_file = os.path.getsize(file_path + "\\" + file_name)
    crc = count_crc_file(file_flag, size_file, size_frame, file_name)
    file_init_struct = struct.pack("! c I I H", file_flag, crc, size_file, size_frame) + file_name.encode()

    sock.sendto(file_init_struct, server_addr)

    return size_file


def read_file(file_name, file_path):
    with open(file_path + "\\" + file_name, "rb") as file:
        byte_file = file.read()
    return byte_file


def get_input_sender():
    file_path = input("Zadajte cestu k suboru: ")
    file_name = input("Zadajte nazov suboru: ")
    while 1:
        size_frame = int(input("Zadajte velkost ramca (1 - 1461): "))
        if 1 <= size_frame <= 1461:
            break
    make_mistake = input("Chcete simulovat chybu? [y/n]: ")
    print()

    return file_name, file_path, make_mistake, size_frame


def send_file(server_addr, sock):
    """
    Funkcia odosle paket, v ktorom su vsetky informacie, ktore bude server potrebovat, aby spravne prijal dany subor.
    Po potvrdeni prijatia informacneho paketu sa poslu pakety obsahujuce data suboru. Potvrdzovanie tychto paketov
    sa vykonava v samostatnom threade.
    """
    confirmed_pack = set()
    file_name, file_path, make_mistake, size_frame = get_input_sender()
    global ack, nack

    while 1:
        size_file = send_file_struct(server_addr, sock, file_path, file_name, size_frame)
        accepted, server_addr = sock.recvfrom(7)

        flag_answ, crc = struct.unpack("! c I", accepted[:5])
        if flag_answ == b'C' and crc == check_crc_num(accepted):
            ack += 1
            break
        nack += 1

    byte_file = read_file(file_name, file_path)
    server_answer = create_answer_thread(byte_file, confirmed_pack, size_file, size_frame, sock)
    send_data_packets(byte_file, confirmed_pack, size_file, make_mistake, server_addr, size_frame, sock)
    server_answer.join()


def get_message_struct(frame_size):
    flag = b'M'
    crc = count_crc(flag, frame_size)

    return struct.pack("! c I", flag, crc) + frame_size


def send_message(server_addr, sock):
    """
    Posle serveru paket s potrebnymi informaciami, a potom posle fragmentovanu spravu.
    """
    global ack, nack
    message = input("Napiste spravu, ktoru chcete poslat: ")
    frame_size = int(input("Zadajte velkost ramca (1 - 1461): "))
    print()

    pack_count = str(int(len(message) / frame_size) + 1)
    message_struct = get_message_struct(pack_count.encode())

    while 1:
        sock.sendto(message_struct, server_addr)
        data = sock.recv(7)

        flag, crc = struct.unpack("! c I", data[:5])
        if flag == b'C' and crc == check_crc_num(data):
            ack += 1
            break
        nack += 1

    send_message_frag(frame_size, message, pack_count, server_addr, sock)


def send_message_frag(frame_size, message, pack_count, server_addr, sock):
    """
    Po fragmentoch odosiela spravu s tym, ze po kazdom odoslani si pyta odpoved
    """
    global ack, nack
    for i in range(int(pack_count)):
        packet_struct = create_packet_struct(i + 1, message[i * frame_size:(i + 1) * frame_size].encode())
        while 1:
            sock.sendto(packet_struct + message[i * frame_size:(i + 1) * frame_size].encode(), server_addr)
            data = sock.recv(7)
            flag, crc = struct.unpack("! c I", data[:5])
            if flag == b'C' and crc == check_crc_num(data):
                print("Paket cislo", i + 1, "bol uspesne potvrdeny")
                ack += 1
                break
            else:
                print("Paket cislo", i + 1, "nebol uspesne potvrdeny")
                nack += 1


def send_end_flag(server_addr, sock):
    """
    Klient odosle serveru paket, ktorym skonci ich komunikaciu. Funkcia taktiez caka na odpoved od serveru.
    """
    flag = b'E'
    crc = count_crc(flag, None)

    end_struct = struct.pack("! c I", flag, crc)

    while 1:
        sock.sendto(end_struct, server_addr)
        data = sock.recv(5)

        if data == end_struct:
            break


def client_menu(server_addr, sock):
    """
    Menu pre klienta. Ponuka vsetky moznosti komunikacie medzi klientom a serverom.
    Funkcia taktiez spusta keep alive thread.

    :param server_addr: ip adresa servera
    :param sock: sparovany socket so serverom
    """
    stop_thread = ka_thread_setup(server_addr, sock)

    while 1:
        print("Zvolte co chcete poslat\nF - subor\nM - sprava\nX - odhlasit sa\n")
        action = input("Akcia: ")
        print()

        stop_thread.set()
        if action == 'f' or action == 'F':
            send_file(server_addr, sock)
        elif action == 'm' or action == 'M':
            send_message(server_addr, sock)
        elif action == 'x' or action == 'X':
            send_end_flag(server_addr, sock)
            print("Pocet ack:", ack)
            print("Pocet nack:", nack)
            break
        print()
        stop_thread.clear()


def create_init_struct():
    init_flag = b'I'
    crc = count_crc(init_flag, None)

    return struct.pack("! c I", init_flag, crc)


def get_server_info():
    ip_add = input("Zadajte IP adresu servera: ")
    while 1:
        port = int(input("Zadajte port servera. Port musi byt v rozmedzi 1024 - 65535: "))
        if 1024 <= port <= 65535:
            break
    print()
    return ip_add, port


def init_connection_client():
    """
    Inicializuje spojenie medzi klientom a serverom tym, ze odosle inicializacny paket a potvrdi prijatie potvrdenia
    od servera. Po spojeni prejde na menu klienta.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip_add, port = get_server_info()
    server_addr = (ip_add, port)
    global ack, nack
    ack = 0
    nack = 0

    init_struct = create_init_struct()

    while 1:
        sock.sendto(init_struct, server_addr)
        data, addr = sock.recvfrom(7)
        if data == init_struct:
            break

    client_menu(server_addr, sock)


# -----------Server------------


def get_file_info(data):
    size_file, size_frame = struct.unpack("! I H", data[5:11])
    file_name = data[11:]

    return size_file, size_frame, file_name


def receive_file(sock, data):
    """
    Prijme paket s informaciami o suboru, ktore bude prijimat. Nasledne prijima pakety obsahujuce data.
    Nakoniec z tychto dat posklada naspat subor.
    """
    size_file, size_frame, file_name = get_file_info(data)
    file_path = input("Zadajte cestu kde chcete ulozit subor: ")
    print()
    data_holder = {}

    iter_count = get_iter_count(size_file, size_frame)
    iteration = 0

    while iteration < iter_count:
        new_data, addr = sock.recvfrom(size_frame + 7)
        flag, crc, no_packet = struct.unpack("! c I H", new_data[:7])

        if flag == b'P' and crc == check_crc_num(new_data):
            data_holder[no_packet] = new_data[7:]
            sock.sendto(get_answer_struct(b'C', no_packet), addr)
            print("Paket cislo", no_packet, "bol uspesne prijaty")
            iteration += 1
        else:
            sock.sendto(get_answer_struct(b'X', no_packet), addr)
            print("Paket cislo", no_packet, "nebol uspesne prijaty")

    save_file(data_holder, file_name, file_path)

    print("\nSubor bol uspesne ulozeny do:", file_path, "\n")


def save_file(data_holder, file_name, file_path):
    with open(file_path + "\\" + file_name.decode(), "wb") as file:
        for iteration in range(len(data_holder)):
            file.write(data_holder[iteration + 1])


def receive_message(sock, data):
    """
    Prijme spravu po fragmentoch, nakoniec ju spoju dokopy a vypise
    """
    pack_count = int(data[5:].decode())
    message = ""
    for i in range(int(pack_count)):
        while 1:
            data, addr = sock.recvfrom(1500)
            flag, crc, no_packet = struct.unpack("! c I H", data[:7])

            if flag == b'P' and crc == check_crc_num(data):
                message += data[7:].decode()
                sock.sendto(get_answer_struct(b'C', no_packet), addr)
                print("Paket cislo", no_packet, "bol uspesne prijaty")
                break
            else:
                sock.sendto(get_answer_struct(b'X', no_packet), addr)
                print("Paket cislo", no_packet, "nebol uspesne prijaty")

    print("\n", message, "\n")


def get_answer_struct(flag, no_packet):
    crc = count_crc_num(flag, no_packet, None)

    return struct.pack("! c I H", flag, crc, no_packet)


def receive_state(sock):
    """
    Server sa nachadza v rezime cakania na dalsi paket. Mozu prist 4 typy paketov.
    Paket na prijatie spravy alebo suboru, keep alive paket, ktory udrzuje spojenie a paket na ukoncenie komunikacie.
    :param sock:
    """
    while 1:
        data, client_addr = sock.recvfrom(1500)
        flag, crc = struct.unpack("! c I", data[:5])

        if flag == b'F' and crc == check_crc_file(data):
            sock.sendto(get_answer_struct(b'C', 0), client_addr)
            receive_file(sock, data)
        elif flag == b'M' and crc == check_crc(data):
            sock.sendto(get_answer_struct(b'C', 0), client_addr)
            receive_message(sock, data)
        elif flag == b'K':
            sock.sendto(get_answer_struct(b'C', 0), client_addr)
        elif flag == b'E' and crc == check_crc(data):
            sock.sendto(data, client_addr)
            break
        else:
            sock.sendto(get_answer_struct(b'X', 0), client_addr)


def init_connection_server():
    """
    pouzivatel nastavi port, na ktorom bude cakat komunikaciu a po prijati inicializacneho paketu sa presunie do
    rezimu cakania na dalsi paket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port = get_server_port()
    sock.bind(("", port))

    while 1:
        data, addr = sock.recvfrom(5)
        flag, crc = struct.unpack("! c I", data)

        if crc == check_crc(data) and flag == b'I':
            sock.sendto(data, addr)
            break

        fail_struct = get_answer_struct(b'X', 0)
        sock.sendto(fail_struct, addr)

    receive_state(sock)


def get_server_port():
    while 1:
        port = int(input("Zadajte port v rozmedzi 1024 - 65535: "))
        if 1024 <= port <= 65535:
            break
    print()
    return port


if __name__ == "__main__":
    while 1:
        print("Zvolte klienta alebo server\nK - klient\nS - server\nX - ukoncenie programu\n")
        service = input("Akcia: ")
        print()

        if service == 'k' or service == 'K':
            init_connection_client()
        elif service == 's' or service == 'S':
            init_connection_server()
        elif service == 'x' or service == 'X':
            break
        print("\n")
