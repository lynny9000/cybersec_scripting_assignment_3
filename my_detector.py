#!/usr/bin/python3
#Student: Brendan Lynn
#Student number: R00195611

#########################################################################################################
#The purpose of this script is complete six tasks from the assignment "Malware Detection & Network Monitoring"
#########################################################################################################

import sys, os, re, time, _thread, threading, logging
from scapy.all import *

#########################################################################################################
# The below function opens the old_bad_word_lst and splits the bad words and appends onto another bad word list bad_word_lst which I use later to compare
#########################################################################################################

def print_if_bad_words_found(): # instructions/function to print if a bad word is found
    
    bad_word_lst = [] # initialising the list object
    old_bad_word_lst = open("bad_words.txt").read().split() # open and read bad words txt file

    for badword in old_bad_word_lst: # searching for the word and appending to the list
        if badword in bad_word_lst:
            continue
        else:
            bad_word_lst.append(badword)

    return bad_word_lst

#########################################################################################################
# The below function parses the bad ips into a list as in task 4
#########################################################################################################

def read_and_parse_bad_words_list_to_list(): #instructions/function to read in iplist
    
    file5 = open("output.txt", "r") # opens and reads in file5
    output_bad_word = file5.read()

    return output_bad_word.split() # splits into a list
    file5.close

#########################################################################################################
# The below function appends the bad ips found into a list
#########################################################################################################

def print_if_bad_ips_found(): # instructions/function to print if a bad ip is found

    ip_lst = [] # initialising the list object
    old_ip_list = open("bad_ips.txt").read().split() # open and read bad ips txt file


    for ip in old_ip_list: # searching for the ip and appending to the list
        if ip in ip_lst:
            continue
        else:
            ip_lst.append(ip)

    return ip_lst # retunrs list to use in compare function

#########################################################################################################
# The below function reads in the pad ips and bad words from the output.txt and splits into a list
#########################################################################################################

def print_txt_file_to_list(): # instructions/function to read in iplist

    file4 = open("output.txt","r") # open bad ips and bad words output file for split into list ip_lst2
    output_ip = file4.read()

    ip_lst2 = output_ip.split(" ")
    file4.close()
   
    return ip_lst2 # returns list so use in compare function

#########################################################################################################
# The below function compares both lists for a bad ip and bad word and prints a warning to the user if either are found
#########################################################################################################

def compare_lists(): # instructions/function ot copmare both lists for bad ip

    x = print_if_bad_ips_found() # returns from different function to use here
    y = print_txt_file_to_list()

    set1 = set(x) # creatubg a set from list x
    common_ips = set1.intersection(y) # creating a set to hold the common elements
    print("Warning!!! Bad IP/s found!!!! Contact your ICT Helpdesk!!!", common_ips) 
    
    z = print_if_bad_words_found() # calling fucntion from another fuctions to compare an print
    q = read_and_parse_bad_words_list_to_list()

    set2 = set(z)
    common_bad_words = set2.intersection(q)
    print("Warning!!! Bad Word/s found!!!! Contact your ICT Helpdesk!!!", common_bad_words)  


#########################################################################################################
# The below is task 2 and a function that checks for bad hashes when the user passes in the argument --file-scan
# Task 5 is also below where I implement threading to speed up the MD5 hash comparison from task 2 an compare the time
#########################################################################################################

def print_if_bad_hash_found(): # instructions/function to compare files for bad hashes

    md5ComputerFiles = os.popen("md5sum * | cut -c1-32 > all_hashes_to_compare.txt").read()


     # reading in both files contents to compare
file1 = open("all_hashes_to_compare.txt", "r")
file2 = open("bad_hashes.txt", "r")

    # splitting each files contents into a list to compare indexes with each other   
all_hashes_to_compare_txt = file1.read().split("\n")
bad_hashes_txt_list = file2.read().split("\n")

start = time.perf_counter() # start counter

x = set(bad_hashes_txt_list)
y = set(all_hashes_to_compare_txt)

#########################################################################################################
################################### before threading ####################################################

#set1 = set(x)
#common_bad_hashes = set1.intersection(y)
#print("Warning!!! Bad Hash/s found!!!! Contact your ICT Helpdesk!!!", common_bad_hashes)
#finish = time.perf_counter()
#print("--- md5sum scan takes %s seconds ---" % (finish - start))         
#print(f"Finished in {round(finish-start, 20)} seconds(s)")
################################### before threading ---> --- 0.00012044599861837924 seconds --- ########
#########################################################################################################

#########################################################################################################
################################## after threading #####################################################

for i in x: # loop to cycle through all the hashes and match on bad hashes
    if i in y:
        # Reference: https://www.tutorialspoint.com/python/python_multithreading.htm
        t1 = threading.Thread(target=print_if_bad_hash_found()) # thread target set to the function 
        print("Warning!!! Bad Hash/s found!!!! Contact your ICT Helpdesk!!!", i)

        t1.start() # calling the thread

finish = time.perf_counter() # finish counter

print(f"Finished in {round(finish-start, 20)} seconds(s)")
######## after threading --> --- 0.010174246999667957 seconds --- would be less if my directory consisted of more files #####
#########################################################################################################


#########################################################################################################
# The below function uses scapy to print the source and destination IPs for task 3 and the payload as required in task 6
#########################################################################################################


def store_src_dst_ip(): # instructions/function to run scapy to capture traffic

    stdout_fileno = sys.stdout

    sys.stdout = open('output.txt', 'w') # records the bad ips and the bad words from the following sniff

    pkts = sniff(iface="enp0s3", prn=lambda x:x.sprintf("src " "{IP:%IP.src% dst %IP.dst% Raw: %Raw.load%\n}")) # Reference: https://scapy.readthedocs.io/en/latest/usage.html
    print(pkts)
    sys.stdout.close()


def print_current_directory_files(): # instructions/function to print contents of currenty directory

    path = '/home/ubuntu/test_scripts/' #current directory

    files = os.listdir(path) 
    for f in files:
        print(f)


#########################################################################################################
# The below is task 1 which contains a main function to read command line arguments from the user using only the sys library. Task 3 is also here where I force via print outputs the user to type in the correct arguments
#########################################################################################################

def main(): # main function

    args = sys.argv # manually reads command line arguments from the user using the sys library 
    
    if sys.argv[1] == "--file-scan" and len(sys.argv) <= 2: # prints only if there are two or less indexes  
        print_current_directory_files() # function called to print current directory
        print_if_bad_hash_found() # function called to check if a bad hash is found or not
    elif sys.argv[1] == "--net-mon" and len(sys.argv) <= 2:
        compare_lists() # function called to compare lists 
    elif sys.argv[1] == "--net-mon" and sys.argv[2] == "enp0s3" and len(sys.argv) <= 3:
        store_src_dst_ip() # function called if user types --net-mon and enp0s3
    elif sys.argv[1] == "--net-mon" and sys.argv[2] == "--file-scan": # enforcing rule from task 3 where a user cannot select both --net-mon and --file-scan
        print("You can not select both --net-mon and --file-scan together! Choose one only!!!")
    elif sys.argv[1] == "--file-scan" and sys.argv[2] == "--net-mon": # enforcing rule from task 3 where a user cannot select both --file-scan aand --net-mon
        print("You can not select both --file-scan and --net-mon together! Choose one only!!!")       
    else:
        print("Error! You did not select or type the correct commands!!! Recheck your code!!!")

#file1.close()                                       
#file2.close()   

main()


#########################################################################################################
# Instructions: how to test/run code

# Task 1
# 1) sudo ./my_detector.py --file-scan

# 1) Task 2 and task 5
# 2) sudo ./my_detector.py --file-scan

# Task 3 and task 4
# 1) sudo ./my_detector.py --net-mon enp0s3
# 2) ping 8.8.8.8 from correct directory
# 3) stop all commands running
# 4) sudo ./my_detector.py --net-mon
# 5) Bad IP/s found displayed or bad Word/s displayed

# Task 6
#1) sudo ./my_detector.py --net-mon enp0s3 
#2) add "badwordbrendan" to bad words text file
#3) sudo scapy
#4) send(IP(src="4.4.4.4",dst="10.0.2.15")/ICMP()/"badwordbrendan") Reference: https://scapy.readthedocs.io/en/latest/usage.html
#5) run sudo ./my_detector.py --net-mon from a differenet temrinal and the badword is printed

#########################################################################################################


