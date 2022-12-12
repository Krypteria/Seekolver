from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

import argparse
import requests
import os
import sys
import signal
import urllib3
import urllib
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#File descriptors used by the application
tmp_file="tmp.txt"
input_file="recon.txt"
apitoken_file=os.path.dirname(os.path.realpath(sys.argv[0]))+"/apitokens.json"
output_available="available.txt"
output_discarted="discarted.txt"

#Used to save the results on execution time
available_url={}
discarted_url=[]

#Used to maintain api tokens in execution time
apiTokens={}

#Number of subdomains found
all_subdomains=0

#Default timeout value
timeoutValue=3

#Default thread value
threads=50

#Valid status codes
status_codes = [200,301,302,307,401,403,404,405,500,502,503]

#filtered status codes
filtered_status_codes = ["200","301","302","307","401","403","404","405","500","502","503"]

#Redirects allowed
redirects = False

#Verbose allowed
verbose = False

#Insecure requests
secure = True

#Headers
headers_json = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0", "Accept" : "application/json, text/plain, */*"}
headers_html = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0", "Accept" : "text/html,application/xhtml+xml,application/xml"}

#Colors 
BLUE,LIGHT_BLUE,PURPLE,YELLOW,RED,GREEN,END="","","","","","",""
#fix to windows bug with colors
if(os.name != "nt"):
	BLUE= "\033[1;34;40m"
	LIGHT_BLUE= "\033[0;34m" 
	PURPLE= "\033[1;35;40m"
	YELLOW= "\033[1;33;40m"
	RED= "\033[1;31;40m"
	GREEN= "\033[1;32;40m"
	END= "\033[0m"

#CTRL + C
def def_handler(sig, frame):
	print("\nExiting...")
	saveResults()
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def printLogo():                 
	print("____________________________________________________________________\n")
	print("           ____ ____ ____ _  _ ____ _    _  _ ____ ____            ")
	print("           [__  |___ |___ |_/  |  | |    |  | |___ |__/            ")
	print("           ___] |___ |___ | \_ |__| |___  \/  |___ |  \          \n")      
	print("			    By " + GREEN + "Kripteria" + END)                                                          
	print("____________________________________________________________________\n")

def createFolders():
	print("\n----------------------- GENERATING OUTPUT FILES --------------------\n")
	if(os.path.isfile(output_available)):
		os.remove(output_available)

	if(os.path.isfile(output_discarted)):
		os.remove(output_discarted)

	if(os.path.isfile(tmp_file)):
		os.remove(tmp_file)

	if(os.path.isfile(input_file)):
		os.remove(input_file)

	open(output_available, "x")
	open(output_discarted, "x")
	open(input_file, "x")
	open(tmp_file, "x")

	print("[*] - Output files generated")
	print("[*] - The output files generated are: " + PURPLE + output_available + END + " and " + PURPLE + output_discarted + END + "\n")

def parseTokens():
	global apiTokens
	if(os.path.isfile(apitoken_file)):
		try:
			apiTokens = json.loads(open(apitoken_file).read())
			print(GREEN + "[*] - API tokens loaded" + END)
		except:
			print(YELLOW + "[*] - Zero API tokens loaded" + END)
	else:
		print(RED + "[*] - API tokens file not found" + END)

def getSubdomains(domain, args) -> bool:
	print("\n------------------------- SUBDOMAIN SEARCH -------------------------\n")

	if(args.organisationName):
		print("[*] - Searching for subdomains associated with the organization " + YELLOW + domain + END + "\n")
	if(args.commonName):
		print("[*] - Searching for subdomains associated with the domain " + YELLOW + domain + END + "\n")

	print("	[*] -" + GREEN + " Securitytrails" + END)
	print("	[*] -" + GREEN + " Alienvault" + END)
	print("	[*] -" + GREEN + " Virustotal" + END)
	print("	[*] -" + GREEN + " Spyonweb" + END)
	print("	[*] -" + GREEN + " Crt.sh" + END)
	print("	[*] -" + GREEN + " Askdns" + END)
		
	crtsh(domain,args)
	spyonweb(domain,args)
	alienvault(domain,args)
	askdns(domain,args)
	securitytrails(domain, args)
	virustotal(domain, args)

	output_file = open(input_file, "a")
	for subdomain in list(set(open(tmp_file).read().splitlines())):
		output_file.write(subdomain+"\n")
	
	output_file.close()
	os.remove(tmp_file)

	if os.path.getsize(input_file) != 0:
		print("\n[*] - Subdomains associated with the domain {domain} found".format(domain=domain))
		return True
	else:
		print("\n" + RED + "[!] - Domain {domain} is not correct or doesn't have subdomains\n".format(domain=domain) + END)
		return False

def crtsh(domain, args) -> None:
	searchField,url = "",""
	if(args.commonName):
		searchField, url = "name_value", "https://crt.sh/?q={domain}&output=json".format(domain=urllib.parse.quote_plus(domain))
	if(args.organisationName):
		searchField, url = "common_name", "https://crt.sh/?O={domain}&output=json".format(domain=urllib.parse.quote_plus(domain))
	
	try:
		response = requests.get(url, headers=headers_json)
		response_json = json.loads(response.text)
		
		output_file = open(tmp_file, "a")
		for entry in response_json:
			if("*" not in entry[searchField] and "@" not in entry[searchField]):
				output_file.write(entry[searchField]+"\n")
		output_file.close()
	except:
		print(RED + "[!] - An error occurred while querying crtsh" + END)

def alienvault(domain, args) -> None:
	if(args.commonName):
		try:
			response = requests.get("https://otx.alienvault.com/otxapi/indicators/domain/passive_dns/{domain}".format(domain=urllib.parse.quote_plus(domain)), headers=headers_json)
			response_json = json.loads(response.text)

			if("passive_dns" in response_json):
				output_file = open(tmp_file, "a")
				for entry in response_json["passive_dns"]:
					output_file.write(entry["hostname"]+"\n")
				output_file.close()
		except:
			print(RED + "[!] - An error occurred while querying alienvault" + END)

def askdns(domain, args) -> None:
	if(args.commonName):
		try:
			response = requests.get("https://askdns.com/domain/{domain}".format(domain=urllib.parse.quote_plus(domain)), headers=headers_html)
			response_html = BeautifulSoup(response.text, 'html.parser')

			output_file = open(tmp_file, "a")
			for entry in response_html.find_all('a'):
				if(domain in entry.get_text()):
					output_file.write(entry.get_text()+"\n")
			output_file.close()
		except:
			print(RED + "[!] - An error occurred while querying askdns" + END)
		
def spyonweb(domain, args) -> None:
	if(args.commonName):
		try:
			response = requests.get("https://spyonweb.com/{domain}".format(domain=urllib.parse.quote_plus(domain)), headers=headers_html)
			response_html = BeautifulSoup(response.text, 'html.parser')
			output_file = open(tmp_file, "a")
			
			if(len(response_html.find_all("div", {'class':'links'})) != 0):
				for entry in response_html.find_all("div", {'class':'links'})[0].find_all('a'):
					if(entry.get_text() != "" and domain in entry.get_text()):
						output_file.write(entry.get_text()+"\n")
				output_file.close()
		except:
			print(RED + "[!] - An error occurred while querying spyonweb" + END)

def securitytrails(domain, args) -> None:
	if(args.commonName and "securitytrails" in apiTokens):
		try:
			securitytrails_header = dict(headers_json)
			securitytrails_header[apiTokens["securitytrails"][0]]=apiTokens["securitytrails"][1]
			response = requests.get("https://api.securitytrails.com/v1/domain/{domain}/subdomains".format(domain=urllib.parse.quote_plus(domain)), headers=securitytrails_header)
			response_json = json.loads(response.text)

			if("subdomains" in response_json):
				output_file = open(tmp_file, "a")
				for entry in response_json["subdomains"]:
					output_file.write(entry+".{domain}\n".format(domain=domain))
				output_file.close()
		except:
			print(RED + "[!] - An error occurred while querying securitytrails" + END)

def virustotal(domain, args) -> None:
	if(args.commonName and "virustotal" in apiTokens):
		try:
			virustotal_header = dict(headers_json)
			virustotal_header[apiTokens["virustotal"][0]]=apiTokens["virustotal"][1]
			response = requests.get("https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000".format(domain=urllib.parse.quote_plus(domain)), headers=virustotal_header)
			response_json = json.loads(response.text)

			if("data" in response_json):
				output_file = open(tmp_file, "a")
				for entry in response_json["data"]: 
					output_file.write(entry["id"]+"\n")
				output_file.close()
		except:
			print(RED + "[!] - An error occurred while querying virustotal" + END)

def doRequest(url) -> dict:
	try:
		r, ext, redirect = "","",None
		if("https" in url):
			r = requests.get(url+":443", headers=headers_html, timeout=timeoutValue, allow_redirects=False, verify=secure)
		elif("http" in url):
			r = requests.get(url+":80", headers=headers_html,timeout=timeoutValue, allow_redirects=False,verify=secure)
		else:
			try:
				r = requests.get("https://"+url+":443", headers=headers_html, timeout=timeoutValue, allow_redirects=False, verify=secure)
				ext="https://"
			except:
				r = requests.get("http://"+url+":80", headers=headers_html, timeout=timeoutValue, allow_redirects=False, verify=secure)
				ext="http://"
		if(redirects):
			if(r.status_code in [301,302,307] and r.headers['Location']):
				redirect = r.headers['Location']
			
		return {"code":r.status_code, "extension":ext, "url":url, "redirect": redirect}
	except:
		discarted_url.append(url + " -> " + "Failed to establish a new connection\n")
		return None

def resolve():
	global all_subdomains
	index, url = 0, ""

	try:
		urls = open(input_file).read().splitlines()
	except:
		print(RED + "[!] - Error opening {file}".format(file=input_file) + END)
		sys.exit(1)

	print("\n----------------------- RESOLVING ADDRESSES ------------------------\n")
	all_subdomains = len(urls)
	if(all_subdomains > 0):
		with ThreadPoolExecutor(max_workers=min(threads,all_subdomains)) as executor:
			futures = [executor.submit(doRequest, url) for url in urls]
			for future_completed in as_completed(futures):
				response = future_completed.result()
				index = index + 1
				if(response != None):
					if(verbose):
						print("[*]","{0:6.2f}%".format(round((index / all_subdomains * 100), 2)), "- response obtained from:",response["url"])
					if(response["code"] != None and response["code"] in status_codes):
						if("https" in response["url"] or "http" in response["url"]):
							available_url[response["url"]] = (str(response["code"]), response["redirect"])
						else:
							available_url[response["extension"] + response["url"]] = (str(response["code"]), response["redirect"])
					elif(response["code"] != None):
						discarted_url.append(response["url"] + " -> " + str(response["code"]) + "\n")
				else:
					if(verbose):
						print("[*]","{0:6.2f}%".format(round((index / all_subdomains * 100), 2)))
			executor.shutdown()

def printInfo(url, values):
	color = ""
	status, redirect = values[0], values[1]
	if(status == "200"):
		color = GREEN
	if(status == "301"):
		color = LIGHT_BLUE
	if(status == "302"):
		color = BLUE
	if(status in ["307","401","405"]):
		color = YELLOW
	if(status in ["403","404"]):
		color = RED
	if(status in ["500","502","503"]):
		color = PURPLE
	
	if(redirect):
		print(url + " -> " + color + status  + END + " -> " + redirect)
	else:
		print(url + " -> " + color + status + END)

def parseFileInfo():
	fileInfo = ""
	try:
		fileInfo = open(input_file).read().splitlines()
	except:
		print(RED + "[!] - Error opening {file}".format(file=input_file) + END)
		sys.exit(1)

	for line in fileInfo:
		splittedline = line.split(">")
		try:
			url,status,redirect = splittedline[0][:-1], splittedline[1][1:4], ""
			if(status in filtered_status_codes):
				if(status in ["301","302","307"]):
					redirect = splittedline[2][1:]
				printInfo(url, (status, redirect))
		except:
			print(RED + "[!] - Error parsing the info in {file}, ¿are you using the file with the domains available?".format(file=input_file) + END)
			sys.exit(1)

def saveResults():
	print("\n----------------------------- RESULTS ------------------------------\n")
	if(all_subdomains > 0):
		print("[*] - {all} subdomains obtained, {resolved} resolved. ".format(all=all_subdomains, resolved=len(available_url)))
		print("[*] - {0:6.2f} % not resolving.".format(100 - (len(available_url) / all_subdomains * 100)))
		print("[*] - {0:6.2f} % resolving.\n".format(len(available_url) / all_subdomains * 100))
		available_url_sorted = sorted(available_url.items(), key=lambda x: x[1])
		with open(output_available, "w") as available_f:
			for url, values in dict(available_url_sorted).items():
				printInfo(url, values)
				status, redirect = values[0], values[1]
				if(redirect):
					available_f.write(url + " -> " + status + " -> " + redirect + "\n")
				else:
					available_f.write(url + " -> " + status + "\n")
			available_f.close()

		with open(output_discarted, "w") as discarted_f:
			discarted_f.writelines(discarted_url)
			discarted_f.close()
	else:
		print("[*] - {all} subdomains obtained, {resolved} resolved. ".format(all=all_subdomains, resolved=len(available_url)))

def parseArguments() -> dict:
	parser = argparse.ArgumentParser(conflict_handler='resolve')
	parser.add_argument('-f', '--file', type=str, help='file with urls to resolve (default recon.txt)')
	parser.add_argument('-o', '--output',type=str,help='name of the output file used for writing the results')
	parser.add_argument('-te', '--targetEntity', type=str, help='target entity on which the subdomain search will be applied')
	parser.add_argument('-cn', '--commonName', action='store_true', help='the aplication will use the target entity as common name')
	parser.add_argument('-on', '--organisationName', action='store_true', help='the aplication will use the target entity as organisation name')
	parser.add_argument('-t', '--threads', type=int, help='number of threads to be used (default 50)')
	parser.add_argument('-to', '--timeout',type=int, help='timeout value for requests (default 3s)')
	parser.add_argument('-r', '--redirect',action='store_true', help='resolves redirections')
	parser.add_argument('-k', '--insecure', action='store_true', help='Allow insecure server connections')
	parser.add_argument('-v', '--verbose',action='store_true', help='enable verbose output')
	parser.add_argument('-s', '--show',action='store_true',help='displays the information of an output file in colour')
	parser.add_argument('-sc', '--statusCodes',nargs='+',help='filters the show parameter output to certain status codes')

	return parser.parse_args()

if __name__ == "__main__":
	args = parseArguments()
	
	printLogo()
	subdomainsFinded = False

	if(args.show and not args.file):
		print(RED + "[!] - parameter -f missing, -s needs a file to display" + END)
		sys.exit(1)

	if(args.file and args.targetEntity):
		print(RED + "[!] - parameters -te | -f cannot be used at the same time" + END)
		sys.exit(1)

	if(not args.file and not args.targetEntity):
		print(RED + "[!] - parameters -te | -f required, use -h for help" + END)
		sys.exit(1)

	if (args.targetEntity):
		if(args.commonName and args.organisationName):
			print(RED + "[!] - parameters -cn | -on cannot be used at the same time" + END)
			sys.exit(1)
		elif(not args.commonName and not args.organisationName):
			print(RED + "[!] - parameters -cn | -on required" + END)
			sys.exit(1)

	if(args.show):
		input_file = args.file
		if(args.statusCodes):
			filtered_status_codes = args.statusCodes
		parseFileInfo()
		sys.exit(0)

	parseTokens()

	if(args.output):
		output_available=args.output

	createFolders()

	if(args.targetEntity):
		subdomainsFinded = getSubdomains(args.targetEntity, args)
	else:
		input_file = args.file
	
	if(args.threads):
		threads = args.threads
	if(args.timeout):
		timeoutValue = args.timeout
	if(args.redirect):
		redirects = True
	if(args.insecure):
		secure = False
	if(args.verbose):
		verbose = True

	resolve()
	saveResults()

	 