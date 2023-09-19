from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

import datetime
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
input_file="subdomains.txt"
apitoken_file=os.path.dirname(os.path.realpath(sys.argv[0]))+"/apitokens.json"
output_available="available"
output_discarted="discarted.txt"
folderName = ""

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
threads=10

#Valid status codes
status_codes = [200,301,302,307,401,403,404,405,500,502,503]

#filtered status codes
filtered_status_codes = ["200","301","302","307","401","403","404","405","500","502","503"]

#filtered domains
filtered_domains = None

#Redirects allowed
redirects = False

#Verbose allowed
verbose = False

#Insecure requests
secure = True

#Ports to be scanned
ports = []

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
	print(" __   ____  ____ __ __   ___   __    __ __  ____ ____            ")
	print("(( \ ||    ||    || //  // \\\  ||    || || ||    || \\\   ")
	print(" \\\  ||==  ||==  ||<<  ((   )) ||    \\\ // ||==  ||_//  ")   
	print("\_)) ||___ ||___ || \\\  \\\_//  ||__|  \V/  ||___ || \\\ \n")   

def createFolders():
	global output_available, output_discarted, folderName
	print("\n[*] - Generating output files \n")
	now = datetime.datetime.now()
	folderName = now.strftime("seekolver_%Y_%m_%d")
	if not os.path.isdir(folderName):
		os.makedirs(folderName)

	if os.path.exists(folderName + "/" + "{output_available}.txt".format(output_available=output_available)):
		count = 2
		while True:
			newFilename = "{output_available}_{count}".format(output_available=output_available, count=count)
			if not os.path.exists(folderName + "/" + "{newFilename}.txt".format(newFilename=newFilename)):
				break
			count += 1
		output_available = newFilename

	output_available += ".txt"
	open(folderName + "/" + output_available, "x")

	if(os.path.isfile(tmp_file)):
		os.remove(tmp_file)

	open(tmp_file, "x")

	print("\t[*] - Output files generated")
	print("\t[*] - The output files generated are: " + PURPLE + output_available + END + " and " + PURPLE + output_discarted + END)

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
	print("\n[*] - Subdomain search \n")

	if(args.organisationName):
		print("\t[*] - Searching for subdomains associated with the organization " + YELLOW + domain + END + "\n")
	if(args.commonName):
		print("\t[*] - Searching for subdomains associated with the domain " + YELLOW + domain + END + "\n")

	print("\t[*] -" + GREEN + " Securitytrails" + END)
	print("\t[*] -" + GREEN + " Alienvault" + END)
	print("\t[*] -" + GREEN + " Virustotal" + END)
	print("\t[*] -" + GREEN + " Spyonweb" + END)
	print("\t[*] -" + GREEN + " Crt.sh" + END)
		
	crtsh(domain,args)
	spyonweb(domain,args)
	alienvault(domain,args)
	securitytrails(domain, args)
	virustotal(domain, args)

	if(os.path.exists(input_file)):
		os.remove(input_file)

	output_file = open(input_file, "a")
	for subdomain in list(set(open(tmp_file).read().splitlines())):
		output_file.write(subdomain+"\n")
	
	output_file.close()

	if os.path.getsize(input_file) != 0:
		print("\n\t[*] - Subdomains associated with the domain {domain} found".format(domain=domain))
		return True
	else:
		print("\n\t" + RED + "[!] - Domain {domain} is not correct or doesn't have subdomains\n".format(domain=domain) + END)
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
		print(RED + "\t[!] - An error occurred while querying crtsh" + END)

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
			print(RED + "\t[!] - An error occurred while querying alienvault" + END)
		
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
			print(RED + "\t[!] - An error occurred while querying spyonweb" + END)

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
			print(RED + "\t[!] - An error occurred while querying securitytrails" + END)

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
			print(RED + "\t[!] - An error occurred while querying virustotal" + END)


def doRequests(url) -> dict:
	responses = {}
	hasResponse, response, temp = False, {}, {}

	if("https" in url or "http" in url):
		(hasResponse, response) = doRequest(0, url, None, None)

		if(hasResponse):
			return (0, response)
		else:
			discarted_url.append(url + " -> " + "Failed to establish a new connection\n")
			return None
	else:
		responses[url] = {}
		httpProtocol, httpsProtocol = ["80", "8080"], ["443","8443"]
		
		for port in ports: 
			if(port in httpProtocol):
				(hasResponse, temp) = doRequest(1, url, port, "http")
			elif(port in httpsProtocol):
				(hasResponse, temp) = doRequest(1, url, port, "https")
			else:
				(hasResponse, temp) = doRequest(1, url, port, "https")

			if(hasResponse):
				responses[url][port] = temp

		if(responses != {}):
			return (1, responses)	
		else:
			discarted_url.append(url + " -> " + "Failed to establish a new connection\n")
			return None
	
# mode 0: resolve	mode 1: discovery
def doRequest(mode, url, port, protocol) -> dict: 
	try:
		redirect, response = "", {}

		if(mode == 0):
			response = requests.get(url, headers=headers_html, timeout=timeoutValue, allow_redirects=False, verify=secure)
		elif(mode == 1):
			response = requests.get("{protocol}://{url}:{port}".format(protocol=protocol, url=url, port=port), headers=headers_html, timeout=timeoutValue, allow_redirects=False, verify=secure)
		if(redirects):
			if(response.status_code in [301,302,307] and response.headers['Location']):
				redirect = response.headers['Location']
		
		return (True, {"statusCode":response.status_code, "protocol":protocol, "url":url, "port": port, "redirect": redirect})
	except:
		return (False, None)

def resolve():
	global all_subdomains
	index = 0

	try:
		urls = open(input_file).read().splitlines()
	except:
		print(RED + "[!] - Error opening {file}".format(file=input_file) + END)
		sys.exit(1)

	print("\n[*] - Resolving addresses \n")
	print("\t[*] - Scanning ports " + GREEN + "{ports}\n".format(ports=' '.join(ports)) + END)

	all_subdomains = len(urls)
	if(all_subdomains > 0):
		with ThreadPoolExecutor(max_workers=min(threads,all_subdomains)) as executor:
			futures = [executor.submit(doRequests, url) for url in urls]
			for future_completed in as_completed(futures):
				response = future_completed.result()
				index = index + 1
				if(response != None):
					mode, responseContent = response[0], response[1]

					if(mode == 0):
						resolveExecution(responseContent, index, all_subdomains)
					elif(mode == 1):
						for url in responseContent:
							for port in responseContent[url]:
								resolveExecution(responseContent[url][port], index, all_subdomains)
				else:
					if(verbose):
						print("\t[*]","{0:6.2f}%".format(round((index / all_subdomains * 100), 2)))
			executor.shutdown()

def resolveExecution(response, index, all_subdomains):
	if(response["statusCode"] != None):
		if(response["statusCode"] in status_codes):
			if(verbose):
				print("\t[*]","{0:6.2f}%".format(round((index / all_subdomains * 100), 2)), "- response obtained from: {url}:{port}".format(url=response["url"], port=response["port"]))
			if("https" in response["url"] or "http" in response["url"]):
				available_url[response["url"]] = (str(response["statusCode"]), response["redirect"])
			else:
				available_url["{protocol}://{url}:{port}".format(protocol=response["protocol"],url=response["url"],port=response["port"])] = (str(response["statusCode"]), response["redirect"])
		else:
			if(verbose):
				print("\t[*]","{0:6.2f}%".format(round((index / all_subdomains * 100), 2)))
			discarted_url.append(response["url"] + " -> " + str(response["statusCode"]) + "\n")
	else:
		if(verbose):
			print("\t[*]","{0:6.2f}%".format(round((index / all_subdomains * 100), 2)))
	

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
		print("\t"+url + " -> " + color + status  + END + " -> " + redirect)
	else:
		print("\t"+url + " -> " + color + status + END)

def parseFileInfo():
	print("[*] - Showing " + PURPLE + "{file}".format(file=input_file) + END + " content in seekolver format\n")

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

			urlParts, domainName = url.split("/")[2].split(".")[-2:], ""
			if len(urlParts) == 1:
				domainName = urlParts[0]
			else:
				domainName = urlParts[-2]
			if(status in filtered_status_codes and (filtered_domains == None or domainName in filtered_domains)):
				if(status in ["301","302","307"]):
					redirect = splittedline[2][1:]
				printInfo(url, (status, redirect))
		except:
			print(RED + "[!] - Error parsing the info in {file}, are you providing the correct file?".format(file=input_file) + END)
			sys.exit(1)

def saveResults():
	print("\n[*] - Results \n")
	if(all_subdomains > 0):
		print("\t[*] - {all} subdomains obtained, {resolved} resolved. ".format(all=all_subdomains, resolved=len(available_url)))
		print("\t[*] - {0:6.2f} % not resolving.".format(100 - (len(available_url) / all_subdomains * 100)))
		print("\t[*] - {0:6.2f} % resolving.\n".format(len(available_url) / all_subdomains * 100))

		available_url_sorted = sorted(available_url.items(), key=lambda x: x[1])
		with open(folderName + "/" + output_available, "w") as available_f:
			for url, values in dict(available_url_sorted).items():
				printInfo(url, values)
				status, redirect = values[0], values[1]
				if(redirect):
					available_f.write(url + " -> " + status + " -> " + redirect + "\n")
				else:
					available_f.write(url + " -> " + status + "\n")
			available_f.close()

		with open(folderName + "/" + output_discarted, "a") as discarted_f:
			discarted_f.writelines(discarted_url)
			discarted_f.close()
	else:
		print("\t[*] - {all} subdomains obtained, {resolved} resolved. ".format(all=all_subdomains, resolved=len(available_url)))

	os.remove(tmp_file)
	

def parseArguments() -> dict:
	parser = argparse.ArgumentParser(conflict_handler='resolve')
	parser.add_argument('-f', '--file', type=str, help='file with urls to resolve')
	parser.add_argument('-o', '--output',type=str,help='name of the output file used for writing the results')
	parser.add_argument('-te', '--targetEntity', type=str, help='target entity on which the subdomain search will be applied')
	parser.add_argument('-cn', '--commonName', action='store_true', help='the aplication will use the target entity as common name')
	parser.add_argument('-on', '--organisationName', action='store_true', help='the aplication will use the target entity as organisation name')
	parser.add_argument('-t', '--threads', type=int, help='number of threads to be used (default 10)')
	parser.add_argument('-p', '--ports', nargs='+', help='ports to be scanned, only HTTPx services allowed [<PORT> <PORT2>]')
	parser.add_argument('-to', '--timeout',type=int, help='timeout value for requests (default 3s)')
	parser.add_argument('-r', '--redirect',action='store_true', help='resolves redirections')
	parser.add_argument('-k', '--insecure', action='store_true', help='allow insecure server connections')
	parser.add_argument('-v', '--verbose',action='store_true', help='enable verbose output')
	parser.add_argument('-s', '--show',action='store_true',help='displays the information of an output file in colour')
	parser.add_argument('-sc', '--showCodes',nargs='+',help='filters the show parameter output to certain status codes [<STATUS_CODE> <STATUS_CODE2>]')
	parser.add_argument('-sd', '--showDomains',nargs='+',help='filters the show parameter output to certain domains')

	return parser.parse_args()

def checkArgErrors(args) -> None:
	if(args.show and not args.file):
		print(RED + "[!] - parameter -f missing, -s needs a file to display" + END)
		sys.exit(1)

	if(args.file and args.targetEntity):
		print(RED + "[!] - parameters -te | -f cannot be used at the same time" + END)
		sys.exit(1)

	if(not args.file and not args.targetEntity):
		print(RED + "[!] - parameters -te | -f required, use -h for help" + END)
		sys.exit(1)

	if((args.targetEntity or args.file) and not args.ports):
		print(RED + "[!] - parameter -p missing, use -h for help" + END)
		sys.exit(1)

	if (args.targetEntity):
		if(args.commonName and args.organisationName):
			print(RED + "[!] - parameters -cn | -on cannot be used at the same time" + END)
			sys.exit(1)
		elif(not args.commonName and not args.organisationName):
			print(RED + "[!] - parameters -cn | -on required" + END)
			sys.exit(1)


if __name__ == "__main__":
	args = parseArguments()
	
	printLogo()
	checkArgErrors(args)
	
	if(args.show):
		input_file = args.file
		if(args.showCodes):
			filtered_status_codes = args.showCodes
		if(args.showDomains):
			filtered_domains = args.showDomains
		parseFileInfo()
		sys.exit(0)

	parseTokens()

	if(args.output):
		output_available=args.output
	if(args.ports):
		ports = args.ports

	createFolders()
	if(args.targetEntity):
		getSubdomains(args.targetEntity, args)
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