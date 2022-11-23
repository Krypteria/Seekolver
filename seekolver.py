from concurrent.futures import ThreadPoolExecutor, as_completed
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
apitoken_file="apitokens.json"
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

#Absolute paths
cat = "/usr/bin/cat"
grep = "/usr/bin/grep"
rm = "/usr/bin/rm"
awk = "/usr/bin/awk"
curl = "/usr/bin/curl"
sort = "/usr/bin/sort"
jq = "/usr/bin/jq"
sed = "/usr/bin/sed"
tr = "/usr/bin/tr"

#Headers
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0", "Accept": "text/html,application/xhtml+xml,application/xml"}
headers_curl_json = "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0' -H 'Accept: application/json, text/plain, */*'"
headers_curl_html = "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0' -H 'Accept: text/html,application/xhtml+xml,application/xml'"

#Colors
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

	print("[*] - Output files generated")
	print("[*] - The output files generated are: " + PURPLE + output_available + END + " and " + PURPLE + output_discarted + END + "\n")

def parseTokens():
	global apiTokens
	if(os.path.isfile(apitoken_file)):
		try:
			apiTokensRaw = open(apitoken_file).read()
			apiTokens = json.loads(apiTokensRaw)
			print("[*] - API tokens loaded")
		except:
			print("[*] - Zero API tokens loaded")

def getSubdomains(domain, args) -> bool:
	print("\n------------------------- SUBDOMAIN SEARCH -------------------------\n")

	print("[*] - Searching for subdomains associated with the domain " + YELLOW + domain + END + "\n")
	print("	[*] -" + GREEN + " Securitytrails" + END)
	print("	[*] -" + GREEN + " Alienvault" + END)
	print("	[*] -" + GREEN + " Virustotal" + END)
	print("	[*] -" + GREEN + " Spyonweb" + END)
	print("	[*] -" + GREEN + " Crt.sh" + END)
	print("	[*] -" + GREEN + " Askdns" + END)

	tmp = open(tmp_file, "a")
	tmp.close()
		
	crtsh(domain,args)
	spyonweb(domain,args)
	alienvault(domain,args)
	askdns(domain,args)
	securitytrails(domain, args)
	virustotal(domain, args)

	os.system("{cat} {tmpFile} | {sort} -u > {reconFile}".format(tmpFile=tmp_file, reconFile=input_file, cat=cat, sort=sort))
	os.system("{rm} {tmpFile}".format(tmpFile=tmp_file, rm=rm))

	if os.path.getsize(input_file) != 0:
		print("\n[*] - Subdomains associated with the domain {domain} found".format(domain=domain))
		return True
	else:
		print(RED + "[!] - Domain {domain} is not correct or doesn't have subdomains\n".format(domain=domain) + END)
		return False

def crtsh(domain, args) -> None:
	searchField=""
	if(args.commonName):
		os.system("{curl} -X GET -s {header} https://crt.sh/\?q\={domain}\&output\=json > output_crtsh.json".format(header=headers_curl_json, domain=urllib.parse.quote_plus(domain), curl=curl))
		searchField = "name_value"
	if(args.organisationName):
		os.system("{curl} -X GET -s {header} https://crt.sh/\?O\={domain}\&output\=json > output_crtsh.json".format(header=headers_curl_json, domain=urllib.parse.quote_plus(domain), curl=curl))
		searchField = "common_name"

	os.system("{cat} output_crtsh.json | {jq} -r '.[].{searchField}' | {sort} -u | {sed} '/*/d' | {grep} {domain} |{grep} -v '@' >> {tmpFile}".format(searchField=searchField, tmpFile=tmp_file, domain=domain.split(".")[0], cat=cat, jq=jq, sort=sort, sed=sed, grep=grep))
	os.system("{rm} output_crtsh.json".format(rm=rm))

def alienvault(domain, args) -> None:
	if(args.commonName):
		os.system("{curl} -X GET -s {header} https://otx.alienvault.com/otxapi/indicators/domain/passive_dns/{domain} > output_alienvault.json".format(header=headers_curl_json, domain=urllib.parse.quote_plus(domain), curl=curl))
		os.system("{cat} output_alienvault.json | {jq} -r '.[][].hostname' 2>/dev/null | {sort} -u | {grep} {domain} | {sed} '/*/d' >> {tmpFile}".format(tmpFile=tmp_file, domain=domain.split(".")[0], cat=cat, jq=jq, sort=sort, grep=grep, sed=sed))
		os.system("{rm} output_alienvault.json".format(rm=rm))

def askdns(domain, args) -> None:
	if(args.commonName):
		os.system("{curl} -X GET -s {header} https://askdns.com/domain/{domain} > output_askdns.json".format(header=headers_curl_html, domain=urllib.parse.quote_plus(domain), curl=curl))
		os.system("{cat} output_askdns.json | {grep} -Po '<a href.*?</a>' | {grep} -Po '>.*?<' | {tr} -d '>' | {tr} -d '<' | {grep} {domain} >> {tmpFile}".format(tmpFile=tmp_file, domain=domain.split(".")[0], cat=cat, grep=grep, tr=tr))
		os.system("{rm} output_askdns.json".format(rm=rm))

def spyonweb(domain, args) -> None:
	if(args.commonName):
		os.system("{curl} -X GET -s {header} https://spyonweb.com/{domain} > output_spyonweb.json".format(header=headers_curl_html, domain=urllib.parse.quote_plus(domain), curl=curl))
		os.system("{cat} output_spyonweb.json | {grep} -Po '<a href.*?</a>' | {grep} {domain} | {grep} -Po '/go.*?\"' | {awk} -F '/' {{'print $3'}} | {tr} -d '\"' >> {tmpFile}".format(tmpFile=tmp_file, domain=domain.split(".")[0], cat=cat, grep=grep, awk=awk, tr=tr))
		os.system("{rm} output_spyonweb.json".format(rm=rm))

def securitytrails(domain, args) -> None:
	if(args.commonName and "securitytrails" in apiTokens):
		os.system("{curl} -X GET -s {header} -H '{token_name}: {token_value}' https://api.securitytrails.com/v1/domain/{domain}/subdomains > output_securitytrails.json".format(header=headers_curl_json, domain=urllib.parse.quote_plus(domain), curl=curl, token_name=apiTokens["securitytrails"][0], token_value=apiTokens["securitytrails"][1]))	
		os.system("{cat} output_securitytrails.json | {jq} -r '.subdomains[]' | {awk} '$0=$0\".{domain}\"' >> {tmpFile}".format(tmpFile=tmp_file, domain=domain, cat=cat, jq=jq, awk=awk))
		os.system("{rm} output_securitytrails.json".format(rm=rm))

def virustotal(domain, args) -> None:
	if(args.commonName and "virustotal" in apiTokens):
		os.system("{curl} -X GET -s {header} -H '{token_name}: {token_value}' https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000 > output_virustotal.json".format(header=headers_curl_json, domain=urllib.parse.quote_plus(domain), curl=curl, token_name=apiTokens["virustotal"][0], token_value=apiTokens["virustotal"][1]))	
		os.system("{cat} output_virustotal.json | {jq} .data[].id | {grep} {domain} | {tr} -d '\"' >> {tmpFile}".format(tmpFile=tmp_file, domain=domain.split(".")[0], cat=cat, jq=jq, grep=grep, tr=tr))
		os.system("{rm} output_virustotal.json".format(rm=rm))

def doRequest(url) -> dict:
	try:
		r, ext, redirect = "","",None
		if("https" in url):
			r = requests.get(url+":443", headers=headers, timeout=timeoutValue, allow_redirects=False, verify=secure)
		elif("http" in url):
			r = requests.get(url+":80", headers=headers,timeout=timeoutValue, allow_redirects=False,verify=secure)
		else:
			try:
				r = requests.get("https://"+url+":443", headers=headers, timeout=timeoutValue, allow_redirects=False, verify=secure)
				ext="https://"
			except:
				r = requests.get("http://"+url+":80", headers=headers, timeout=timeoutValue, allow_redirects=False, verify=secure)
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
	urls=""
	try:
		urls = open(input_file).read().splitlines()
	except:
		print(RED + "[!] - Error opening {file}".format(file=input_file) + END)
		sys.exit(1)

	all_subdomains = len(urls)
	index = 0
	print("\n----------------------- RESOLVING ADDRESSES ------------------------\n")
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

	if(args.targetEntity):
		subdomainsFinded = getSubdomains(args.targetEntity, args)
	else:
		input_file = args.file
	
	if(args.output):
		output_available=args.output
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

	createFolders()
	resolve()
	saveResults()

	 
