import requests
import regex as re
import os

def screen_clear():
	if os.name == 'posix':
		 _ = os.system('clear')
	else:
		_ = os.system('cls')

#// to ignore SSL certificate error==========================================//
from requests.packages.urllib3.exceptions import InsecureRequestWarning    #//
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)        #//
#=========================================================================//

banner = '''
  __  __          _ _       _     _       _      _              _                 
 |  \/  | ___  __| (_) __ _| |   (_)_ __ | | __ | |_ ___       | |___  ___  _ __  
 | |\/| |/ _ \/ _` | |/ _` | |   | | '_ \| |/ / | __/ _ \   _  | / __|/ _ \| '_ \ 
 | |  | |  __/ (_| | | (_| | |___| | | | |   <  | || (_) | | |_| \__ \ (_) | | | |
 |_|  |_|\___|\__,_|_|\__,_|_____|_|_| |_|_|\_\  \__\___/   \___/|___/\___/|_| |_|

    By - Abhay(aka OyeTroubleMaker)    gitHUB - https://github.com/abhaygupta08/

 About this tool : This python script takes a Media link from user and fetches its jSON file which includes description of MediaFile and all Download Varients with metaData of particular file format

======> Supports 35 SOURCES (list is on the site - https://youtubevideomp3.download)

-------------------------------------                                                                                  
 Disclaimer : This tools is a vurnerability Exploitation of site https://youtubevideomp3.download (All the content that user is fetching from script is owned by Respective Owner)
-------------------------------------



'''
screen_clear()
print(banner)

inputURL = input('Enter your URL / Press Enter to Exit: ')
if inputURL == "":
	exit()
#inputURL = 'https://www.youtube.com/watch?v=_2IS14oBr3E' # imp - not need to use url encode

page = requests.session()

#============GET PART // to fetch - token and phpsessid
headerGET = {
	'authority': 'youtubevideomp3.download',
'method': 'GET',
'path': '/en32/',
'scheme': 'https',
'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
'accept-encoding': 'gzip, deflate, br',
'accept-language': 'en-US,en;q=0.9',
'cache-control': 'max-age=0',
'sec-ch-ua': '"Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"',
'sec-ch-ua-mobile': '?0',
'sec-fetch-dest': 'document',
'sec-fetch-mode': 'navigate',
'sec-fetch-site': 'none',
'sec-fetch-user': '?1',
'upgrade-insecure-requests': '1',
'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36',
}
#===homepage url ===\\
url = "https://youtubevideomp3.download/en32"
r = page.get(url,headers=headerGET,verify=False)
value = str(r.text.encode('utf-8')) #gives encoding error so converted to utf-8 then to string
token = re.findall('value="([^"]*)',value)[0]     #fetch token (unique)
sid = page.cookies['PHPSESSID']            #fetch sessid from cookies

#===POST part w/ sessid and token
##post var starts
headerPOST = {
	'authority': 'youtubevideomp3.download',
'method': 'POST',
'path': '/en32/system/action.php',
'scheme': 'https',
'accept': '*/*',
'accept-encoding': 'gzip, deflate, br',
'accept-language': 'en-US,en;q=0.9',
'content-length': '130',
'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
'origin': 'https://youtubevideomp3.download',
'referer': 'https://youtubevideomp3.download/en32/',
'cookie': 'PHPSESSID='+sid+'; popup=done; _ga=GA1.2.1526733129.1615292178; _gid=GA1.2.1129027350.1615292178; _gat_gtag_UA_64202283_16=1',
'sec-ch-ua': '"Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"',
'sec-ch-ua-mobile': '?0',
'sec-fetch-dest': 'empty',
'cookie': 'PHPSESSID='+sid+'; popup=done; _ga=GA1.2.1526733129.1615292178; _gid=GA1.2.1129027350.1615292178; _gat_gtag_UA_64202283_16=1',
'sec-fetch-mode': 'cors',
'sec-fetch-site': 'same-origin',
'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36',
'x-requested-with': 'XMLHttpRequest',
}
datA = {
	'url': inputURL,
'token': token
}
##post var ends

m = page.post('https://youtubevideomp3.download/en32/system/action.php',data=datA,headers=headerPOST,verify=False)
jsonData = m.text

print(jsonData) ##remove it if you want

##  | var jsonData is the json var of particular link 
##  | just search and study for how to fetch values from json

##  | ABOUT - 35 SOURCES ARE SUPPORTED(https://youtubevideomp3.download) | 
##  | visit above site to see the SUPPORTED sits                         |

page.close() #closes requests session