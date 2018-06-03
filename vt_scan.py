import sys, requests, urllib, urllib2, argparse, hashlib, re, json

class Api:
  def __init__(self):
    self.api_key = ''
    self.base_url = 'https://www.virustotal.com/vtapi/v2/'

  def getReport(self, filehash):
    params = {'apikey': self.api_key, 'resource': filehash}
    url = self.base_url + 'file/report'
    headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "gzip,  Virustotal API Client"}
    response = requests.get(url, params=params, headers=headers)
    reported_json = response.json()

    filename = filehash + '_report.json'
    f = open(filename, 'w')

    json.dump(reported_json, f, indent=4)

    f.close()

    return reported_json

  def downloadFile(self, filehash):
    try:
      params = {'apikey': self.api_key, 'resource': filehash}
      url = self.base_url + 'file/download'
      headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "gzip,  Virustotal API Client"}
      response = requests.get(url, params=params)
      downloaded_file = response.content

      if len(downloaded_file) > 0:
        filename = filehash + '_file.bin'
        f = open(filename, 'wb')
        f.write(downloaded_file)
        f.close()
        print "Malware was saved as " + filename
      else:
        print "Not found " + filehash 
    except Exception:
      print "Occurd some exception"

    return

def main():
  args = sys.argv
  vt_api = Api()

  if len(args) < 2:
    print "Parameter error"
    sys.exit(1)

  filehash = args[1]
  download_flg = args[2]

  jsondata = vt_api.getReport(filehash)

  if download_flg == '-d':
    vt_api.downloadFile(filehash)

if __name__ == '__main__':
  main()
