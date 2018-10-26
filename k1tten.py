import requests
from bs4 import BeautifulSoup

def f(string, n):
	a = []
	for i in range(0, len(string), n):
		a.append(string[i:i+n])
	print('\n'.join(a))

link = 'http://13.115.255.46/?s=06e77f2958b65ffd2c0f7629b9e19627'

soup = BeautifulSoup(requests.get(link).text)

for i in soup.select('table.table > tbody')[0].select('tr'):
    string = i.select('a')[0]['href'].strip('?s=')
    # location = requests.get('http://13.115.255.46/?s=' + string).history[0].headers['Location']
    title = i.select('a')[0].text
    f(title, 16)
    print('\n')
    f(string, 32)
    print('\n\n')
