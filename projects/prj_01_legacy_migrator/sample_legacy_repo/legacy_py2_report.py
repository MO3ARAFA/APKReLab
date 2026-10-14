# Python 2 era script: not parseable by Python 3.
import urllib2

def fetch(url):
    print "fetching", url
    return urllib2.urlopen(url).read()
