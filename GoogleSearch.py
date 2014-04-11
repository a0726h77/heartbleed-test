import urllib2
import cookielib
import time
import urllib
import json

DEBUG = False


def google_search(pattern, rsz=None, pages=None):
    links = []

    try:
        # get search information
        query = urllib.urlencode({'rsz': 8, 'q': pattern})
        # response = urllib.urlopen('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&' + query).read()

        cj = cookielib.CookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        opener.addheaders = [('Referer', 'http://www.google.com/bot.html'),
                            ('Content-Type', 'application/x-www-form-urlencoded'),
                            ('User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')]

        usock = opener.open('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&' + query)
        response = usock.read()

        search_result = json.loads(response)
        if DEBUG:
            print '*Found %s results*' % search_result['responseData']['cursor']['resultCount']
    except:
        return

    # fetch all pages
    starts = list(int(r['start']) for r in search_result['responseData']['cursor']['pages'])
    if DEBUG:
        print starts
    for s in starts:
        if DEBUG:
            print 'fetch: ' + str(s),

        try:
            query = urllib.urlencode({'rsz': 8, 'start': s, 'q': pattern})
            # response = urllib.urlopen ('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&' + query).read()

            usock = opener.open('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&' + query)
            response = usock.read()

            search_result = json.loads(response)

            # generate links
            for r in search_result['responseData']['results']:
                links.append({'title': r['title'], 'url': r['url'], 'cacheUrl': r['cacheUrl']})
        except:
            if DEBUG:
                print ' ... failed',
            pass
        finally:
            if DEBUG:
                print
            pass

        time.sleep(4)

    return links
